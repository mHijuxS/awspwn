"""Grants policy-evaluation correctness (Step 3).

Offline unit tests for the single-principal identity-policy evaluator: NotAction
as a complement, explicit-deny precedence (action + resource + evaluable
condition), three-valued conditions, resource wildcard/scoped evaluation, the
resource-aware vs "anywhere" split, and the deny-aware, universal-Allow-based
is_admin. These are the semantics the old flat matcher got wrong (NotAction
unioned into Action; Allow "*" trusted blindly; a literal "*" action proxy).
"""

from awspwn.enum.iam import Grants


def _g(*docs) -> Grants:
    g = Grants()
    for d in docs:
        g.add_document(d)
    return g


def _stmt(effect, **kw):
    s = {"Effect": effect}
    s.update(kw)
    return {"Version": "2012-10-17", "Statement": [s]}


# ─── NotAction as complement, not as allowed actions (the old bug) ───────────


def test_allow_notaction_is_complement():
    g = _g(_stmt("Allow", NotAction="iam:*", Resource="*"))
    # Everything EXCEPT iam:* is allowed (queried "anywhere").
    assert g.allows_action_anywhere("s3:GetObject") == (True, False)
    assert g.allows_action_anywhere("ec2:RunInstances") == (True, False)
    # iam:* is excluded - NOT allowed (old code wrongly reported allowed).
    assert g.allows_action_anywhere("iam:CreateUser") == (False, False)
    # And the flat action_patterns projection must not contain "iam:*".
    assert all(pat != "iam:*" for pat, _r, _c in g.allows)


def test_deny_notaction_inverse():
    # Admin, then deny everything EXCEPT s3 -> only s3 survives.
    g = _g(
        _stmt("Allow", Action="*", Resource="*"),
        _stmt("Deny", NotAction="s3:*", Resource="*"),
    )
    assert g.allows_action_anywhere("s3:GetObject") == (True, False)      # s3 not denied
    assert g.allows_action_anywhere("ec2:RunInstances") == (False, False)  # denied by NotAction


# ─── Explicit-deny precedence ────────────────────────────────────────────────


def test_unconditional_deny_beats_allow():
    g = _g(
        _stmt("Allow", Action="iam:*", Resource="*"),
        _stmt("Deny", Action="iam:CreateUser", Resource="*"),
    )
    assert g.allows_action("iam:CreateUser", "*") == (False, False)
    assert g.allows_action("iam:DeleteUser", "*") == (True, False)


def test_deny_precedence_is_resource_specific():
    g = _g(
        _stmt("Allow", Action="s3:GetObject", Resource="*"),
        _stmt("Deny", Action="s3:GetObject", Resource="arn:aws:s3:::secret/*"),
    )
    # Deny applies only to its resource.
    assert g.allows_action("s3:GetObject", "arn:aws:s3:::public/key") == (True, False)
    assert g.allows_action("s3:GetObject", "arn:aws:s3:::secret/key") == (False, False)
    # "Anywhere": a universal allow shadowed by a scoped deny -> allowed but
    # conditional (unknown whether a given target is the denied one).
    assert g.allows_action_anywhere("s3:GetObject") == (True, True)


# ─── Unevaluable conditions -> conditional/unknown, never definite ───────────


def test_conditional_allow_is_conditional():
    g = _g(_stmt("Allow", Action="iam:PassRole", Resource="*",
                 Condition={"StringEquals": {"iam:PassedToService": "ec2.amazonaws.com"}}))
    assert g.allows_action("iam:PassRole", "*") == (True, True)
    assert g.allows_action_anywhere("iam:PassRole") == (True, True)


def test_conditional_deny_does_not_hard_deny():
    g = _g(
        _stmt("Allow", Action="s3:GetObject", Resource="*"),
        _stmt("Deny", Action="s3:GetObject", Resource="*",
              Condition={"NotIpAddress": {"aws:SourceIp": "10.0.0.0/8"}}),
    )
    # The deny MIGHT apply -> allowed but conditional, not a definite deny.
    assert g.allows_action("s3:GetObject", "arn:aws:s3:::b/k") == (True, True)


# ─── Resource wildcard matching + resource-specific evaluation ───────────────


def test_resource_wildcard_matching():
    g = _g(_stmt("Allow", Action="s3:GetObject", Resource="arn:aws:s3:::bucket/*"))
    assert g.allows_action("s3:GetObject", "arn:aws:s3:::bucket/key") == (True, False)
    assert g.allows_action("s3:GetObject", "arn:aws:s3:::other/key") == (False, False)
    # "Anywhere" on a resource-scoped allow -> allowed somewhere, but conditional.
    assert g.allows_action_anywhere("s3:GetObject") == (True, True)


def test_resource_matching_is_case_sensitive():
    # ARN resource segments are case-sensitive (unlike action names).
    g = _g(_stmt("Allow", Action="s3:GetObject", Resource="arn:aws:s3:::Bucket/*"))
    assert g.allows_action("s3:GetObject", "arn:aws:s3:::Bucket/k") == (True, False)
    assert g.allows_action("s3:GetObject", "arn:aws:s3:::bucket/k") == (False, False)
    # Action case does not matter.
    assert g.allows_action("S3:getobject", "arn:aws:s3:::Bucket/k") == (True, False)


def test_not_resource_excludes():
    g = _g(_stmt("Allow", Action="s3:GetObject", NotResource="arn:aws:s3:::locked/*"))
    assert g.allows_action("s3:GetObject", "arn:aws:s3:::open/key") == (True, False)
    assert g.allows_action("s3:GetObject", "arn:aws:s3:::locked/key") == (False, False)


# ─── is_admin: universal-Allow based, deny-aware ─────────────────────────────


def test_is_admin_plain_wildcard():
    assert _g(_stmt("Allow", Action="*", Resource="*")).is_admin is True


def test_is_admin_rejects_notaction_allow():
    # Regression: Allow NotAction is NOT admin - a literal "*" action proxy used
    # to match it, but it grants everything EXCEPT iam:*, so not unrestricted.
    assert _g(_stmt("Allow", NotAction="iam:*", Resource="*")).is_admin is False


def test_is_admin_rejects_action_wildcard_scoped_resource():
    # Admin action but scoped to one resource is not account admin.
    assert _g(_stmt("Allow", Action="*", Resource="arn:aws:s3:::b/*")).is_admin is False


def test_is_admin_revoked_by_any_deny():
    # Conservative literal-admin contract: ANY deny disqualifies.
    blanket = _g(_stmt("Allow", Action="*", Resource="*"),
                 _stmt("Deny", Action="iam:*", Resource="*"))
    scoped = _g(_stmt("Allow", Action="*", Resource="*"),
                _stmt("Deny", Action="s3:GetObject", Resource="arn:aws:s3:::one/*"))
    # A near-universal NotResource deny (escaped the old resource_universal check).
    notresource = _g(_stmt("Allow", Action="*", Resource="*"),
                     _stmt("Deny", Action="*", NotResource="arn:aws:s3:::safe/*"))
    conditional = _g(_stmt("Allow", Action="*", Resource="*"),
                     _stmt("Deny", Action="*", Resource="*",
                           Condition={"BoolIfExists": {"aws:MultiFactorAuthPresent": "false"}}))
    for g in (blanket, scoped, notresource, conditional):
        assert g.is_admin is False


# ─── add_admin_grant + merge respect the same contract ───────────────────────


def test_admin_by_arn_grant_then_denied():
    g = Grants()
    g.add_admin_grant()
    assert g.is_admin is True
    g.add_document(_stmt("Deny", Action="iam:*", Resource="*"))
    assert g.is_admin is False


def test_merge_inherits_group_admin():
    user_g = _g(_stmt("Allow", Action="s3:GetObject", Resource="*"))
    group_g = _g(_stmt("Allow", Action="*", Resource="*"))
    assert user_g.is_admin is False
    user_g.merge(group_g)
    assert user_g.is_admin is True


# ─── conjunctions + serialization ────────────────────────────────────────────


def test_allows_all_anywhere_conjunction_and_conditionality():
    g = _g(
        _stmt("Allow", Action="iam:CreateRole", Resource="*"),
        _stmt("Allow", Action="iam:AttachRolePolicy", Resource="*",
              Condition={"StringEquals": {"aws:RequestTag/x": "y"}}),
    )
    # Missing sts:AssumeRole -> the whole conjunction fails.
    assert g.allows_all_anywhere(["iam:CreateRole", "iam:AttachRolePolicy", "sts:AssumeRole"]) == (False, False)
    # Present pair, one leg conditional -> allowed-but-conditional.
    assert g.allows_all_anywhere(["iam:CreateRole", "iam:AttachRolePolicy"]) == (True, True)


# ─── privesc resource-awareness (gap 3) ──────────────────────────────────────


def test_self_admin_rejects_grant_scoped_to_another_principal():
    from awspwn.enum.iam import _grant_allows

    self_arn = "arn:aws:iam::111:user/dev"
    other = "arn:aws:iam::111:user/victim"
    required = [("iam:AttachUserPolicy", "SELF")]

    scoped = _g(_stmt("Allow", Action="iam:AttachUserPolicy", Resource=other))
    # Resource-agnostic-style check would say allowed; SELF-scoped correctly does not.
    assert _grant_allows(scoped, required, self_arn, self_arn) == (False, False)

    unscoped = _g(_stmt("Allow", Action="iam:AttachUserPolicy", Resource="*"))
    assert _grant_allows(unscoped, required, self_arn, self_arn) == (True, False)

    on_self = _g(_stmt("Allow", Action="iam:AttachUserPolicy", Resource=self_arn))
    assert _grant_allows(on_self, required, self_arn, self_arn) == (True, False)


def test_passrole_gate_leg_makes_edge_conditional_when_scoped():
    from awspwn.enum.iam import _grant_allows

    role = "arn:aws:iam::111:role/app"
    required = [("iam:PassRole", "TGT"), ("lambda:CreateFunction", "ANY"), ("lambda:InvokeFunction", "ANY")]
    # PassRole exactly on the target role, but the compute legs are only scoped ->
    # the ANY (anywhere) legs come back conditional, so the edge is conditional.
    g = _g(
        _stmt("Allow", Action="iam:PassRole", Resource=role),
        _stmt("Allow", Action="lambda:CreateFunction", Resource="arn:aws:lambda:us-east-1:111:function:x"),
        _stmt("Allow", Action="lambda:InvokeFunction", Resource="arn:aws:lambda:us-east-1:111:function:x"),
    )
    assert _grant_allows(g, required, role, role) == (True, True)


def test_statements_roundtrip_preserves_semantics():
    g = _g(
        _stmt("Allow", Action="s3:GetObject", Resource="arn:aws:s3:::b/*"),
        _stmt("Deny", Action="s3:GetObject", Resource="arn:aws:s3:::b/secret/*"),
    )
    g2 = Grants.from_statements(g.to_statements())
    assert g2.allows_action("s3:GetObject", "arn:aws:s3:::b/public") == (True, False)
    assert g2.allows_action("s3:GetObject", "arn:aws:s3:::b/secret/x") == (False, False)
