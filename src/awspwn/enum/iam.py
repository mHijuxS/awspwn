"""IAM enumerator - builds the identity graph and mints privilege-escalation
edges from policy documents.

Degradation chain (you rarely have full IAM read on a real engagement):
  1. iam:GetAccountAuthorizationDetails - one-shot dump of everything.
  2. denied -> individual List*/Get* per object type.
  3. denied -> enumerate-iam brute force: probe a curated list of read-only,
     safe-arg API calls to map the CURRENT identity's effective permissions
     with zero IAM read privilege.

Privesc edges are minted by a local, best-effort policy evaluator (`Grants`) over
the statements. It models explicit-deny precedence, Action/NotAction (NotAction
as the complement - "everything except"), and Resource/NotResource wildcards,
with three-valued handling of Condition keys it cannot evaluate: a conditional
statement is a *maybe* (the edge is marked `conditional`), never a certainty.
Fast and offline / moto-friendly (moto does not implement SimulatePrincipalPolicy);
policy/simulate.py refines the same edges when simulation is available. Still NOT
modelled here (documented gaps): resource-policy / SCP / permission-boundary
interaction and condition-key semantics - hence `conditional` edges are best-
effort and simulate is the authority when present.
"""

from __future__ import annotations

import json
import re
import urllib.parse
from dataclasses import dataclass, field

from ..aws_client import AwsClient, canonical_principal_id
from ..models import Edge, Finding, Node, NodeKind, Severity
from .base import EnumResult, ServiceEnumerator


# ─── Policy document helpers ────────────────────────────────────────────────


def _load_doc(doc) -> dict:
    """Normalise a policy document - GAAD returns them URL-encoded; get_* APIs
    sometimes return dicts. Handle both."""
    if isinstance(doc, dict):
        return doc
    if isinstance(doc, str):
        try:
            return json.loads(urllib.parse.unquote(doc))
        except (ValueError, TypeError):
            try:
                return json.loads(doc)
            except (ValueError, TypeError):
                return {}
    return {}


def _as_list(x) -> list:
    if x is None:
        return []
    return x if isinstance(x, list) else [x]


def _wildcard_regex(pattern: str, flags: int = 0) -> re.Pattern:
    esc = re.escape(pattern).replace(r"\*", ".*").replace(r"\?", ".")
    return re.compile("^" + esc + "$", flags)


def _action_regex(pattern: str) -> re.Pattern:
    """AWS action wildcard -> regex. 'iam:Create*' -> ^iam:create.*$. Action names
    are case-INsensitive in IAM, so match case-insensitively."""
    return _wildcard_regex(pattern, re.IGNORECASE)


def _resource_regex(pattern: str) -> re.Pattern:
    """Resource ARN wildcard -> regex, CASE-SENSITIVE. ARN resource segments
    (bucket names, object keys, parameter names) are not uniformly case-
    insensitive, so - unlike actions - resources must match exactly."""
    return _wildcard_regex(pattern)


class _Statement:
    """One parsed policy statement. Action/NotAction compile case-insensitively;
    Resource/NotResource compile case-sensitively. `has_condition` is True when
    the statement carries Condition keys we do not evaluate - such a statement can
    only ever contribute a *maybe*, never a definite allow or deny. Raw pattern
    lists are retained so the statement can be serialized onto a node and matched
    without the original policy document."""

    __slots__ = ("effect", "has_condition", "a_pats", "na_pats", "r_pats", "nr_pats",
                 "_a_rx", "_na_rx", "_r_rx", "_nr_rx")

    def __init__(self, effect, actions, not_actions, resources, not_resources, has_condition):
        self.effect = effect
        self.has_condition = has_condition
        self.a_pats = actions
        self.na_pats = not_actions
        self.r_pats = resources
        self.nr_pats = not_resources
        self._a_rx = [_action_regex(a) for a in actions] if actions is not None else None
        self._na_rx = [_action_regex(a) for a in not_actions] if not_actions is not None else None
        self._r_rx = [_resource_regex(r) for r in resources] if resources is not None else None
        self._nr_rx = [_resource_regex(r) for r in not_resources] if not_resources is not None else None

    def matches_action(self, action: str) -> bool:
        # Action: the action must match one of the patterns. NotAction: the action
        # must match NONE of them (the COMPLEMENT - "everything except these"). A
        # statement with neither constrains no action and is inert.
        if self._a_rx is None and self._na_rx is None:
            return False
        if self._a_rx is not None and not any(rx.match(action) for rx in self._a_rx):
            return False
        if self._na_rx is not None and any(rx.match(action) for rx in self._na_rx):
            return False
        return True

    def matches_resource(self, resource: str) -> bool:
        # `resource` is a concrete ARN (or "*"). Matched against Resource /
        # NotResource wildcards. An identity statement with neither is invalid but
        # treated leniently as "*".
        if self._r_rx is not None and not any(rx.match(resource) for rx in self._r_rx):
            return False
        if self._nr_rx is not None and any(rx.match(resource) for rx in self._nr_rx):
            return False
        return True

    def action_is_universal(self) -> bool:
        """True if this statement grants EVERY action: a positive Action of "*"
        and no NotAction. Only this justifies admin - "s3:*" or a NotAction set
        does not."""
        if self._na_rx is not None:
            return False
        if self.a_pats is None:
            return False
        return any(p == "*" for p in self.a_pats)

    def resource_universal(self) -> bool:
        """True if this statement applies to every resource - no NotResource and a
        Resource of "*" (or absent). A resource-scoped or NotResource statement is
        not universal and cannot be applied with certainty to an anywhere query."""
        if self._nr_rx:
            return False
        if self.r_pats is None:
            return True
        return any(p == "*" for p in self.r_pats)

    # ── serialization (compact internal form, persisted on principal nodes) ──
    def to_dict(self) -> dict:
        d = {"Effect": self.effect}
        if self.a_pats is not None:
            d["Action"] = self.a_pats
        if self.na_pats is not None:
            d["NotAction"] = self.na_pats
        if self.r_pats is not None:
            d["Resource"] = self.r_pats
        if self.nr_pats is not None:
            d["NotResource"] = self.nr_pats
        if self.has_condition:
            d["_conditional"] = True  # presence only; we never evaluate the keys
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "_Statement":
        return cls(
            d.get("Effect", "Allow"),
            _as_list(d["Action"]) if "Action" in d else None,
            _as_list(d["NotAction"]) if "NotAction" in d else None,
            _as_list(d["Resource"]) if "Resource" in d else None,
            _as_list(d["NotResource"]) if "NotResource" in d else None,
            bool(d.get("_conditional") or d.get("Condition")),
        )


class Grants:
    """Best-effort single-principal identity-policy evaluator.

    Models the parts of IAM policy evaluation that change which edges are real:
    Allow/Deny with explicit-deny precedence, Action/NotAction (as a complement),
    Resource/NotResource wildcards, and three-valued handling of Condition keys
    we cannot evaluate (a conditional statement is a *maybe*, never a certainty).

    Two query modes, deliberately separated:
      * allows_action(action, resource) - a resource-AWARE edge decision against a
        concrete target ARN. Use this to mint an edge whose target is known.
      * allows_action_anywhere(action) - "is this allowed against SOME resource?",
        for discovery/reporting and for gate actions (e.g. ec2:RunInstances) whose
        resource is out of scope. A scoped/conditional allow answers (True, True):
        allowed somewhere, but not a certainty for any particular target.

    Still NOT modelled (documented gaps, refined by simulate): resource-policy /
    SCP / permission-boundary interaction, and condition-key semantics."""

    def __init__(self):
        self.statements: list[_Statement] = []
        # Flat positive-Action Allow patterns, kept for the `action_patterns` node
        # property (display) only. NOT authoritative for correlation - it cannot
        # express NotAction complements, resource scoping, conditions, or denies.
        self.allows: list[tuple[str, list[str], bool]] = []

    def add_document(self, doc: dict) -> None:
        for stmt in _as_list(doc.get("Statement")):
            if not isinstance(stmt, dict):
                continue
            effect = stmt.get("Effect")
            if effect not in ("Allow", "Deny"):
                continue
            actions = _as_list(stmt.get("Action")) if "Action" in stmt else None
            not_actions = _as_list(stmt.get("NotAction")) if "NotAction" in stmt else None
            if actions is None and not_actions is None:
                continue
            resources = _as_list(stmt.get("Resource")) if "Resource" in stmt else None
            not_resources = _as_list(stmt.get("NotResource")) if "NotResource" in stmt else None
            has_cond = bool(stmt.get("Condition"))
            self._add(_Statement(effect, actions, not_actions, resources, not_resources, has_cond))

    def _add(self, s: _Statement) -> None:
        self.statements.append(s)
        if s.effect == "Allow" and s.a_pats is not None:
            res = s.r_pats or ["*"]
            for a in s.a_pats:
                self.allows.append((a, res, s.has_condition))

    def add_admin_grant(self) -> None:
        """Record an equivalent Allow */* for an AdministratorAccess attachment
        whose document we could not read (identified by ARN). Injected as a real
        statement so explicit-deny precedence still applies to it."""
        self._add(_Statement("Allow", ["*"], None, ["*"], None, False))

    def merge(self, other: "Grants") -> None:
        """Fold another principal's grants in (e.g. a user's group). Statements
        carry over whole, so deny precedence and is_admin recompute correctly."""
        for s in other.statements:
            self._add(s)

    # ── serialization onto a principal node ──────────────────────────────────
    def to_statements(self) -> list[dict]:
        return [s.to_dict() for s in self.statements]

    @classmethod
    def from_statements(cls, raw: list) -> "Grants":
        g = cls()
        for d in raw or []:
            if isinstance(d, dict):
                g._add(_Statement.from_dict(d))
        return g

    # ── resource-aware evaluation (edge decisions) ───────────────────────────
    def allows_action(self, action: str, resource: str) -> tuple[bool, bool]:
        """(allowed, conditional) for one action against a CONCRETE resource ARN
        (or "*"). Explicit-deny precedence: an unconditional Deny that matches the
        action and resource wins outright; a conditional Deny is only a *maybe*
        and marks the result conditional. An unconditional Allow allows; a
        conditional-only Allow allows conditionally."""
        uncond_allow = cond_allow = uncond_deny = cond_deny = False
        for s in self.statements:
            if not s.matches_action(action) or not s.matches_resource(resource):
                continue
            if s.effect == "Deny":
                if s.has_condition:
                    cond_deny = True
                else:
                    uncond_deny = True
            else:
                if s.has_condition:
                    cond_allow = True
                else:
                    uncond_allow = True
        if uncond_deny:
            return (False, False)
        if uncond_allow:
            return (True, cond_deny)
        if cond_allow:
            return (True, True)
        return (False, False)

    def allows_all(self, actions: list[str], resource: str) -> tuple[bool, bool]:
        """Every action allowed against `resource`. Conditional if any leg is."""
        conditional = False
        for a in actions:
            ok, cond = self.allows_action(a, resource)
            if not ok:
                return False, False
            conditional = conditional or cond
        return True, conditional

    # ── anywhere evaluation (discovery / gate actions) ───────────────────────
    def allows_action_anywhere(self, action: str) -> tuple[bool, bool]:
        """(allowed, conditional) for "can this principal do `action` against SOME
        resource?". A universally-scoped unconditional Allow is a certainty; a
        merely resource-scoped or conditional Allow is (True, True) - allowed
        somewhere, but not certain for any specific target. Only an unconditional,
        resource-universal Deny hard-denies here; a scoped/conditional deny is a
        maybe."""
        uncond_allow_univ = scoped_or_cond_allow = uncond_deny_univ = maybe_deny = False
        for s in self.statements:
            if not s.matches_action(action):
                continue
            if s.effect == "Deny":
                if not s.has_condition and s.resource_universal():
                    uncond_deny_univ = True
                else:
                    maybe_deny = True
            else:
                if not s.has_condition and s.resource_universal():
                    uncond_allow_univ = True
                else:
                    scoped_or_cond_allow = True
        if uncond_deny_univ:
            return (False, False)
        if uncond_allow_univ:
            return (True, maybe_deny)
        if scoped_or_cond_allow:
            return (True, True)
        return (False, False)

    def allows_all_anywhere(self, actions: list[str]) -> tuple[bool, bool]:
        conditional = False
        for a in actions:
            ok, cond = self.allows_action_anywhere(a)
            if not ok:
                return False, False
            conditional = conditional or cond
        return True, conditional

    @property
    def is_admin(self) -> bool:
        """Literal UNRESTRICTED admin: a genuinely-universal unconditional Allow
        (positive Action "*" on Resource "*") and NO Deny statement of any kind.

        Deliberately conservative - ANY Deny (blanket, resource-scoped, or
        conditional) means the principal cannot do at least one thing, so they are
        not *unrestricted*. This drives the EffectiveAdmin "game over" shortcut,
        where a false positive (claiming instant admin when a deny blocks a step)
        is worse than a false negative: a principal narrowed by a benign scoped
        deny is still reachable to admin through its ordinary privesc edges, just
        not via the shortcut."""
        if any(s.effect == "Deny" for s in self.statements):
            return False
        return any(
            s.effect == "Allow" and not s.has_condition
            and s.action_is_universal() and s.resource_universal()
            for s in self.statements
        )


# ─── Privesc rule table ─────────────────────────────────────────────────────
# Each rule is (edge_kind, selector, required) where `required` is a list of
# (action, resource_role) legs. resource_role scopes the permission check:
#   "SELF" - against the principal's OWN ARN (self-escalation actions).
#   "TGT"  - against the escalation TARGET's ARN (the user/role/group/policy the
#            selector iterates to).
#   "ANY"  - "allowed against some resource" (gate/creation actions whose resource
#            is out of scope, e.g. ec2:RunInstances, iam:CreateRole). An ANY leg
#            backed only by scoped/conditional grants makes the edge conditional.
# Selectors: self_admin, group_admin, attached_policy_admin, users, groups,
# roles, passable_roles.
_PRIVESC_RULES = [
    ("AttachUserPolicy", "self_admin", [("iam:AttachUserPolicy", "SELF")]),
    ("PutUserPolicy", "self_admin", [("iam:PutUserPolicy", "SELF")]),
    ("AttachGroupPolicy", "group_admin", [("iam:AttachGroupPolicy", "TGT")]),
    ("PutGroupPolicy", "group_admin", [("iam:PutGroupPolicy", "TGT")]),
    # Rewriting a customer-managed policy ATTACHED to the principal -> self admin.
    # Checked against each attached policy's ARN (TGT), so the edge exists only for
    # a policy the principal actually holds and the strategy has a target to pick.
    ("CreatePolicyVersion", "attached_policy", [("iam:CreatePolicyVersion", "TGT")]),
    ("SetDefaultPolicyVersion", "attached_policy", [("iam:SetDefaultPolicyVersion", "TGT")]),
    ("CreateRoleAndAssume", "self_admin",
     [("iam:CreateRole", "ANY"), ("iam:AttachRolePolicy", "ANY"), ("sts:AssumeRole", "ANY")]),
    ("CreateAccessKey", "users", [("iam:CreateAccessKey", "TGT")]),
    ("CreateLoginProfile", "users", [("iam:CreateLoginProfile", "TGT")]),
    ("UpdateLoginProfile", "users", [("iam:UpdateLoginProfile", "TGT")]),
    ("AddUserToGroup", "groups", [("iam:AddUserToGroup", "TGT")]),
    ("UpdateAssumeRolePolicy", "roles", [("iam:UpdateAssumeRolePolicy", "TGT"), ("sts:AssumeRole", "TGT")]),
    ("AttachRolePolicy", "roles", [("iam:AttachRolePolicy", "TGT"), ("sts:AssumeRole", "TGT")]),
    ("PutRolePolicy", "roles", [("iam:PutRolePolicy", "TGT"), ("sts:AssumeRole", "TGT")]),
    # PassRole + compute (self gains a passed role's privileges). PassRole is
    # scoped to the target role; the compute action's resource is out of scope.
    ("RunInstanceWithRole", "passable_roles", [("iam:PassRole", "TGT"), ("ec2:RunInstances", "ANY")]),
    ("CreateLambdaWithRole", "passable_roles",
     [("iam:PassRole", "TGT"), ("lambda:CreateFunction", "ANY"), ("lambda:InvokeFunction", "ANY")]),
    ("CloudFormationCreateStack", "passable_roles", [("iam:PassRole", "TGT"), ("cloudformation:CreateStack", "ANY")]),
    ("ECSRunTaskWithRole", "passable_roles", [("iam:PassRole", "TGT"), ("ecs:RunTask", "ANY")]),
    ("GlueCreateDevEndpoint", "passable_roles", [("iam:PassRole", "TGT"), ("glue:CreateDevEndpoint", "ANY")]),
    ("SageMakerCreateNotebook", "passable_roles",
     [("iam:PassRole", "TGT"), ("sagemaker:CreateNotebookInstance", "ANY"),
      ("sagemaker:CreatePresignedNotebookInstanceUrl", "ANY")]),
    ("CodeBuildCreateProject", "passable_roles",
     [("iam:PassRole", "TGT"), ("codebuild:CreateProject", "ANY"), ("codebuild:StartBuild", "ANY")]),
]


def _grant_allows(grants: "Grants", required, self_arn: str, target_arn: str) -> tuple[bool, bool]:
    """Evaluate a rule's (action, resource_role) legs against a principal's grants.
    Returns (allowed, conditional). SELF/TGT are resource-aware (exact deny
    precedence against the concrete ARN); ANY is an anywhere check."""
    conditional = False
    for action, role in required:
        if role == "SELF":
            ok, cond = grants.allows_action(action, self_arn)
        elif role == "TGT":
            ok, cond = grants.allows_action(action, target_arn)
        else:  # ANY
            ok, cond = grants.allows_action_anywhere(action)
        if not ok:
            return False, False
        conditional = conditional or cond
    return True, conditional


@dataclass
class _SelfRead:
    """Outcome of a per-vantage self-policy read. `completeness` is the three-state
    authority: 'complete' (every listing + document read succeeded -> authoritative
    grants, retraction allowed), 'partial' (some succeeded, coverage incomplete ->
    additive non-authoritative evidence only), 'none' (nothing readable)."""

    grants: "Grants"
    completeness: str
    attached: list = field(default_factory=list)   # attached managed policy ARNs
    principal_arn: str = ""                          # path-qualified when known


def _completeness(got_any: bool, complete: bool) -> str:
    if not got_any:
        return "none"
    return "complete" if complete else "partial"


def _admin_goal_id(account: str) -> str:
    return f"awspwn:admin:{account or 'unknown'}"


def _is_service_linked(arn: str, name: str) -> bool:
    """Service-linked roles can only be assumed by their AWS service and cannot
    be passed to arbitrary compute - so they are never useful privesc targets."""
    return "/aws-service-role/" in arn or name.startswith("AWSServiceRoleFor")


# ─── Enumerator ─────────────────────────────────────────────────────────────


class IamEnumerator(ServiceEnumerator):
    name = "iam"
    service = "iam"
    is_global = True

    def enumerate(self, client: AwsClient, region: str) -> EnumResult:
        result = EnumResult()
        iam = client.client("iam")
        account = client.identity.account

        gaad = self._get_gaad(iam, result)
        if gaad is not None:
            # Full account view (authoritative).
            self._build_from_gaad(gaad, account, client, result, complete=True)
            return result

        # GAAD denied. Piecemeal identity listing rebuilds a list-only (non-
        # authoritative) view when available; then - REGARDLESS of whether that
        # succeeded (it lists identities but reads no policies) - self-resolve the
        # CURRENT principal's own policies. resolve_self probes exactly once, so
        # there is no separate brute-force probe.
        piecemeal = self._piecemeal(iam, result)
        if piecemeal is not None:
            self._build_from_gaad(piecemeal, account, client, result, complete=False)
        self.resolve_self(client, result)
        return result

    # ─── Step 1: GetAccountAuthorizationDetails ────────────────────────────

    def _get_gaad(self, iam, result: EnumResult):
        try:
            details = {
                "UserDetailList": [],
                "GroupDetailList": [],
                "RoleDetailList": [],
                "Policies": [],
            }
            paginator = iam.get_paginator("get_account_authorization_details")
            for page in paginator.paginate():
                for key in details:
                    details[key].extend(page.get(key, []))
            return details
        except Exception as exc:  # noqa: BLE001
            if not self._handle(exc, "iam:GetAccountAuthorizationDetails", "", result):
                raise
            return None

    # ─── Step 2: piecemeal List*/Get* ──────────────────────────────────────

    def _piecemeal(self, iam, result: EnumResult):
        """Rebuild a GAAD-shaped dict from individual calls when GAAD is denied."""
        details = {
            "UserDetailList": [],
            "GroupDetailList": [],
            "RoleDetailList": [],
            "Policies": [],
        }
        any_ok = False

        try:
            for page in iam.get_paginator("list_users").paginate():
                for u in page.get("Users", []):
                    details["UserDetailList"].append(
                        {
                            "UserName": u["UserName"],
                            "Arn": u["Arn"],
                            "GroupList": [],
                            "AttachedManagedPolicies": [],
                            "UserPolicyList": [],
                        }
                    )
            any_ok = True
        except Exception as exc:  # noqa: BLE001
            if not self._handle(exc, "iam:ListUsers", "", result):
                raise

        try:
            for page in iam.get_paginator("list_roles").paginate():
                for r in page.get("Roles", []):
                    details["RoleDetailList"].append(
                        {
                            "RoleName": r["RoleName"],
                            "Arn": r["Arn"],
                            "AssumeRolePolicyDocument": r.get("AssumeRolePolicyDocument", {}),
                            "AttachedManagedPolicies": [],
                            "RolePolicyList": [],
                            "InstanceProfileList": [],
                        }
                    )
            any_ok = True
        except Exception as exc:  # noqa: BLE001
            if not self._handle(exc, "iam:ListRoles", "", result):
                raise

        try:
            for page in iam.get_paginator("list_groups").paginate():
                for g in page.get("Groups", []):
                    details["GroupDetailList"].append(
                        {
                            "GroupName": g["GroupName"],
                            "Arn": g["Arn"],
                            "AttachedManagedPolicies": [],
                            "GroupPolicyList": [],
                        }
                    )
            any_ok = True
        except Exception as exc:  # noqa: BLE001
            if not self._handle(exc, "iam:ListGroups", "", result):
                raise

        return details if any_ok else None

    # ─── Step 3: enumerate-iam brute force ─────────────────────────────────

    # Read-only, safe-argument probes. Success => you hold that permission.
    _PROBES = [
        ("iam:GetAccountSummary", "iam", "get_account_summary", {}),
        ("iam:ListUsers", "iam", "list_users", {"MaxItems": 1}),
        ("iam:ListRoles", "iam", "list_roles", {"MaxItems": 1}),
        ("iam:ListGroups", "iam", "list_groups", {"MaxItems": 1}),
        ("iam:ListPolicies", "iam", "list_policies", {"MaxItems": 1, "Scope": "Local"}),
        ("ec2:DescribeInstances", "ec2", "describe_instances", {"MaxResults": 5}),
        ("ec2:DescribeSnapshots", "ec2", "describe_snapshots", {"MaxResults": 5, "OwnerIds": ["self"]}),
        ("s3:ListAllMyBuckets", "s3", "list_buckets", {}),
        ("lambda:ListFunctions", "lambda", "list_functions", {"MaxItems": 1}),
        ("secretsmanager:ListSecrets", "secretsmanager", "list_secrets", {"MaxResults": 1}),
        ("ssm:DescribeParameters", "ssm", "describe_parameters", {"MaxResults": 1}),
        ("dynamodb:ListTables", "dynamodb", "list_tables", {"Limit": 1}),
        ("rds:DescribeDBInstances", "rds", "describe_db_instances", {"MaxRecords": 20}),
        ("organizations:ListAccounts", "organizations", "list_accounts", {}),
        ("sts:GetCallerIdentity", "sts", "get_caller_identity", {}),
    ]

    def _probe_actions(self, client: AwsClient) -> list[str]:
        """Empirically confirm the CURRENT identity's permissions by making the
        read-only, safe-argument probe calls. A successful call proves exactly the
        one action it exercised - nothing more. These are EMPIRICAL facts and are
        kept distinct from policy-inferred grants (they are a separate node
        property and are never fed into policy-derived correlation, which would
        over-claim - `list_secrets` succeeding does not imply GetSecretValue)."""
        confirmed: list[str] = []
        for perm, service, op, kwargs in self._PROBES:
            try:
                getattr(client.client(service), op)(**kwargs)
                confirmed.append(perm)
            except Exception:  # noqa: BLE001 - denial is the expected common case
                continue
        return sorted(confirmed)

    # ─── Self-policy resolver (per-vantage, low-read) ──────────────────────
    # Read the CURRENT principal's OWN policies (user or role) into a normalized
    # Grants, so a vantage with no account-wide IAM read still contributes a
    # non-empty, resource-aware self-node. Separate from the empirical probes:
    # policy grants drive correlation/privesc; probes are recorded as distinct
    # empirical facts (confirmed_actions) and never fed into policy-derived edges.

    def _read_managed_into(self, iam, policy_arn: str, grants: "Grants", result: EnumResult) -> bool:
        """Fold a managed policy's default-version document into `grants`. Returns
        True if the document was incorporated (or recognised by ARN), False if the
        read failed - the caller uses that to downgrade completeness."""
        if not policy_arn:
            return True
        # AdministratorAccess is AWS-managed; recognise it by ARN and model the
        # equivalent Allow */* rather than reading its document.
        if policy_arn.endswith(":policy/AdministratorAccess"):
            grants.add_admin_grant()
            return True
        try:
            default = iam.get_policy(PolicyArn=policy_arn)["Policy"]["DefaultVersionId"]
            doc = iam.get_policy_version(PolicyArn=policy_arn, VersionId=default)["PolicyVersion"]["Document"]
            grants.add_document(_load_doc(doc))
            return True
        except Exception as exc:  # noqa: BLE001 - unreadable managed policy: record, skip
            self._handle(exc, "iam:GetPolicyVersion", "", result)
            return False

    def _self_read_group(self, iam, gname: str, grants: "Grants", result: EnumResult) -> bool:
        """Fold a group's policies into `grants` (inheritance). Returns True only
        if every listing and document read succeeded."""
        if not gname:
            return True
        ok = True
        try:
            for page in iam.get_paginator("list_attached_group_policies").paginate(GroupName=gname):
                for m in page.get("AttachedPolicies", []):
                    if not self._read_managed_into(iam, m.get("PolicyArn", ""), grants, result):
                        ok = False
        except Exception as exc:  # noqa: BLE001
            self._handle(exc, "iam:ListAttachedGroupPolicies", "", result)
            ok = False
        try:
            for page in iam.get_paginator("list_group_policies").paginate(GroupName=gname):
                for pname in page.get("PolicyNames", []):
                    try:
                        doc = iam.get_group_policy(GroupName=gname, PolicyName=pname)["PolicyDocument"]
                        grants.add_document(_load_doc(doc))
                    except Exception as exc2:  # noqa: BLE001
                        self._handle(exc2, "iam:GetGroupPolicy", "", result)
                        ok = False
        except Exception as exc:  # noqa: BLE001
            self._handle(exc, "iam:ListGroupPolicies", "", result)
            ok = False
        return ok

    def _self_read_user(self, iam, arn: str, result: EnumResult) -> "_SelfRead":
        grants = Grants()
        attached: list[str] = []
        got_any = False   # at least one listing returned
        complete = True   # EVERY listing AND EVERY referenced document read succeeded
        principal_arn = arn
        try:
            u = iam.get_user()["User"]
            name = u["UserName"]
            principal_arn = u.get("Arn", arn)
        except Exception as exc:  # noqa: BLE001 - fall back to the ARN's user name
            self._handle(exc, "iam:GetUser", "", result)
            name = arn.split(":user/", 1)[1].rsplit("/", 1)[-1] if ":user/" in arn else arn.rsplit("/", 1)[-1]
            complete = False
        try:
            for page in iam.get_paginator("list_attached_user_policies").paginate(UserName=name):
                for m in page.get("AttachedPolicies", []):
                    parn = m.get("PolicyArn", "")
                    if parn:
                        attached.append(parn)
                    if not self._read_managed_into(iam, parn, grants, result):
                        complete = False
            got_any = True
        except Exception as exc:  # noqa: BLE001
            if not self._handle(exc, "iam:ListAttachedUserPolicies", "", result):
                raise
            complete = False
        try:
            for page in iam.get_paginator("list_user_policies").paginate(UserName=name):
                for pname in page.get("PolicyNames", []):
                    try:
                        doc = iam.get_user_policy(UserName=name, PolicyName=pname)["PolicyDocument"]
                        grants.add_document(_load_doc(doc))
                    except Exception as exc2:  # noqa: BLE001
                        self._handle(exc2, "iam:GetUserPolicy", "", result)
                        complete = False
            got_any = True
        except Exception as exc:  # noqa: BLE001
            if not self._handle(exc, "iam:ListUserPolicies", "", result):
                raise
            complete = False
        try:
            for page in iam.get_paginator("list_groups_for_user").paginate(UserName=name):
                for grp in page.get("Groups", []):
                    if not self._self_read_group(iam, grp.get("GroupName", ""), grants, result):
                        complete = False
            got_any = True
        except Exception as exc:  # noqa: BLE001 - group inheritance is best-effort
            self._handle(exc, "iam:ListGroupsForUser", "", result)
            complete = False
        return _SelfRead(grants, _completeness(got_any, complete), attached, principal_arn)

    def _self_read_role(self, iam, arn: str, result: EnumResult) -> "_SelfRead":
        """The role equivalent of the user self-read - the primary POST-PIVOT
        vantage (you assume a role, so the current principal is a role)."""
        grants = Grants()
        attached: list[str] = []
        got_any = False
        complete = True
        name = arn.split(":role/", 1)[1].rsplit("/", 1)[-1] if ":role/" in arn else arn.rsplit("/", 1)[-1]
        principal_arn = arn
        try:
            r = iam.get_role(RoleName=name)["Role"]
            name = r.get("RoleName", name)
            principal_arn = r.get("Arn", arn)  # path-qualified
        except Exception as exc:  # noqa: BLE001 - keep the ARN-derived name
            self._handle(exc, "iam:GetRole", "", result)
            complete = False
        try:
            for page in iam.get_paginator("list_attached_role_policies").paginate(RoleName=name):
                for m in page.get("AttachedPolicies", []):
                    parn = m.get("PolicyArn", "")
                    if parn:
                        attached.append(parn)
                    if not self._read_managed_into(iam, parn, grants, result):
                        complete = False
            got_any = True
        except Exception as exc:  # noqa: BLE001
            if not self._handle(exc, "iam:ListAttachedRolePolicies", "", result):
                raise
            complete = False
        try:
            for page in iam.get_paginator("list_role_policies").paginate(RoleName=name):
                for pname in page.get("PolicyNames", []):
                    try:
                        doc = iam.get_role_policy(RoleName=name, PolicyName=pname)["PolicyDocument"]
                        grants.add_document(_load_doc(doc))
                    except Exception as exc2:  # noqa: BLE001
                        self._handle(exc2, "iam:GetRolePolicy", "", result)
                        complete = False
            got_any = True
        except Exception as exc:  # noqa: BLE001
            if not self._handle(exc, "iam:ListRolePolicies", "", result):
                raise
            complete = False
        return _SelfRead(grants, _completeness(got_any, complete), attached, principal_arn)

    def resolve_self(self, client: AwsClient, result: EnumResult = None) -> EnumResult:
        """Resolve the current principal from its OWN vantage. Three-state by
        completeness of the self-read:
          * complete - every required listing AND every referenced document read
            succeeded. Publishes AUTHORITATIVE `grant_statements` (possibly []),
            `action_patterns`, `attached_policies`, `is_admin`, and mints the admin
            goal + EffectiveAdmin + self-referential privesc edges. An authoritative
            empty set supersedes/clears stale merged properties.
          * partial - some component succeeded but coverage is incomplete. Publishes
            observed grants as NON-authoritative `grant_statements_partial` (additive
            conditional evidence that never retracts/replaces a prior complete
            snapshot), plus `attached_policies`; no `is_admin`, no self edges.
          * none - nothing readable. Omits all policy properties.
        `confirmed_actions` (empirical probes) is always present and SEPARATE from
        policy grants - never fed into policy-derived correlation. Does NOT
        enumerate other principals; later pivots fill those in."""
        result = result if result is not None else EnumResult()
        iam = client.client("iam")
        arn = canonical_principal_id(client.identity)
        account = client.identity.account

        if ":user/" in arn:
            sr = self._self_read_user(iam, arn, result)
            is_user = True
        elif ":role/" in arn:
            sr = self._self_read_role(iam, arn, result)
            is_user = False
        else:
            sr = _SelfRead(Grants(), "none", [], arn)
            is_user = False

        node_arn = sr.principal_arn or arn
        confirmed = self._probe_actions(client)
        if confirmed:
            result.findings.append(Finding(
                severity=Severity.HIGH, category="permissions",
                title=f"Current identity holds {len(confirmed)} probed permission(s)",
                detail="Effective permissions confirmed by successful API calls.",
                evidence="\n".join(confirmed), arn=node_arn,
            ))
        kind = NodeKind.from_arn(node_arn)
        if kind == NodeKind.UNKNOWN:
            kind = NodeKind.IAM_USER if is_user else NodeKind.IAM_ROLE
        props = {"is_caller": True, "source": "self-read", "confirmed_actions": confirmed}

        if sr.completeness == "complete":
            props["grant_read_status"] = "complete"
            props["grant_statements"] = sr.grants.to_statements()
            props["action_patterns"] = sorted({p for p, _r, _c in sr.grants.allows})
            props["attached_policies"] = sr.attached
            props["is_admin"] = sr.grants.is_admin
        elif sr.completeness == "partial":
            # Non-authoritative: separate keys so a partial read can never overwrite
            # authoritative display data on a prior complete snapshot.
            props["grant_read_status"] = "partial"
            props["grant_statements_partial"] = sr.grants.to_statements()
            props["action_patterns_partial"] = sorted({p for p, _r, _c in sr.grants.allows})
            props["attached_policies_partial"] = sr.attached

        result.nodes.append(Node(object_id=node_arn, name=node_arn.rsplit("/", 1)[-1],
                                 kind=kind, account=account, properties=props))

        # Self-referential privesc + admin only from a COMPLETE (authoritative)
        # read - never claim escalation we could not fully verify.
        if sr.completeness == "complete":
            admin_id = _admin_goal_id(account)
            result.nodes.append(Node(
                object_id=admin_id, name="admin", kind=NodeKind.AWS_ACCOUNT, account=account,
                properties={"is_admin": True, "synthetic_goal": True},
            ))
            if sr.grants.is_admin:
                result.edges.append(Edge(node_arn, admin_id, "EffectiveAdmin", {"reason": "self-read-admin"}))
            info = {"grants": sr.grants, "groups": [], "attached": sr.attached}
            self._apply_privesc_rules(node_arn, info, {}, {}, {}, {}, admin_id, result, is_user=is_user)
        return result

    # ─── Graph construction from GAAD ──────────────────────────────────────

    def _build_from_gaad(
        self, gaad: dict, account: str, client: AwsClient, result: EnumResult,
        *, complete: bool = True,
    ) -> None:
        # `complete` distinguishes a real GAAD dump (full policy documents ->
        # authoritative grant_statements) from a piecemeal, list-only rebuild
        # (identities without policies). A list-only record must NOT publish
        # authoritative (empty) grant_statements, or a later vantage would treat it
        # as "this principal has no permissions" and erase real discovered edges.
        # Managed-policy documents by ARN (default version).
        policy_docs: dict[str, dict] = {}
        for pol in gaad.get("Policies", []):
            arn = pol.get("Arn", "")
            default_ver = pol.get("DefaultVersionId")
            for ver in pol.get("PolicyVersionList", []):
                if ver.get("IsDefaultVersion") or ver.get("VersionId") == default_ver:
                    policy_docs[arn] = _load_doc(ver.get("Document", {}))
                    break
            # Node for the policy itself
            result.nodes.append(
                Node(
                    object_id=arn,
                    name=pol.get("PolicyName", arn),
                    kind=NodeKind.IAM_POLICY,
                    account=account,
                    properties={"attachment_count": pol.get("AttachmentCount", 0)},
                )
            )

        def grants_for(managed: list, inline: list, inline_key: str) -> Grants:
            g = Grants()
            for m in managed:
                doc = policy_docs.get(m.get("PolicyArn", ""))
                if doc:
                    g.add_document(doc)
                # AdministratorAccess by ARN is admin even if we lack its doc -
                # inject the equivalent Allow */* so deny-precedence still applies.
                if m.get("PolicyArn", "").endswith(":policy/AdministratorAccess"):
                    g.add_admin_grant()
            for pol in inline:
                g.add_document(_load_doc(pol.get(inline_key, {})))
            return g

        # ── Groups ──
        group_grants: dict[str, Grants] = {}
        group_admin: dict[str, bool] = {}
        for grp in gaad.get("GroupDetailList", []):
            name = grp.get("GroupName", "")
            arn = grp.get("Arn", "")
            g = grants_for(
                grp.get("AttachedManagedPolicies", []),
                grp.get("GroupPolicyList", []),
                "PolicyDocument",
            )
            group_grants[name] = g
            group_admin[name] = g.is_admin
            attached = [m.get("PolicyArn", "") for m in grp.get("AttachedManagedPolicies", [])]
            gprops = {}
            if complete:
                # Same conditional construction as users/roles: a list-only group
                # must not appear authoritatively non-admin / policy-empty.
                gprops["is_admin"] = g.is_admin
                gprops["attached_policies"] = attached
            result.nodes.append(
                Node(object_id=arn, name=name, kind=NodeKind.IAM_GROUP, account=account, properties=gprops)
            )

        # ── Users ──
        users: dict[str, dict] = {}
        for usr in gaad.get("UserDetailList", []):
            name = usr.get("UserName", "")
            arn = usr.get("Arn", "")
            g = grants_for(
                usr.get("AttachedManagedPolicies", []),
                usr.get("UserPolicyList", []),
                "PolicyDocument",
            )
            # Fold in group-inherited grants.
            member_groups = usr.get("GroupList", [])
            for gname in member_groups:
                gg = group_grants.get(gname)
                if gg:
                    g.merge(gg)  # fold in group statements whole (deny + admin recompute)
            attached = [m.get("PolicyArn", "") for m in usr.get("AttachedManagedPolicies", [])]
            users[arn] = {"name": name, "grants": g, "groups": member_groups, "attached": attached}
            uprops = {}
            if complete:
                # Authoritative snapshot: full policy documents were read.
                uprops["grant_read_status"] = "complete"
                uprops["grant_statements"] = g.to_statements()
                uprops["is_admin"] = g.is_admin
                uprops["attached_policies"] = attached
                uprops["action_patterns"] = sorted({p for p, _r, _c in g.allows})
            # Piecemeal (list-only): omit ALL policy-derived properties, or a
            # list-only record would downgrade a richer node on merge.
            result.nodes.append(
                Node(object_id=arn, name=name, kind=NodeKind.IAM_USER, account=account, properties=uprops)
            )

        # ── Roles ──
        roles: dict[str, dict] = {}
        for role in gaad.get("RoleDetailList", []):
            name = role.get("RoleName", "")
            arn = role.get("Arn", "")
            g = grants_for(
                role.get("AttachedManagedPolicies", []),
                role.get("RolePolicyList", []),
                "PolicyDocument",
            )
            trust = _load_doc(role.get("AssumeRolePolicyDocument", {}))
            trusted_arns, trusts_ext, trusts_wild = self._parse_trust(trust, account)
            attached = [m.get("PolicyArn", "") for m in role.get("AttachedManagedPolicies", [])]
            service_linked = _is_service_linked(arn, name)
            roles[arn] = {
                "name": name,
                "grants": g,
                "trusted": trusted_arns,
                "trusts_external": trusts_ext,
                "trusts_wildcard": trusts_wild,
                "service_linked": service_linked,
                "attached": attached,
            }
            rprops = {
                # Structural (trust/name-derived), safe to publish even list-only:
                "trusts_external": trusts_ext,
                "trusts_wildcard": trusts_wild,
                "is_org_management": name == "OrganizationAccountAccessRole",
                "service_linked": service_linked,
            }
            if complete:
                rprops["grant_read_status"] = "complete"
                rprops["grant_statements"] = g.to_statements()
                rprops["is_admin"] = g.is_admin
                rprops["attached_policies"] = attached
                rprops["action_patterns"] = sorted({p for p, _r, _c in g.allows})
            result.nodes.append(
                Node(object_id=arn, name=name, kind=NodeKind.IAM_ROLE, account=account, properties=rprops)
            )

        # ── Admin goal node ──
        admin_id = _admin_goal_id(account)
        result.nodes.append(
            Node(
                object_id=admin_id,
                name="admin",
                kind=NodeKind.AWS_ACCOUNT,
                account=account,
                properties={"is_admin": True, "synthetic_goal": True},
            )
        )

        # ── Edges ──
        self._mint_edges(users, roles, group_grants, group_admin, gaad, account, admin_id, result)

    def _parse_trust(self, trust: dict, account: str):
        """Return (trusted_principal_arns, trusts_external, trusts_wildcard)."""
        trusted: list[str] = []
        trusts_ext = False
        trusts_wild = False
        for stmt in _as_list(trust.get("Statement")):
            if not isinstance(stmt, dict) or stmt.get("Effect") != "Allow":
                continue
            actions = _as_list(stmt.get("Action"))
            if not any("assumerole" in a.lower() for a in actions):
                continue
            principal = stmt.get("Principal", {})
            aws_principals = _as_list(principal.get("AWS")) if isinstance(principal, dict) else _as_list(principal)
            for p in aws_principals:
                if p == "*":
                    trusts_wild = True
                    continue
                trusted.append(p)
                # arn:aws:iam::ACCT:root  or  arn:aws:iam::ACCT:...
                if account and account not in p:
                    trusts_ext = True
        return trusted, trusts_ext, trusts_wild

    def _mint_edges(
        self, users, roles, group_grants, group_admin, gaad, account, admin_id, result: EnumResult
    ):
        # Name -> group ARN, for MemberOf and AddUserToGroup targets.
        group_arn_by_name = {
            g.get("GroupName", ""): g.get("Arn", "") for g in gaad.get("GroupDetailList", [])
        }

        # Admin principals -> admin goal (reaching them == reaching admin).
        for arn, info in {**users, **roles}.items():
            if info["grants"].is_admin:
                result.edges.append(Edge(arn, admin_id, "EffectiveAdmin", {"reason": "wildcard-admin"}))

        # CanAssume edges from role trust policies.
        all_principals = {**users, **roles}
        for role_arn, rinfo in roles.items():
            for tp in rinfo["trusted"]:
                # Specific principal ARN trusted directly.
                if tp in all_principals:
                    result.edges.append(Edge(tp, role_arn, "CanAssume", {"via": "trust-direct"}))
                # Account-root trust: any principal in the account with AssumeRole.
                elif tp.endswith(":root"):
                    tp_account = tp.split(":")[4] if ":" in tp else ""
                    for parn, pinfo in all_principals.items():
                        if pinfo.get("grants") is None:
                            continue
                        ok, cond = pinfo["grants"].allows_action("sts:AssumeRole", role_arn)
                        if ok and (not tp_account or tp_account == account):
                            result.edges.append(
                                Edge(parn, role_arn, "CanAssume", {"via": "trust-account-root"}, conditional=cond)
                            )

        # MemberOf + privesc edges per user.
        for arn, info in users.items():
            for gname in info["groups"]:
                garn = group_arn_by_name.get(gname)
                if garn:
                    result.edges.append(Edge(arn, garn, "MemberOf", {}))
            self._apply_privesc_rules(arn, info, users, roles, group_arn_by_name, group_admin, admin_id, result, is_user=True)

        # Privesc edges per role (roles can escalate too, once assumed).
        for arn, info in roles.items():
            self._apply_privesc_rules(arn, info, users, roles, group_arn_by_name, group_admin, admin_id, result, is_user=False)

    def _apply_privesc_rules(
        self, arn, info, users, roles, group_arn_by_name, group_admin, admin_id, result: EnumResult, is_user: bool
    ):
        grants: Grants = info["grants"]
        for edge_kind, selector, required in _PRIVESC_RULES:

            if selector == "self_admin":
                # SELF-scoped: the escalation acts on the principal's OWN ARN, so a
                # grant scoped to some OTHER user/role must not mint a self edge.
                ok, cond = _grant_allows(grants, required, arn, arn)
                if ok:
                    result.edges.append(Edge(arn, admin_id, edge_kind, {}, conditional=cond))

            elif selector == "attached_policy":
                # One edge per customer-managed policy attached to the principal,
                # checked against that policy's ARN. AWS-managed policies cannot
                # have versions rewritten, so they are skipped.
                for pol_arn in info.get("attached", []):
                    if not pol_arn or pol_arn.startswith("arn:aws:iam::aws:policy/"):
                        continue
                    ok, cond = _grant_allows(grants, required, arn, pol_arn)
                    if ok:
                        result.edges.append(Edge(arn, admin_id, edge_kind, {"via_policy": pol_arn}, conditional=cond))

            elif selector == "group_admin":
                if is_user:
                    for gname in info.get("groups", []):
                        garn = group_arn_by_name.get(gname)
                        if not garn:
                            continue
                        ok, cond = _grant_allows(grants, required, arn, garn)
                        if ok:
                            result.edges.append(Edge(arn, admin_id, edge_kind, {"via_group": gname}, conditional=cond))

            elif selector == "users":
                for uarn in users:
                    if uarn == arn:
                        continue
                    ok, cond = _grant_allows(grants, required, arn, uarn)
                    if ok:
                        result.edges.append(Edge(arn, uarn, edge_kind, {}, conditional=cond))

            elif selector == "groups":
                for gname, garn in group_arn_by_name.items():
                    ok, cond = _grant_allows(grants, required, arn, garn)
                    if ok:
                        result.edges.append(Edge(arn, garn, edge_kind, {}, conditional=cond))

            elif selector in ("roles", "passable_roles", "assumable_roles"):
                # Target any non-service-linked role. PassRole / AssumeRole legs
                # are checked against the specific role ARN; the compute/create
                # gate actions are ANY (resource out of scope). Service-linked
                # roles are excluded - not passable to arbitrary compute or
                # assumable by a user.
                for rarn, rinfo in roles.items():
                    if rarn == arn or rinfo.get("service_linked"):
                        continue
                    ok, cond = _grant_allows(grants, required, arn, rarn)
                    if ok:
                        result.edges.append(Edge(arn, rarn, edge_kind, {}, conditional=cond))
