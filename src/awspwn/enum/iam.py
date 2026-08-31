"""IAM enumerator - builds the identity graph and mints privilege-escalation
edges from policy documents.

Degradation chain (you rarely have full IAM read on a real engagement):
  1. iam:GetAccountAuthorizationDetails - one-shot dump of everything.
  2. denied -> individual List*/Get* per object type.
  3. denied -> enumerate-iam brute force: probe a curated list of read-only,
     safe-arg API calls to map the CURRENT identity's effective permissions
     with zero IAM read privilege.

Privesc edges are minted by a local, best-effort policy matcher over the raw
Allow statements. This is fast and works offline / under moto (which does not
implement SimulatePrincipalPolicy). policy/simulate.py refines the same edges
authoritatively when simulation is available. Deny statements and most
Condition keys are NOT evaluated here - such edges are marked `conditional` so
the operator knows they are best-effort. This is the documented correctness
limitation of the offline path.
"""

from __future__ import annotations

import json
import re
import urllib.parse

from ..aws_client import AwsClient
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


def _action_regex(pattern: str) -> re.Pattern:
    """AWS action wildcard -> regex. 'iam:Create*' -> ^iam:create.*$ (ci)."""
    esc = re.escape(pattern).replace(r"\*", ".*").replace(r"\?", ".")
    return re.compile("^" + esc + "$", re.IGNORECASE)


class Grants:
    """Aggregated Allow actions for a principal, with resource context."""

    def __init__(self):
        # list of (action_pattern, [resources], has_condition)
        self.allows: list[tuple[str, list[str], bool]] = []
        self.is_admin = False

    def add_document(self, doc: dict) -> None:
        for stmt in _as_list(doc.get("Statement")):
            if not isinstance(stmt, dict):
                continue
            if stmt.get("Effect") != "Allow":
                continue  # deny-precedence not modelled here (see module docstring)
            actions = _as_list(stmt.get("Action")) + _as_list(stmt.get("NotAction"))
            resources = _as_list(stmt.get("Resource")) or ["*"]
            has_cond = bool(stmt.get("Condition"))
            for act in actions:
                self.allows.append((act, resources, has_cond))
                if act == "*" and "*" in resources and not has_cond:
                    self.is_admin = True

    def allows_action(self, action: str) -> tuple[bool, bool]:
        """Return (allowed, conditional)."""
        conditional = False
        for pattern, _resources, has_cond in self.allows:
            if _action_regex(pattern).match(action):
                if has_cond:
                    conditional = True
                    continue
                return True, False
        return (conditional, conditional)

    def allows_all(self, actions: list[str]) -> tuple[bool, bool]:
        """True only if EVERY action is allowed. Conditional if any leg is."""
        conditional = False
        for a in actions:
            ok, cond = self.allows_action(a)
            if not ok:
                return False, False
            conditional = conditional or cond
        return True, conditional


# ─── Privesc rule table ─────────────────────────────────────────────────────
# Each rule maps a set of required actions to an edge kind and a target
# selector. Selectors: "admin" (self-escalation to admin goal), "users",
# "groups", "roles", "assumable_roles".

_PRIVESC_RULES = [
    # Self-escalation to admin (the principal itself gains admin)
    (["iam:AttachUserPolicy"], "AttachUserPolicy", "self_admin"),
    (["iam:PutUserPolicy"], "PutUserPolicy", "self_admin"),
    (["iam:AttachGroupPolicy"], "AttachGroupPolicy", "group_admin"),
    (["iam:PutGroupPolicy"], "PutGroupPolicy", "group_admin"),
    (["iam:CreatePolicyVersion"], "CreatePolicyVersion", "attached_policy_admin"),
    (["iam:SetDefaultPolicyVersion"], "SetDefaultPolicyVersion", "attached_policy_admin"),
    (["iam:CreateRole", "iam:AttachRolePolicy", "sts:AssumeRole"], "CreateRoleAndAssume", "self_admin"),
    (["iam:CreateAccessKey"], "CreateAccessKey", "users"),
    (["iam:CreateLoginProfile"], "CreateLoginProfile", "users"),
    (["iam:UpdateLoginProfile"], "UpdateLoginProfile", "users"),
    (["iam:AddUserToGroup"], "AddUserToGroup", "groups"),
    (["iam:UpdateAssumeRolePolicy", "sts:AssumeRole"], "UpdateAssumeRolePolicy", "roles"),
    (["iam:AttachRolePolicy", "sts:AssumeRole"], "AttachRolePolicy", "roles"),
    (["iam:PutRolePolicy", "sts:AssumeRole"], "PutRolePolicy", "roles"),
    # PassRole + compute (self gains a passed role's privileges)
    (["iam:PassRole", "ec2:RunInstances"], "RunInstanceWithRole", "passable_roles"),
    (["iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"], "CreateLambdaWithRole", "passable_roles"),
    (["iam:PassRole", "cloudformation:CreateStack"], "CloudFormationCreateStack", "passable_roles"),
    (["iam:PassRole", "ecs:RunTask"], "ECSRunTaskWithRole", "passable_roles"),
    (["iam:PassRole", "glue:CreateDevEndpoint"], "GlueCreateDevEndpoint", "passable_roles"),
    (["iam:PassRole", "sagemaker:CreateNotebookInstance", "sagemaker:CreatePresignedNotebookInstanceUrl"], "SageMakerCreateNotebook", "passable_roles"),
    (["iam:PassRole", "codebuild:CreateProject", "codebuild:StartBuild"], "CodeBuildCreateProject", "passable_roles"),
]


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
        if gaad is None:
            gaad = self._piecemeal(iam, result)
        if gaad is None:
            # Total IAM-read denial: probe our own effective perms empirically.
            self._brute_force(client, result)
            return result

        self._build_from_gaad(gaad, account, client, result)
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

    def _brute_force(self, client: AwsClient, result: EnumResult) -> None:
        result.findings.append(
            Finding(
                severity=Severity.MEDIUM,
                category="enum",
                title="Full IAM read denied - falling back to permission brute-force",
                detail="Could not read account IAM. Probing the current identity's own effective permissions.",
            )
        )
        allowed: list[str] = []
        for perm, service, op, kwargs in self._PROBES:
            try:
                getattr(client.client(service), op)(**kwargs)
                allowed.append(perm)
            except Exception:  # noqa: BLE001 - denial is the expected common case
                continue
        if allowed:
            result.findings.append(
                Finding(
                    severity=Severity.HIGH,
                    category="permissions",
                    title=f"Current identity holds {len(allowed)} probed permission(s)",
                    detail="Effective permissions confirmed by successful API calls.",
                    evidence="\n".join(sorted(allowed)),
                    arn=client.identity.arn,
                )
            )

    # ─── Graph construction from GAAD ──────────────────────────────────────

    def _build_from_gaad(
        self, gaad: dict, account: str, client: AwsClient, result: EnumResult
    ) -> None:
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
                # AdministratorAccess by ARN is admin even if we lack its doc.
                if m.get("PolicyArn", "").endswith(":policy/AdministratorAccess"):
                    g.is_admin = True
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
            result.nodes.append(
                Node(
                    object_id=arn,
                    name=name,
                    kind=NodeKind.IAM_GROUP,
                    account=account,
                    properties={"is_admin": g.is_admin, "attached_policies": attached},
                )
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
                    g.allows.extend(gg.allows)
                    g.is_admin = g.is_admin or gg.is_admin
            attached = [m.get("PolicyArn", "") for m in usr.get("AttachedManagedPolicies", [])]
            users[arn] = {"name": name, "grants": g, "groups": member_groups}
            result.nodes.append(
                Node(
                    object_id=arn,
                    name=name,
                    kind=NodeKind.IAM_USER,
                    account=account,
                    properties={
                        "is_admin": g.is_admin,
                        "attached_policies": attached,
                        "action_patterns": sorted({p for p, _r, _c in g.allows}),
                    },
                )
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
            }
            result.nodes.append(
                Node(
                    object_id=arn,
                    name=name,
                    kind=NodeKind.IAM_ROLE,
                    account=account,
                    properties={
                        "is_admin": g.is_admin,
                        "attached_policies": attached,
                        "trusts_external": trusts_ext,
                        "trusts_wildcard": trusts_wild,
                        "is_org_management": name == "OrganizationAccountAccessRole",
                        "service_linked": service_linked,
                        "action_patterns": sorted({p for p, _r, _c in g.allows}),
                    },
                )
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
                        ok, cond = pinfo["grants"].allows_action("sts:AssumeRole")
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
        for required, edge_kind, selector in _PRIVESC_RULES:
            ok, conditional = grants.allows_all(required)
            if not ok:
                continue

            if selector == "self_admin":
                result.edges.append(Edge(arn, admin_id, edge_kind, {}, conditional=conditional))

            elif selector == "group_admin":
                # Escalates admin only via a group the principal belongs to.
                if is_user:
                    for gname in info.get("groups", []):
                        if group_admin.get(gname) or True:  # attaching admin makes any group admin
                            garn = group_arn_by_name.get(gname)
                            if garn:
                                result.edges.append(Edge(arn, admin_id, edge_kind, {"via_group": gname}, conditional=conditional))

            elif selector == "attached_policy_admin":
                # Rewriting an attached customer-managed policy -> self admin.
                result.edges.append(Edge(arn, admin_id, edge_kind, {}, conditional=conditional))

            elif selector == "users":
                for uarn in users:
                    if uarn != arn:
                        result.edges.append(Edge(arn, uarn, edge_kind, {}, conditional=conditional))

            elif selector == "groups":
                for gname, garn in group_arn_by_name.items():
                    result.edges.append(Edge(arn, garn, edge_kind, {}, conditional=conditional))

            elif selector == "roles":
                for rarn, rinfo in roles.items():
                    if rarn != arn and not rinfo.get("service_linked"):
                        result.edges.append(Edge(arn, rarn, edge_kind, {}, conditional=conditional))

            elif selector in ("passable_roles", "assumable_roles"):
                # Best-effort: target any non-service-linked role. Resource
                # scoping on PassRole is refined by simulate.py; here we surface
                # the candidate paths. Service-linked roles are excluded - they
                # cannot be passed to arbitrary compute or assumed by a user.
                for rarn, rinfo in roles.items():
                    if rarn != arn and not rinfo.get("service_linked"):
                        result.edges.append(Edge(arn, rarn, edge_kind, {}, conditional=conditional))
