"""Organizations / IAM Identity Center enumerator - the org structure, member
accounts, SCPs, and SSO permission sets. Present only when the caller sits in
(or is delegated admin of) the management account; denied otherwise, which is
recorded rather than fatal.
"""

from __future__ import annotations

from ..aws_client import AwsClient
from ..models import Edge, Finding, Node, NodeKind, Severity
from .base import EnumResult, ServiceEnumerator


class OrgEnumerator(ServiceEnumerator):
    name = "org"
    service = "organizations"
    is_global = True

    def enumerate(self, client: AwsClient, region: str) -> EnumResult:
        result = EnumResult()
        org = client.client("organizations")
        account = client.identity.account

        try:
            desc = org.describe_organization().get("Organization", {})
        except Exception as exc:  # noqa: BLE001
            if not self._handle(exc, "organizations:DescribeOrganization", "", result):
                raise
            return result

        org_id = desc.get("Id", "")
        mgmt = desc.get("MasterAccountId", "")
        org_arn = desc.get("Arn", f"arn:aws:organizations::{mgmt}:organization/{org_id}")
        result.nodes.append(
            Node(object_id=org_arn, name=org_id, kind=NodeKind.ORGANIZATION, account=mgmt,
                 properties={"management_account": mgmt})
        )
        in_mgmt = account and account == mgmt
        if in_mgmt:
            result.findings.append(
                Finding(
                    severity=Severity.CRITICAL,
                    category="org",
                    title="Caller is in the Organizations MANAGEMENT account",
                    detail="You can assume OrganizationAccountAccessRole into every member account - org-wide admin.",
                    arn=org_arn,
                )
            )

        # Member accounts
        try:
            accounts = []
            for page in org.get_paginator("list_accounts").paginate():
                accounts.extend(page.get("Accounts", []))
            for acct in accounts:
                aid = acct.get("Id", "")
                aarn = acct.get("Arn", f"arn:aws:organizations::{mgmt}:account/{org_id}/{aid}")
                kind = NodeKind.AWS_ACCOUNT if aid == account else NodeKind.EXTERNAL_ACCOUNT
                result.nodes.append(
                    Node(object_id=aarn, name=acct.get("Name", aid), kind=kind, account=aid,
                         properties={"email": acct.get("Email", ""), "status": acct.get("Status", "")})
                )
                # From the management account, model the org-admin reach.
                if in_mgmt and aid != account:
                    result.edges.append(Edge(org_arn, aarn, "OrgManagementAccountAccess", {"role": "OrganizationAccountAccessRole"}))
        except Exception as exc:  # noqa: BLE001
            self._handle(exc, "organizations:ListAccounts", "", result)

        # SCPs
        try:
            for page in org.get_paginator("list_policies").paginate(Filter="SERVICE_CONTROL_POLICY"):
                for pol in page.get("Policies", []):
                    pid = pol.get("Id", "")
                    parn = pol.get("Arn", f"arn:aws:organizations::{mgmt}:policy/{org_id}/service_control_policy/{pid}")
                    result.nodes.append(
                        Node(object_id=parn, name=pol.get("Name", pid), kind=NodeKind.SCP, account=mgmt,
                             properties={"aws_managed": pol.get("AwsManaged", False)})
                    )
        except Exception as exc:  # noqa: BLE001
            self._handle(exc, "organizations:ListPolicies", "", result)

        # IAM Identity Center (SSO)
        self._sso(client, account, result)

        return result

    def _sso(self, client, account, result):
        try:
            sso = client.client("sso-admin")
            instances = sso.list_instances().get("Instances", [])
        except Exception as exc:  # noqa: BLE001
            self._handle(exc, "sso-admin:ListInstances", "", result)
            return
        for inst in instances:
            inst_arn = inst.get("InstanceArn", "")
            result.nodes.append(
                Node(object_id=inst_arn, name="IdentityCenter", kind=NodeKind.IDENTITY_CENTER, account=account,
                     properties={"identity_store": inst.get("IdentityStoreId", "")})
            )
            try:
                for page in sso.get_paginator("list_permission_sets").paginate(InstanceArn=inst_arn):
                    for ps_arn in page.get("PermissionSets", []):
                        result.nodes.append(
                            Node(object_id=ps_arn, name=ps_arn.rsplit("/", 1)[-1],
                                 kind=NodeKind.SSO_PERMISSION_SET, account=account, properties={})
                        )
            except Exception as exc:  # noqa: BLE001
                self._handle(exc, "sso-admin:ListPermissionSets", "", result)
