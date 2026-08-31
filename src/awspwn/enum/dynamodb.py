"""DynamoDB enumerator - tables (metadata only). Table contents are read via the
DynamoDBScan exploitation edge, not during enum.
"""

from __future__ import annotations

from ..aws_client import AwsClient
from ..models import Node, NodeKind
from .base import EnumResult, ServiceEnumerator


class DynamoDbEnumerator(ServiceEnumerator):
    name = "dynamodb"
    service = "dynamodb"
    is_global = False

    def enumerate(self, client: AwsClient, region: str) -> EnumResult:
        result = EnumResult()
        ddb = client.client("dynamodb", region=region)
        account = client.identity.account
        try:
            for page in ddb.get_paginator("list_tables").paginate():
                for name in page.get("TableNames", []):
                    arn = f"arn:aws:dynamodb:{region}:{account}:table/{name}"
                    props = {}
                    try:
                        desc = ddb.describe_table(TableName=name).get("Table", {})
                        props["item_count"] = desc.get("ItemCount", 0)
                    except Exception:  # noqa: BLE001
                        pass
                    result.nodes.append(
                        Node(object_id=arn, name=name, kind=NodeKind.DYNAMODB_TABLE, account=account, region=region, properties=props)
                    )
        except Exception as exc:  # noqa: BLE001
            if not self._handle(exc, "dynamodb:ListTables", region, result):
                raise
        return result
