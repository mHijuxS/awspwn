"""AWS client layer - session factory, region iteration, retry/backoff, and
error classification.

This is AWSPwn's analogue of ADPwn's kerberos.py. Where ADPwn detects
KRB_AP_ERR_SKEW and monkey-patches datetime, AWSPwn handles the AWS transient
failure classes: IAM eventual consistency (a freshly minted key/grant is not
valid for a few seconds), throttling, expired tokens, and region opt-in. It
also centralises botocore ClientError classification so the rest of the tool
never inspects error strings by hand.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from enum import Enum
from typing import Callable, Optional

import boto3
from botocore.config import Config
from botocore.exceptions import (
    ClientError,
    EndpointConnectionError,
    NoCredentialsError,
)

from .models import AwsIdentity


# Global (partition-wide) services always hit one endpoint; regional services
# are swept across active regions.
GLOBAL_SERVICES = {"iam", "s3", "sts", "organizations", "sso-admin", "identitystore"}

# A safe default region sweep when we cannot (or should not) call
# ec2:DescribeRegions. Ordered by how often things actually live there.
DEFAULT_REGIONS = [
    "us-east-1",
    "us-west-2",
    "eu-west-1",
    "us-east-2",
    "eu-central-1",
    "ap-southeast-1",
    "ap-northeast-1",
    "us-west-1",
]


# ─── Principal identity normalization ───────────────────────────────────────


def canonical_principal_id(identity) -> str:
    """Map a live STS session ARN back to the IAM principal ARN used as a graph
    node id, so a propagated identity lines up with the node it came from.

        arn:aws:sts::ACCT:assumed-role/ROLE/SESSION  -> arn:aws:iam::ACCT:role/ROLE

    User ARNs, role ARNs, and anything not recognisably an STS assumed-role ARN
    are returned unchanged. Federated-user / caller-identity STS ARNs have no IAM
    node, so they pass through as-is. Accepts an AwsIdentity or a bare ARN str.

    Note the deliberate asymmetry with the loop's frontier source: after a chosen
    pivot the destination graph-node id is already known (it is the edge target),
    so this normalizer is only needed where we have creds but no originating edge
    - the initial identity, the self-node minted during collection, and simulate's
    PolicySourceArn (which rejects STS session ARNs)."""
    arn = getattr(identity, "arn", identity) or ""
    parts = arn.split(":", 5)
    # arn : partition : service : region : account : resource
    if len(parts) < 6 or parts[2] != "sts":
        return arn
    resource = parts[5]
    if not resource.startswith("assumed-role/"):
        return arn  # federated-user / other STS forms have no IAM role node
    rest = resource[len("assumed-role/"):]
    role = rest.split("/", 1)[0]
    if not role:
        return arn
    return f"arn:{parts[1]}:iam::{parts[4]}:role/{role}"


def resolve_role_arn(client, role_name: str) -> str:
    """The path-qualified role ARN via iam:GetRole (an STS session ARN and the
    name-only canonicalization both drop the role's IAM path). Returns "" on any
    failure - a best-effort refinement, never fatal. Shared by the STS enumerator
    and the self-policy resolver so the GetRole logic lives in one place."""
    try:
        return client.client("iam").get_role(RoleName=role_name)["Role"]["Arn"]
    except Exception:  # noqa: BLE001 - no GetRole / wrong name: keep the caller's fallback
        return ""


def resolve_graph_principal_id(client) -> str:
    """The IAM principal ARN used as this identity's graph-node id: the STS
    session ARN canonicalized to its role, then path-qualified via GetRole when
    possible. This is the id to look the vantage up by, and the only ARN valid as
    a SimulatePrincipalPolicy PolicySourceArn (an STS session ARN is rejected)."""
    arn = canonical_principal_id(client.identity)
    if ":role/" in arn:
        resolved = resolve_role_arn(client, arn.rsplit("/", 1)[-1])
        if resolved:
            return resolved
    return arn


# ─── Error classification ───────────────────────────────────────────────────


class ErrorClass(Enum):
    ACCESS_DENIED = "access_denied"        # hard permission failure
    TRANSIENT = "transient"                # eventual consistency / bad-sig window
    THROTTLING = "throttling"              # slow down and retry
    EXPIRED = "expired"                    # session creds no longer valid
    REGION = "region"                      # wrong/opt-in region
    DRY_RUN_OK = "dry_run_ok"              # EC2 DryRun success signal
    NOT_FOUND = "not_found"                # resource/entity does not exist
    OTHER = "other"


_ACCESS_DENIED_CODES = {
    "AccessDenied",
    "AccessDeniedException",
    "UnauthorizedOperation",
    "AuthorizationError",
    "Forbidden",
}
_TRANSIENT_CODES = {
    "InvalidClientTokenId",
    "SignatureDoesNotMatch",
    "RequestExpired",  # can also mean skew; safe to retry a couple of times
}
_THROTTLING_CODES = {
    "Throttling",
    "ThrottlingException",
    "RequestLimitExceeded",
    "TooManyRequestsException",
    "RequestThrottled",
    "SlowDown",
}
_EXPIRED_CODES = {
    "ExpiredToken",
    "ExpiredTokenException",
    "TokenRefreshRequired",
}
_REGION_CODES = {
    "OptInRequired",
    "InvalidClientTokenId.Region",
    "UnrecognizedClientException",
}
_NOT_FOUND_CODES = {
    "NoSuchEntity",
    "NoSuchEntityException",
    "ResourceNotFoundException",
    "NoSuchBucket",
    "EntityDoesNotExist",
}


def error_code(err: ClientError) -> str:
    try:
        return err.response["Error"]["Code"]
    except (AttributeError, KeyError, TypeError):
        return ""


def classify(err: Exception) -> ErrorClass:
    """Map a boto exception to a handling class."""
    if isinstance(err, EndpointConnectionError):
        return ErrorClass.REGION
    if not isinstance(err, ClientError):
        return ErrorClass.OTHER
    code = error_code(err)
    if code == "DryRunOperation":
        return ErrorClass.DRY_RUN_OK
    if code in _ACCESS_DENIED_CODES:
        return ErrorClass.ACCESS_DENIED
    if code in _TRANSIENT_CODES:
        return ErrorClass.TRANSIENT
    if code in _THROTTLING_CODES:
        return ErrorClass.THROTTLING
    if code in _EXPIRED_CODES:
        return ErrorClass.EXPIRED
    if code in _REGION_CODES:
        return ErrorClass.REGION
    if code in _NOT_FOUND_CODES:
        return ErrorClass.NOT_FOUND
    return ErrorClass.OTHER


def is_access_denied(err: Exception) -> bool:
    return classify(err) == ErrorClass.ACCESS_DENIED


# ─── Session factory ────────────────────────────────────────────────────────


_BOTO_CONFIG = Config(
    retries={"max_attempts": 3, "mode": "adaptive"},
    connect_timeout=10,
    read_timeout=30,
    user_agent_extra="awspwn/0.1",
)


class AwsClient:
    """Wraps a boto3 Session plus the identity it resolves to.

    One AwsClient == one identity. Assuming a role or minting keys produces a
    NEW AwsClient (see `assume_role`), which is how credential propagation walks
    the attack path - the analogue of ADPwn rewriting ATTACKER_NAME/PASS.
    """

    def __init__(self, identity: AwsIdentity):
        self.identity = identity
        self._session = self._build_session(identity)
        self._client_cache: dict[tuple[str, str], object] = {}

    @staticmethod
    def _build_session(identity: AwsIdentity) -> boto3.Session:
        if identity.has_keys:
            return boto3.Session(
                aws_access_key_id=identity.access_key,
                aws_secret_access_key=identity.secret_key,
                aws_session_token=identity.session_token or None,
                region_name=identity.region or "us-east-1",
            )
        if identity.profile:
            return boto3.Session(
                profile_name=identity.profile,
                region_name=identity.region or None,
            )
        # Fall back to the ambient credential chain (env vars, instance role).
        return boto3.Session(region_name=identity.region or None)

    # ─── Client access ─────────────────────────────────────────────────────

    def client(self, service: str, region: Optional[str] = None):
        if service in GLOBAL_SERVICES:
            region = "us-east-1"
        region = region or self.identity.region or "us-east-1"
        key = (service, region)
        if key not in self._client_cache:
            self._client_cache[key] = self._session.client(
                service, region_name=region, config=_BOTO_CONFIG
            )
        return self._client_cache[key]

    # ─── Identity resolution ───────────────────────────────────────────────

    def whoami(self) -> AwsIdentity:
        """Resolve the current caller via sts:GetCallerIdentity and cache it."""
        sts = self.client("sts")
        resp = sts.get_caller_identity()
        self.identity.arn = resp.get("Arn", self.identity.arn)
        self.identity.account = resp.get("Account", self.identity.account)
        self.identity.user_id = resp.get("UserId", self.identity.user_id)
        return self.identity

    def assume_role(
        self,
        role_arn: str,
        session_name: str = "awspwn",
        external_id: str = "",
        duration: int = 3600,
    ) -> "AwsClient":
        """Assume a role and return a NEW AwsClient bound to the session creds.

        Boto3-native (no regex): the returned structured triple becomes the next
        hop's identity. This is the core of credential propagation.
        """
        sts = self.client("sts")
        kwargs = {
            "RoleArn": role_arn,
            "RoleSessionName": session_name,
            "DurationSeconds": duration,
        }
        if external_id:
            kwargs["ExternalId"] = external_id
        resp = sts.assume_role(**kwargs)
        creds = resp["Credentials"]
        new_identity = AwsIdentity(
            access_key=creds["AccessKeyId"],
            secret_key=creds["SecretAccessKey"],
            session_token=creds["SessionToken"],
            arn=resp.get("AssumedRoleUser", {}).get("Arn", role_arn),
            account=role_arn.split(":")[4] if ":" in role_arn else self.identity.account,
            region=self.identity.region,
            expiration=str(creds.get("Expiration", "")),
            source="assume-role",
        )
        return AwsClient(new_identity)

    # ─── Region discovery ──────────────────────────────────────────────────

    def active_regions(self) -> list[str]:
        """Regions enabled for this account, falling back to a default sweep."""
        try:
            ec2 = self.client("ec2", region="us-east-1")
            resp = ec2.describe_regions(AllRegions=False)
            regions = [r["RegionName"] for r in resp.get("Regions", [])]
            return regions or DEFAULT_REGIONS
        except Exception:
            return DEFAULT_REGIONS


# ─── Retry helpers ──────────────────────────────────────────────────────────


@dataclass
class RetryPolicy:
    max_wait: float = 60.0
    base: float = 2.0
    factor: float = 2.0
    max_attempts: int = 8


def retry_until_consistent(
    fn: Callable,
    *,
    treat_access_denied_as_transient: bool = False,
    policy: Optional[RetryPolicy] = None,
    on_retry: Optional[Callable[[int, float, Exception], None]] = None,
):
    """Call `fn` with exponential backoff across AWS transient failures.

    The IAM eventual-consistency case (the clock-skew analogue): right after a
    grant that SHOULD enable a call, AWS may still answer AccessDenied /
    InvalidClientTokenId / SignatureDoesNotMatch for a few seconds. Set
    treat_access_denied_as_transient only in that narrow window - never for a
    cold call, where AccessDenied is the real answer.

    Throttling and transient errors are always retried. AccessDenied (when not
    flagged transient), Expired, and NotFound raise immediately.
    """
    policy = policy or RetryPolicy()
    waited = 0.0
    delay = policy.base
    last_exc: Optional[Exception] = None

    for attempt in range(1, policy.max_attempts + 1):
        try:
            return fn()
        except Exception as exc:  # noqa: BLE001 - classify decides what to do
            last_exc = exc
            cls = classify(exc)
            retryable = cls in (ErrorClass.TRANSIENT, ErrorClass.THROTTLING)
            if cls == ErrorClass.ACCESS_DENIED and treat_access_denied_as_transient:
                retryable = True
            if not retryable or waited >= policy.max_wait:
                raise
            if on_retry:
                on_retry(attempt, delay, exc)
            time.sleep(delay)
            waited += delay
            delay = min(delay * policy.factor, policy.max_wait - waited if policy.max_wait > waited else delay)

    if last_exc:
        raise last_exc
    return None


# ─── Bootstrap ──────────────────────────────────────────────────────────────


def build_identity_from_args(args) -> AwsIdentity:
    """Construct the starting identity from CLI flags / environment.

    Precedence: explicit --access-key/--secret-key > --profile > ambient chain.
    """
    import os

    region = (
        getattr(args, "region", None)
        or os.environ.get("AWS_REGION")
        or os.environ.get("AWS_DEFAULT_REGION")
        or "us-east-1"
    )
    access_key = getattr(args, "access_key", None) or ""
    secret_key = getattr(args, "secret_key", None) or ""
    session_token = getattr(args, "session_token", None) or ""
    profile = getattr(args, "profile", None) or os.environ.get("AWS_PROFILE", "")

    if access_key and secret_key:
        return AwsIdentity(
            access_key=access_key,
            secret_key=secret_key,
            session_token=session_token,
            region=region,
            source="cli-keys",
        )
    if profile:
        return AwsIdentity(profile=profile, region=region, source="profile")
    # Ambient: env vars already exported, or an instance/task role.
    return AwsIdentity(
        access_key=os.environ.get("AWS_ACCESS_KEY_ID", ""),
        secret_key=os.environ.get("AWS_SECRET_ACCESS_KEY", ""),
        session_token=os.environ.get("AWS_SESSION_TOKEN", ""),
        region=region,
        source="env",
    )


def connect(args) -> AwsClient:
    """Build an AwsClient from CLI args and resolve its identity.

    Raises a clear error if no usable credentials are present.
    """
    identity = build_identity_from_args(args)
    client = AwsClient(identity)
    try:
        client.whoami()
    except NoCredentialsError as exc:
        raise RuntimeError(
            "No AWS credentials found. Pass --profile, --access-key/--secret-key, "
            "or export AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY."
        ) from exc
    return client
