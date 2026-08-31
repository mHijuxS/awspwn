"""Console sign-in - turn CLI credentials into an AWS Management Console URL.

Phase-3 helper behind `awspwn console`. The federation endpoint lets you trade a
set of AWS credentials for a browser sign-in link, which is invaluable once an
attack chain lands you on a role/user whose privileges are easier to exercise in
the UI (or that you simply want to eyeball).

Two credential shapes are handled:

  * **Temporary credentials** (an assumed role, a federation token - anything
    carrying a session token): fed straight to `getSigninToken`.
  * **Long-term IAM-user keys** (no session token): the federation endpoint will
    not accept these directly, so we first call `sts:GetFederationToken` to mint
    a short-lived session bounded by the user's own permissions, then federate
    with that.

Uses only stdlib `urllib`/`json` for the HTTP dance - no new dependency. boto3 is
touched solely for the optional GetFederationToken step.
"""

from __future__ import annotations

import json
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Optional

from .models import AwsIdentity

FEDERATION_ENDPOINT = "https://signin.aws.amazon.com/federation"
DEFAULT_DESTINATION = "https://console.aws.amazon.com/"
DEFAULT_ISSUER = "https://github.com/awspwn"


@dataclass
class ConsoleResult:
    url: str
    source: str          # "session-creds" or "federation-token"
    federated_arn: str = ""
    note: str = ""


class ConsoleError(RuntimeError):
    """Raised when a sign-in URL cannot be produced."""


def _get_signin_token(session: dict, duration: Optional[int], timeout: int = 20) -> str:
    """Exchange a credential session for a SigninToken via the federation API."""
    params = {
        "Action": "getSigninToken",
        "Session": json.dumps(session),
    }
    # SessionDuration is only valid when federating long-term creds (it is
    # rejected alongside a session token), so callers pass None for role creds.
    if duration:
        params["SessionDuration"] = str(duration)
    url = f"{FEDERATION_ENDPOINT}?{urllib.parse.urlencode(params)}"
    req = urllib.request.Request(url, headers={"User-Agent": "awspwn/console"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 (fixed AWS host)
            body = resp.read().decode()
    except Exception as exc:  # noqa: BLE001
        raise ConsoleError(f"federation getSigninToken failed: {exc}") from exc
    try:
        token = json.loads(body)["SigninToken"]
    except (ValueError, KeyError) as exc:
        raise ConsoleError(f"malformed federation response: {body[:200]}") from exc
    return token


def _login_url(signin_token: str, issuer: str, destination: str) -> str:
    params = {
        "Action": "login",
        "Issuer": issuer,
        "Destination": destination,
        "SigninToken": signin_token,
    }
    return f"{FEDERATION_ENDPOINT}?{urllib.parse.urlencode(params)}"


def signin_url_from_identity(
    identity: AwsIdentity,
    *,
    destination: str = DEFAULT_DESTINATION,
    issuer: str = DEFAULT_ISSUER,
    duration: int = 3600,
) -> ConsoleResult:
    """Build a console sign-in URL directly from a credential set.

    Requires temporary credentials (a session token). For long-term IAM-user
    keys, use `signin_url` with a live AwsClient so GetFederationToken can run.
    """
    if not identity.has_keys:
        raise ConsoleError("no access key / secret key available to federate")
    if not identity.session_token:
        raise ConsoleError(
            "long-term IAM-user credentials cannot be federated directly - "
            "call signin_url() with a client so sts:GetFederationToken can run"
        )
    session = {
        "sessionId": identity.access_key,
        "sessionKey": identity.secret_key,
        "sessionToken": identity.session_token,
    }
    token = _get_signin_token(session, duration=None)
    return ConsoleResult(
        url=_login_url(token, issuer, destination),
        source="session-creds",
        federated_arn=identity.arn,
    )


# A permissive policy so the federated session keeps the user's full effective
# permissions (the session is still bounded by the *intersection* with the
# user's own policy, so this cannot exceed what they already have).
_FED_POLICY = json.dumps(
    {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
)


def signin_url(
    client,
    *,
    destination: str = DEFAULT_DESTINATION,
    issuer: str = DEFAULT_ISSUER,
    session_name: str = "awspwn",
    duration: int = 3600,
) -> ConsoleResult:
    """Build a console sign-in URL for `client`'s identity, minting a federation
    token first when the identity holds only long-term keys."""
    identity = client.identity

    # Temporary creds (assumed role, existing federation/session token): direct.
    if identity.session_token:
        return signin_url_from_identity(
            identity, destination=destination, issuer=issuer, duration=duration
        )

    # Long-term IAM-user keys: GetFederationToken -> temp creds -> federate.
    sts = client.client("sts")
    try:
        resp = sts.get_federation_token(
            Name=session_name[:32] or "awspwn", Policy=_FED_POLICY, DurationSeconds=duration
        )
    except Exception as exc:  # noqa: BLE001
        raise ConsoleError(
            "sts:GetFederationToken failed (needed for long-term IAM-user creds); "
            f"underlying error: {exc}"
        ) from exc
    creds = resp["Credentials"]
    session = {
        "sessionId": creds["AccessKeyId"],
        "sessionKey": creds["SecretAccessKey"],
        "sessionToken": creds["SessionToken"],
    }
    token = _get_signin_token(session, duration=None)
    fed_arn = resp.get("FederatedUser", {}).get("Arn", identity.arn)
    return ConsoleResult(
        url=_login_url(token, issuer, destination),
        source="federation-token",
        federated_arn=fed_arn,
        note="minted via sts:GetFederationToken; session bounded by the user's own policy",
    )
