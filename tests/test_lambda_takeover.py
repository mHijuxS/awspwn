"""Lambda takeover: executable credential-gain pivot (Step 6, sub-step 2).

Reconcile-level tests (pure) cover minting/suppression/role-change reconciliation.
Strategy-level tests drive _strat_lambda_takeover with fakes - moto cannot execute
Lambda code, so real capture is stubbed - to prove backup-before-mutation, restore,
ledger reversal, live-on-failed-restore, and identity-mismatch rejection.
"""

import base64
import json

from awspwn import strategy
from awspwn.enum.correlate import reconcile_resource_edges
from awspwn.enum.iam import Grants
from awspwn.graph import AttackGraph
from awspwn.models import AwsIdentity, BlastRadius, Edge, Node, NodeKind
from awspwn.state import State, load_state
from awspwn.strategy import Gates, PwnEngine, _strat_lambda_takeover

ACCT = "111111111111"
FN_ARN = f"arn:aws:lambda:us-east-1:{ACCT}:function:app"
ROLE = f"arn:aws:iam::{ACCT}:role/app-exec"
ROLE2 = f"arn:aws:iam::{ACCT}:role/other-exec"
PRIN = f"arn:aws:iam::{ACCT}:user/dev"
TAKE_ACTIONS = ["lambda:GetFunction", "lambda:UpdateFunctionCode", "lambda:InvokeFunction"]


def _principal(actions, resource):
    g = Grants()
    g.add_document({"Statement": [{"Effect": "Allow", "Action": actions, "Resource": resource}]})
    return Node(PRIN, "dev", NodeKind.IAM_USER,
                properties={"grant_read_status": "complete", "grant_statements": g.to_statements()})


def _function(role_arn=ROLE, runtime="python3.12", package="Zip"):
    return Node(FN_ARN, "app", NodeKind.LAMBDA_FUNCTION, region="us-east-1",
                properties={"role_arn": role_arn, "runtime": runtime, "handler": "index.handler",
                            "package_type": package})


def _key(edges, kind="LambdaTakeover"):
    return {(e.source_id, e.target_id, e.kind): e for e in edges if e.kind == kind}


# ─── reconcile: minting / suppression / role-change ──────────────────────────


def test_takeover_edge_minted_to_execution_role_with_metadata():
    nodes = [_principal(TAKE_ACTIONS, FN_ARN), _function(), Node(ROLE, "app-exec", NodeKind.IAM_ROLE)]
    up, _rm = reconcile_resource_edges(nodes, [])
    e = _key(up)[(PRIN, ROLE, "LambdaTakeover")]
    assert e.properties["function_arn"] == FN_ARN
    assert e.properties["role_arn"] == ROLE
    assert e.properties["runtime"] == "python3.12"
    assert e.properties["handler"] == "index.handler"


def test_missing_get_function_permission_no_edge():
    # Without GetFunction the package cannot be backed up -> no executable edge.
    nodes = [_principal(["lambda:UpdateFunctionCode", "lambda:InvokeFunction"], FN_ARN), _function(),
             Node(ROLE, "app-exec", NodeKind.IAM_ROLE)]
    up, _rm = reconcile_resource_edges(nodes, [])
    assert _key(up) == {}


def test_container_and_non_python_suppressed():
    for func in (_function(package="Image"), _function(runtime="go1.x"), _function(runtime="nodejs20.x")):
        nodes = [_principal(TAKE_ACTIONS, FN_ARN), func, Node(ROLE, "app-exec", NodeKind.IAM_ROLE)]
        up, _rm = reconcile_resource_edges(nodes, [])
        assert _key(up) == {}, f"should not mint for {func.properties}"


def test_role_change_retracts_old_takeover():
    principal = _principal(TAKE_ACTIONS, FN_ARN)
    # A prior takeover edge to ROLE exists; the function's role is now ROLE2.
    prior = Edge(PRIN, ROLE, "LambdaTakeover", {"via": "correlation", "function_arn": FN_ARN})
    nodes = [principal, _function(role_arn=ROLE2),
             Node(ROLE, "app-exec", NodeKind.IAM_ROLE), Node(ROLE2, "other-exec", NodeKind.IAM_ROLE)]
    up, rm = reconcile_resource_edges(nodes, [prior])
    assert (PRIN, ROLE, "LambdaTakeover") in rm                    # stale role retracted
    assert (PRIN, ROLE2, "LambdaTakeover") in _key(up)            # current role minted


# ─── strategy: backup / capture / restore / verify ───────────────────────────


class _FakeLambda:
    def __init__(self, handler="index.handler", runtime="python3.12", payload=None,
                 update_fail=False, restore_fail=False, restore_wait_fail=False,
                 backup=b"PK-original-package"):
        self.handler, self.runtime, self.payload = handler, runtime, payload
        self.update_fail, self.restore_fail, self.restore_wait_fail = (
            update_fail, restore_fail, restore_wait_fail)
        self.backup = backup
        self.updates = 0

    def get_function(self, FunctionName):
        url = "data:application/zip;base64," + base64.b64encode(self.backup).decode()
        return {"Configuration": {"Handler": self.handler, "Runtime": self.runtime},
                "Code": {"Location": url}}

    def update_function_code(self, FunctionName, ZipFile):
        self.updates += 1
        if self.updates == 1 and self.update_fail:
            raise RuntimeError("overwrite failed")
        if self.updates == 2 and self.restore_fail:
            raise RuntimeError("restore failed")
        return {}

    def get_waiter(self, _name):
        lam = self

        class _W:
            def wait(self, **kw):
                # A real waiter failure PROPAGATES during destructive execution.
                if lam.restore_wait_fail and lam.updates == 2:
                    raise RuntimeError("waiter: deploy did not stabilize")
                return None
        return _W()

    def invoke(self, FunctionName):
        payload = self.payload or {}

        class _P:
            def read(_self):
                return json.dumps(payload).encode()
        return {"Payload": _P(), "FunctionError": None if payload else "Unhandled"}


class _FakeClient:
    def __init__(self, lam):
        self._lam = lam
        self.identity = AwsIdentity(arn=PRIN, account=ACCT, region="us-east-1")

    def client(self, service, region=None):
        return self._lam


class _FakeSts:
    def __init__(self, arn):
        self._arn = arn

    def get_caller_identity(self):
        return {"Arn": self._arn}


def _engine(tmp_path):
    return PwnEngine(State(), AttackGraph({}, []),
                     Gates(execute=True, allow_destructive=True), loot_dir=str(tmp_path))


def _run(engine, lam, monkeypatch, sts_arn):
    """Drive the strategy, stubbing the verification client's STS identity."""
    monkeypatch.setattr(strategy, "AwsClient",
                        lambda ident: _StubNew(ident, _FakeSts(sts_arn)))
    edge = Edge(PRIN, ROLE, "LambdaTakeover", {
        "function_arn": FN_ARN, "function_name": "app", "region": "us-east-1",
        "runtime": "python3.12", "handler": "index.handler", "package_type": "Zip", "role_arn": ROLE})
    dst = Node(ROLE, "app-exec", NodeKind.IAM_ROLE)
    return _strat_lambda_takeover(engine, _FakeClient(lam), edge, Node(PRIN, "dev", NodeKind.IAM_USER),
                                  dst, {"REGION": "us-east-1"})


class _StubNew:
    def __init__(self, ident, sts):
        self.identity = ident
        self._sts = sts

    def client(self, service, region=None):
        return self._sts


_CREDS = {"AWS_ACCESS_KEY_ID": "ASIAX", "AWS_SECRET_ACCESS_KEY": "s", "AWS_SESSION_TOKEN": "t"}
_MATCHING_STS = f"arn:aws:sts::{ACCT}:assumed-role/app-exec/lambda-session"


def test_backup_failure_records_no_mutation(tmp_path, monkeypatch):
    engine = _engine(tmp_path)
    lam = _FakeLambda(payload=_CREDS)
    # Break the package download so the backup fails BEFORE any mutation.
    monkeypatch.setattr(lam, "get_function", lambda FunctionName: {
        "Configuration": {"Handler": "index.handler", "Runtime": "python3.12"},
        "Code": {"Location": "http://127.0.0.1:0/nope"}})
    res = _run(engine, lam, monkeypatch, _MATCHING_STS)
    assert res.ok is False
    assert engine.mutation_count == 0
    assert engine.state.mutations == []           # nothing recorded, nothing overwritten
    assert lam.updates == 0


def test_successful_capture_and_restore(tmp_path, monkeypatch):
    engine = _engine(tmp_path)
    lam = _FakeLambda(payload=_CREDS)
    res = _run(engine, lam, monkeypatch, _MATCHING_STS)
    assert res.ok is True
    # The live client keeps its ACTUAL STS session ARN (graph-ID/live-identity
    # separation); roam uses the edge target as the post-pivot graph id.
    assert res.new_client.identity.arn == _MATCHING_STS
    assert lam.updates == 2                         # overwrite + restore
    assert engine.mutation_count == 0               # ledger entry reverted after restore
    assert engine.state.mutations[0].reverted is True


def test_failed_restore_leaves_live_ledger_entry(tmp_path, monkeypatch):
    engine = _engine(tmp_path)
    lam = _FakeLambda(payload=_CREDS, restore_fail=True)
    res = _run(engine, lam, monkeypatch, _MATCHING_STS)
    # Capture still succeeds, but the restore failed -> the entry stays LIVE so
    # `awspwn rollback` can reload the package from the backup file on disk.
    assert res.ok is True
    m = engine.state.mutations[0]
    assert m.reverted is False
    assert engine.mutation_count == 1
    assert m.undo_params.get("_backup_path")        # durable rollback reference


def test_captured_identity_mismatch_rejected(tmp_path, monkeypatch):
    engine = _engine(tmp_path)
    lam = _FakeLambda(payload=_CREDS)
    wrong = f"arn:aws:sts::{ACCT}:assumed-role/some-other-role/sess"
    res = _run(engine, lam, monkeypatch, wrong)
    assert res.ok is False
    assert res.new_client is None
    assert lam.updates == 2                         # still restored the package
    assert engine.state.mutations[0].reverted is True


def test_successful_restore_deletes_backup(tmp_path, monkeypatch):
    import os
    engine = _engine(tmp_path)
    lam = _FakeLambda(payload=_CREDS)
    _run(engine, lam, monkeypatch, _MATCHING_STS)
    backup = engine.state.mutations[0].undo_params["_backup_path"]
    assert not os.path.exists(backup)   # reverted entry no longer needs it


def test_restore_waiter_failure_leaves_live_entry(tmp_path, monkeypatch):
    import os
    engine = _engine(tmp_path)
    lam = _FakeLambda(payload=_CREDS, restore_wait_fail=True)
    res = _run(engine, lam, monkeypatch, _MATCHING_STS)
    # The restore deploy did not stabilize -> NOT marked reverted; backup kept.
    assert res.ok is True
    assert engine.state.mutations[0].reverted is False
    assert engine.mutation_count == 1
    assert os.path.exists(engine.state.mutations[0].undo_params["_backup_path"])


def test_unreproducible_handler_suppressed_before_mutation(tmp_path, monkeypatch):
    engine = _engine(tmp_path)
    lam = _FakeLambda(payload=_CREDS, handler="index.9invalid")  # non-identifier function
    res = _run(engine, lam, monkeypatch, _MATCHING_STS)
    assert res.ok is False and res.manual is True
    assert engine.state.mutations == []   # refused before any mutation
    assert lam.updates == 0


def test_exfil_zip_supports_nested_module_and_rejects_bad_handlers():
    import io
    import zipfile
    from awspwn.strategy import _exfil_zip_for_handler

    zb = _exfil_zip_for_handler("pkg.mod.entry")
    names = set(zipfile.ZipFile(io.BytesIO(zb)).namelist())
    assert "pkg/mod.py" in names            # dots are package separators, not the filename
    assert "pkg/__init__.py" in names       # package dir made importable
    assert _exfil_zip_for_handler("index.9bad") is None      # invalid function name
    assert _exfil_zip_for_handler("bad-mod.handler") is None  # invalid module component


def test_load_state_roundtrips_takeover_ledger(tmp_path, monkeypatch):
    # The live ledger entry persists so rollback can restore later.
    engine = _engine(tmp_path)
    lam = _FakeLambda(payload=_CREDS, restore_fail=True)
    _run(engine, lam, monkeypatch, _MATCHING_STS)
    reloaded = load_state(str(tmp_path))
    assert reloaded.mutations[0].undo_api == "lambda:UpdateFunctionCode"
    assert reloaded.mutations[0].blast_radius == BlastRadius.DESTRUCTIVE.value
