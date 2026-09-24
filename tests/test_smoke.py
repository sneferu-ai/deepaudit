from __future__ import annotations
import json
import subprocess
import sys
import tempfile
from pathlib import Path


def test_imports():
    from deepaudit.languages.python.frontend import PythonLanguageFrontend
    from deepaudit.core.repo_map import build_repo_model
    from deepaudit.core.pipeline import run_deepaudit_scan
    from deepaudit.sdk.mock import MockConvergenceClient
    from deepaudit.sandbox.runner import LocalRunner

    assert PythonLanguageFrontend
    assert build_repo_model
    assert run_deepaudit_scan
    assert MockConvergenceClient
    assert LocalRunner


def test_empty_repo():
    from deepaudit.core.pipeline import run_deepaudit_scan
    from deepaudit.sandbox.runner import LocalRunner

    with tempfile.TemporaryDirectory() as tmp:
        runner = LocalRunner(Path(tmp))
        result = run_deepaudit_scan(Path(tmp), runner=runner)
        assert result.exit_code == 0
        assert result.summary.proven == 0


def _fixture(name: str) -> Path:
    return Path(__file__).parent / "fixtures" / name


def test_static_finding_secret():
    from deepaudit.core.static_scan import scan_repository

    with tempfile.TemporaryDirectory() as tmp:
        repo = Path(tmp)
        (repo / "config.py").write_text('api_key = "sk-test-1234567890abcdef1234567890abcdef"\n', encoding="utf-8")
        findings = scan_repository(repo)
        assert len(findings) >= 1
        assert any(f.exploit_class == "secrets_in_code" for f in findings)


def test_fixture_sql_injection():
    from deepaudit.core.pipeline import run_deepaudit_scan
    from deepaudit.sandbox.runner import LocalRunner

    fixture = _fixture("sql_injection")
    runner = LocalRunner(fixture)
    result = run_deepaudit_scan(fixture, runner=runner)
    assert result.summary.proven == 1
    assert result.bundle.findings[0].exploit_class == "sql_injection"


def test_fixture_command_injection():
    from deepaudit.core.pipeline import run_deepaudit_scan
    from deepaudit.sandbox.runner import LocalRunner

    fixture = _fixture("command_injection")
    runner = LocalRunner(fixture)
    result = run_deepaudit_scan(fixture, runner=runner)
    assert result.summary.proven == 1
    assert result.bundle.findings[0].exploit_class == "command_injection"


def test_fixture_code_injection():
    from deepaudit.core.pipeline import run_deepaudit_scan
    from deepaudit.sandbox.runner import LocalRunner

    fixture = _fixture("code_injection")
    runner = LocalRunner(fixture)
    result = run_deepaudit_scan(fixture, runner=runner)
    assert result.summary.proven == 1
    assert result.bundle.findings[0].exploit_class == "code_injection"
    assert result.bundle.findings[0].reproduction.template_name == "code_injection_exec"


def test_fixture_unsafe_deserialization():
    from deepaudit.core.pipeline import run_deepaudit_scan
    from deepaudit.sandbox.runner import LocalRunner

    fixture = _fixture("unsafe_deserialization")
    runner = LocalRunner(fixture)
    result = run_deepaudit_scan(fixture, runner=runner)
    assert result.summary.proven == 1
    assert result.bundle.findings[0].exploit_class == "unsafe_deserialization"


def test_fixture_path_traversal():
    from deepaudit.core.pipeline import run_deepaudit_scan
    from deepaudit.sandbox.runner import LocalRunner

    fixture = _fixture("path_traversal")
    runner = LocalRunner(fixture)
    result = run_deepaudit_scan(fixture, runner=runner)
    assert result.summary.proven == 1
    assert result.bundle.findings[0].exploit_class == "path_traversal"


def test_fixture_auth_bypass():
    from deepaudit.core.pipeline import run_deepaudit_scan
    from deepaudit.sandbox.runner import LocalRunner

    fixture = _fixture("auth_bypass")
    runner = LocalRunner(fixture)
    result = run_deepaudit_scan(fixture, runner=runner)
    assert result.summary.proven == 1
    finding = result.bundle.findings[0]
    assert finding.exploit_class == "auth_bypass"
    assert finding.reproduction.template_name == "auth_bypass_direct"
    assert finding.reproduction.verdict == "proven"
    assert finding.reproduction.exploit_run.sentinel_observed is True
    assert finding.reproduction.control_run.sentinel_observed is False


def test_fixture_template_injection():
    from deepaudit.core.pipeline import run_deepaudit_scan
    from deepaudit.sandbox.runner import LocalRunner

    fixture = _fixture("template_injection")
    runner = LocalRunner(fixture)
    result = run_deepaudit_scan(fixture, runner=runner)
    assert result.summary.proven == 1
    finding = result.bundle.findings[0]
    assert finding.exploit_class == "template_injection"
    assert finding.reproduction.template_name == "template_injection_jinja2"
    assert finding.reproduction.verdict == "proven"
    assert finding.reproduction.exploit_run.sentinel_observed is True
    assert finding.reproduction.control_run.sentinel_observed is False


def test_rejecting_mock_convergence():
    from deepaudit.core.pipeline import run_deepaudit_scan
    from deepaudit.sandbox.runner import LocalRunner
    from deepaudit.sdk.mock import RejectingMockConvergenceClient

    fixture = _fixture("sql_injection")
    runner = LocalRunner(fixture)
    client = RejectingMockConvergenceClient()
    result = run_deepaudit_scan(fixture, runner=runner, convergence_client=client)
    assert result.summary.proven == 0
    assert result.summary.unverified >= 1


def test_bundle_signing_and_verification():
    from deepaudit.core.pipeline import run_deepaudit_scan
    from deepaudit.core.findings import verify_bundle, bundle_to_json
    from deepaudit.sandbox.runner import LocalRunner

    fixture = _fixture("sql_injection")
    runner = LocalRunner(fixture)
    result = run_deepaudit_scan(fixture, runner=runner)
    assert result.bundle_path is not None
    # Verify the on-disk JSON bundle.
    assert verify_bundle(result.bundle_path) is True
    # Sanity-check that the bundle serializes to proper JSON structs.
    payload = bundle_to_json(result.bundle)
    assert isinstance(payload, dict)
    assert isinstance(payload["findings"], list)
    assert isinstance(payload["findings"][0], dict)
    assert payload["findings"][0]["exploit_class"] == "sql_injection"
    assert isinstance(payload["signature"], dict)


def test_resign_bundle():
    from deepaudit.core.pipeline import run_deepaudit_scan
    from deepaudit.core.findings import verify_bundle, resign_bundle, bundle_to_json
    from deepaudit.sandbox.runner import LocalRunner

    fixture = _fixture("sql_injection")
    runner = LocalRunner(fixture)
    result = run_deepaudit_scan(fixture, runner=runner)
    assert result.bundle_path is not None

    # Verify original signature
    assert verify_bundle(result.bundle_path) is True

    # Modify the bundle (e.g., remove unverified findings)
    original_payload = bundle_to_json(result.bundle)
    result.bundle.unverified = []
    result.bundle.static_findings = []

    # Re-sign and verify again
    resign_bundle(result.bundle)
    assert verify_bundle(result.bundle) is True

    # Re-serialized bundle should still have valid signature
    new_payload = bundle_to_json(result.bundle)
    assert new_payload["signature"] != original_payload["signature"]
    assert new_payload["unverified"] == []
    assert new_payload["static_findings"] == []


def test_verify_rerun():
    from deepaudit.core.pipeline import run_deepaudit_scan
    from deepaudit.core.findings import verify_bundle
    from deepaudit.sandbox.runner import LocalRunner

    fixture = _fixture("sql_injection")
    runner = LocalRunner(fixture)
    result = run_deepaudit_scan(fixture, runner=runner)
    assert result.bundle_path is not None
    assert verify_bundle(result.bundle_path) is True

    # Verify with re-run should also succeed
    assert verify_bundle(result.bundle) is True


def test_acceptance_fixture():
    from deepaudit.core.pipeline import run_deepaudit_scan
    from deepaudit.sandbox.runner import LocalRunner
    from deepaudit.core.findings import verify_bundle

    fixture = _fixture("acceptance_repo")
    # Initialize the SQLite database for the fixture
    setup_db = fixture / "setup_db.py"
    if setup_db.exists():
        subprocess.run([sys.executable, str(setup_db)], cwd=fixture, check=True)

    runner = LocalRunner(fixture)
    result = run_deepaudit_scan(fixture, runner=runner, mock_sdk=True)

    assert len(result.bundle.findings) == 1
    finding = result.bundle.findings[0]
    assert finding.exploit_class == "sql_injection"

    files_in_path = {pp.file for pp in finding.cross_file_path}
    assert "app.py" in files_in_path
    assert "db.py" in files_in_path
    assert len(files_in_path) >= 2

    assert finding.source.file == "app.py"
    assert "request.args" in finding.source.expression

    assert finding.sink.file == "db.py"
    assert "search_raw" in finding.sink.function

    for f in result.bundle.findings:
        assert "search_safe" not in f.sink.function

    assert finding.reproduction.kind == "differential"
    assert finding.reproduction.verdict == "proven"
    assert finding.reproduction.exploit_run.sentinel_observed is True
    assert finding.reproduction.control_run.sentinel_observed is False

    assert verify_bundle(result.bundle_path) is True

    assert len(finding.convergence.lineages_judged) >= 2
    assert finding.convergence.agreed is True

    assert finding.reproduction.template_name == "sql_injection_read"
    assert finding.reproduction.adapter_name == "FunctionParamRequestAdapter"

    assert len(result.bundle.static_findings) == 0
    assert result.exit_code == 0


def test_config_compat_patch_reaches_default_runner():
    from deepaudit.core import pipeline
    from deepaudit.core.pipeline import run_deepaudit_scan
    from deepaudit.config.defaults import DeepAuditConfig

    class CapturingRunner:
        last = None

        def __init__(self, repo_path, compat_patch=None):
            self.repo_path = repo_path
            self.compat_patch = compat_patch
            CapturingRunner.last = self

        def run_harness(self, *args, **kwargs):
            from deepaudit.models.finding import SandboxRunResult

            return SandboxRunResult(
                run_kind="exploit",
                status="ok",
                exit_code=0,
                stdout="",
                stderr="",
                sentinel_observed=False,
                duration_ms=0,
                files_written=[],
                image_digest="",
            )

    original = pipeline.LocalRunner
    pipeline.LocalRunner = CapturingRunner
    try:
        with tempfile.TemporaryDirectory() as tmp:
            repo = Path(tmp)
            (repo / "app.py").write_text("x = 1\n", encoding="utf-8")
            config = DeepAuditConfig(compat_patch=Path(__file__), max_candidates=0)
            run_deepaudit_scan(repo, config=config)
            assert CapturingRunner.last is not None
            assert CapturingRunner.last.compat_patch is not None
            assert "from __future__ import annotations" in CapturingRunner.last.compat_patch
    finally:
        pipeline.LocalRunner = original


def test_config_convergence_lineages_propagate():
    from deepaudit.core.pipeline import run_deepaudit_scan
    from deepaudit.sandbox.runner import LocalRunner
    from deepaudit.config.defaults import DeepAuditConfig

    fixture = _fixture("sql_injection")
    config = DeepAuditConfig(convergence_lineages=["fw", "kimi"])
    result = run_deepaudit_scan(fixture, config=config, runner=LocalRunner(fixture))
    assert result.exit_code == 0
    assert result.summary.proven == 1
    assert result.bundle.findings[0].convergence.lineages_judged == ("fw", "kimi")


def test_sentinel_hash_is_full_sha256():
    from deepaudit.sandbox.sentinel import make_sentinel, hash_sentinel
    import hashlib

    sentinel = make_sentinel()
    expected = hashlib.sha256(sentinel.encode()).hexdigest()
    assert hash_sentinel(sentinel) == expected
    assert len(hash_sentinel(sentinel)) == 64


def test_scan_timeout_alias_defaults_to_none():
    from deepaudit.cli.main import _parse_args

    args = _parse_args(["scan", "tests/fixtures/sql_injection"])
    assert args.scan_timeout is None
    assert args.sandbox_timeout == 60


def test_sandbox_timeout_still_configurable():
    from deepaudit.cli.main import _parse_args

    args = _parse_args(["scan", "tests/fixtures/sql_injection", "--sandbox-timeout", "120"])
    assert args.scan_timeout is None
    assert args.sandbox_timeout == 120


def test_jobs_flag_accepted():
    from deepaudit.cli.main import _parse_args

    args = _parse_args(["scan", "tests/fixtures/sql_injection", "--jobs", "4"])
    assert args.jobs == 4


def _tmp_out(name: str) -> str:
    """Unique per-call temp output path. A FIXED shared /tmp name collides under
    sticky-bit /tmp across uids / parallel runs (the CLI renames the bundle onto
    --output; a leftover target owned by another uid makes os.rename EPERM)."""
    return str(Path(tempfile.mkdtemp(prefix="deepaudit-test-")) / name)


def test_text_verbose_format_output(capsys):
    from deepaudit.cli.main import _parse_args, _scan_command

    args = _parse_args(["scan", "tests/fixtures/sql_injection", "--authorized", "--mock-sdk", "--format", "text-verbose", "--output", _tmp_out("verbose.json")])
    code = _scan_command(args)
    assert code == 0
    captured = capsys.readouterr()
    assert "Findings:" in captured.out
    assert "sql_injection" in captured.out


def test_sarif_format_output(capsys):
    import json
    from deepaudit.cli.main import _parse_args, _scan_command

    args = _parse_args(["scan", "tests/fixtures/sql_injection", "--authorized", "--mock-sdk", "--format", "sarif", "--output", _tmp_out("sarif.json")])
    code = _scan_command(args)
    assert code == 0
    captured = capsys.readouterr()
    sarif = json.loads(captured.out)
    assert sarif["version"] == "2.1.0"
    assert len(sarif["runs"]) == 1
    assert len(sarif["runs"][0]["results"]) >= 1


def test_verify_cli_rerun():
    import subprocess

    fixture = str(_fixture("sql_injection"))
    bundle_out = _tmp_out("verify-rerun.json")
    # Produce a bundle with the CLI
    scan_cmd = [
        sys.executable, "-m", "deepaudit.cli.main",
        "scan", fixture,
        "--authorized", "--mock-sdk",
        "--output", bundle_out,
    ]
    result = subprocess.run(scan_cmd, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr

    # Verify with re-run
    verify_cmd = [
        sys.executable, "-m", "deepaudit.cli.main",
        "verify", bundle_out,
        "--re-run", fixture,
    ]
    result = subprocess.run(verify_cmd, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert "verify: bundle is valid" in result.stdout


def test_control_unexpected_exit():
    from deepaudit.core.proof_oracle import run_proof
    from deepaudit.models.finding import SandboxRunResult

    class CrashingRunner:
        def run_harness(self, source_code, is_exploit, sentinel, channels=None, timeout=30):
            if not is_exploit:
                return SandboxRunResult(
                    run_kind="control",
                    status="crash",
                    exit_code=1,
                    stdout="",
                    stderr="boom",
                    sentinel_observed=False,
                    duration_ms=0,
                    files_written=[],
                    image_digest="",
                )
            return SandboxRunResult(
                run_kind="exploit",
                status="ok",
                exit_code=0,
                stdout=sentinel,
                stderr="",
                sentinel_observed=True,
                duration_ms=0,
                files_written=[],
                image_digest="",
            )

    from deepaudit.core.proof_oracle import _unverified
    from deepaudit.poc_gen import generate_harnesses
    from deepaudit.sandbox.env_probe import probe_current_environment
    from deepaudit.core.repo_map import build_repo_model
    from deepaudit.languages.python.frontend import PythonLanguageFrontend
    from deepaudit.core.candidate_gen import generate_candidates
    from deepaudit.models.candidate import VulnerabilityCandidate

    fixture = _fixture("sql_injection")
    frontend = PythonLanguageFrontend()
    model = build_repo_model(fixture, frontend)
    candidates = generate_candidates(model)
    assert len(candidates) >= 1
    candidate = candidates[0]

    env = probe_current_environment()
    exploit_code, control_code, template_name, adapter_name, sentinel, channels = generate_harnesses(candidate, env, model)
    assert exploit_code is not None
    assert control_code is not None

    proof = run_proof(candidate, CrashingRunner(), model, env=env, timeout=30)
    assert proof is not None
    assert proof.verdict == "unverified"
    assert proof.unverified_reason == "control_unexpected_exit"


# --------------------------------------------------------------------------
# Finalizer hardening (FIX-741): bundle isolation honesty, env scrub,
# no-silent-docker-downgrade, dynamic sdk_info, compat_patch forward, SARIF.
# --------------------------------------------------------------------------


def test_local_bundle_declares_no_isolation():
    """The signed bundle must NOT claim container isolation that LocalRunner
    never applied. (Regression: sandbox_config hardcoded network='none'.)"""
    from deepaudit.core.pipeline import run_deepaudit_scan
    from deepaudit.sandbox.runner import LocalRunner

    fixture = _fixture("sql_injection")
    result = run_deepaudit_scan(fixture, runner=LocalRunner(fixture))
    sb = result.bundle.sandbox
    assert sb["mode"] == "local"
    assert sb["isolation_applied"] is False
    assert sb["network"] == "host"
    assert sb["network"] != "none"  # the exact lie we removed


def test_localrunner_scrubs_secret_env(monkeypatch):
    """Host secrets must not cross into the harness subprocess by default;
    PATH must remain so shell-based exploits still resolve binaries."""
    import json as _json
    from deepaudit.sandbox.runner import LocalRunner

    monkeypatch.setenv("DEEPAUDIT_SECRET_PROBE", "leaked-token")
    with tempfile.TemporaryDirectory() as tmp:
        runner = LocalRunner(Path(tmp))
        harness = "import os, json\nprint(json.dumps(sorted(os.environ.keys())))\n"
        res = runner.run_harness(harness, is_exploit=True, sentinel="DA-x", channels=["stdout"])
        keys = _json.loads(res.stdout)
        assert "DEEPAUDIT_SECRET_PROBE" not in keys  # scrubbed
        assert "PATH" in keys  # kept for shell exploits


def test_localrunner_env_passthrough_opt_in(monkeypatch):
    """env_passthrough=True restores legacy full-environment behaviour."""
    import json as _json
    from deepaudit.sandbox.runner import LocalRunner

    monkeypatch.setenv("DEEPAUDIT_SECRET_PROBE", "leaked-token")
    with tempfile.TemporaryDirectory() as tmp:
        runner = LocalRunner(Path(tmp), env_passthrough=True)
        harness = "import os, json\nprint(json.dumps(sorted(os.environ.keys())))\n"
        res = runner.run_harness(harness, is_exploit=True, sentinel="DA-x", channels=["stdout"])
        keys = _json.loads(res.stdout)
        assert "DEEPAUDIT_SECRET_PROBE" in keys


def test_docker_mode_not_silently_downgraded(capsys):
    """`--sandbox-mode docker` must build the Docker runner (a v1 stub) and warn,
    never silently fall back to unisolated local execution."""
    from deepaudit.cli.main import _parse_args, _scan_command

    out = _tmp_out("docker-mode.json")
    args = _parse_args([
        "scan", "tests/fixtures/sql_injection",
        "--authorized", "--sandbox-mode", "docker", "--output", out,
    ])
    code = _scan_command(args)
    captured = capsys.readouterr()
    assert "stub" in captured.err.lower()  # operator warned
    data = json.loads(Path(out).read_text())
    assert data["sandbox"]["mode"] == "docker"
    assert data["sandbox"]["isolation_applied"] is False
    assert data["findings"] == []  # stub proves nothing -> honest, not fake-proven
    assert code == 0


def test_sdk_info_reflects_actual_client():
    """sdk_info must report the convergence client that actually ran, not a
    hardcoded string. (Regression: assemble_bundle hardcoded MockConvergenceClient.)"""
    from deepaudit.core.pipeline import _sdk_info, MockClient
    from deepaudit.sdk.mock import MockConvergenceClient, RejectingMockConvergenceClient

    assert _sdk_info(MockConvergenceClient())["convergence_is_mock"] is True
    assert _sdk_info(RejectingMockConvergenceClient())["convergence_is_mock"] is True
    assert _sdk_info(MockClient())["convergence_is_mock"] is True  # shim unwraps

    class FakeRealClient:
        def judge(self, *a, **k):
            raise NotImplementedError

        def trace_last(self, *a, **k):
            raise NotImplementedError

    info = _sdk_info(FakeRealClient())
    assert info["convergence_is_mock"] is False
    assert info["convergence_client"].endswith("FakeRealClient")
    assert "claudopus_available" in info


def test_docker_runner_forwards_compat_patch():
    """The Docker wrapper must forward compat_patch to the impl, not drop it."""
    from deepaudit.sandbox.runner import DockerRunner

    with tempfile.TemporaryDirectory() as tmp:
        runner = DockerRunner(Path(tmp), compat_patch="# COMPAT MARKER")
        assert runner.compat_patch == "# COMPAT MARKER"
        assert runner._impl.compat_patch == "# COMPAT MARKER"
        assert runner.describe()["isolation_applied"] is False


def test_sarif_uribaseid_is_symbolic(capsys):
    """SARIF uriBaseId must be a symbolic id resolved via originalUriBaseIds."""
    from deepaudit.cli.main import _parse_args, _scan_command

    args = _parse_args([
        "scan", "tests/fixtures/sql_injection",
        "--authorized", "--mock-sdk", "--format", "sarif",
        "--output", _tmp_out("sarif-uribase.json"),
    ])
    code = _scan_command(args)
    assert code == 0
    sarif = json.loads(capsys.readouterr().out)
    run = sarif["runs"][0]
    assert "SRCROOT" in run["originalUriBaseIds"]
    loc = run["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]
    assert loc["uriBaseId"] == "SRCROOT"


# ── Real cross-lineage convergence via the claudopus SDK (sdk-judge-v1) ──────

def _sample_candidate() -> dict:
    return {
        "id": "cand-1", "exploit_class": "sql_injection", "cross_file": True,
        "source": {"file": "app.py", "line": 5, "function": "handle_search",
                   "expression": "request.args.get('q')"},
        "sink": {"file": "db.py", "line": 6, "function": "search_raw",
                 "expression": "cursor.execute(...)"},
        "taint_path": [{"file": "app.py", "line": 5}, {"file": "db.py", "line": 6}],
        "sanitizers_on_path": [], "sanitizer_bypassed": False,
    }


def test_convergence_claim_and_context_render_the_candidate():
    from deepaudit.sdk.client import candidate_claim, candidate_context
    cand = _sample_candidate()
    claim = candidate_claim(cand)
    ctx = candidate_context(cand)
    assert "sql_injection" in claim and "cross-file" in claim
    assert "app.py:5" in ctx and "db.py:6" in ctx          # cross-file source+sink
    assert "Sanitizers seen on path: NONE" in ctx


def test_convergence_maps_sdk_judgment_to_result(monkeypatch):
    """RealConvergenceClient maps a JudgmentResult-shaped reply -> ConvergenceResult."""
    from deepaudit.sdk import client as cl

    class _Judgment:
        agreed = True
        lineages_judged = ["moonshot", "minimax"]
        per_lineage = {"moonshot": {"verdict": "affirmed"}, "minimax": {"verdict": "affirmed"}}
        rationale = "2 distinct lineages affirmed"

    class _FakeClient:
        def __init__(self, base):
            self.base = base
        def judge(self, body):
            assert "claim" in body and "context" in body and body["require_agreement"] == "unanimous"
            return _Judgment()

    import types
    monkeypatch.setitem(sys.modules, "claudopus", types.SimpleNamespace(Client=_FakeClient))
    rc = cl.RealConvergenceClient(base_url="http://x")
    res = rc.judge(_sample_candidate(), lineages=["a", "b"], require_agreement="all", on_disagreement="reject")
    assert res.agreed is True
    assert set(res.lineages_judged) == {"moonshot", "minimax"}
    assert res.candidate_id == "cand-1"


def test_convergence_sdk_error_is_not_silent_affirm(monkeypatch):
    from deepaudit.sdk import client as cl
    import types

    class _BoomClient:
        def __init__(self, base): ...
        def judge(self, body):
            raise RuntimeError("orchestrator exploded")

    monkeypatch.setitem(sys.modules, "claudopus", types.SimpleNamespace(Client=_BoomClient))
    rc = cl.RealConvergenceClient(base_url="http://x")
    res = rc.judge(_sample_candidate(), lineages=["a"], require_agreement="all", on_disagreement="reject")
    assert res.agreed is False           # an error is a non-agreement, never affirmed
    assert "error" in res.rationale.lower()


def test_unreachable_orchestrator_falls_back_to_mock_honestly():
    from deepaudit.core.pipeline import _build_convergence_client, MockClient
    from deepaudit.config.defaults import DeepAuditConfig
    c = _build_convergence_client(DeepAuditConfig(claudopus_base_url="http://127.0.0.1:59999"))
    assert isinstance(c, MockClient)     # SDK/orchestrator down -> honest mock, not a crash


# ── Engine-reported mock/degraded judges reach the signed bundle ─────────────

def _fake_claudopus(monkeypatch, *, is_mock, degraded=False, agreed=True):
    import types

    class _Judgment:
        def __init__(self):
            self.agreed = agreed
            self.lineages_judged = ["mock-lineage-0", "mock-lineage-1"]
            self.per_lineage = {"mock-lineage-0": {"verdict": "affirmed"},
                                "mock-lineage-1": {"verdict": "affirmed"}}
            self.rationale = "fake engine"
            self.is_mock = is_mock
            self.degraded = degraded

    class _Client:
        def __init__(self, base): ...
        def judge(self, body):
            return _Judgment()

    import importlib.machinery
    fake = types.ModuleType("claudopus")
    fake.__spec__ = importlib.machinery.ModuleSpec("claudopus", loader=None)
    fake.Client = _Client
    monkeypatch.setitem(sys.modules, "claudopus", fake)


def test_engine_mock_judges_mark_bundle_mock(monkeypatch):
    """A real SDK client talking to a Sneferu engine in mock/codegen mode must
    not produce a bundle that claims real convergence."""
    from deepaudit.core.pipeline import run_deepaudit_scan
    from deepaudit.sandbox.runner import LocalRunner
    from deepaudit.sdk.client import RealConvergenceClient

    _fake_claudopus(monkeypatch, is_mock=True)
    fixture = _fixture("sql_injection")
    result = run_deepaudit_scan(fixture, runner=LocalRunner(fixture),
                                convergence_client=RealConvergenceClient("http://x"))
    sdk = result.bundle.sdk
    assert sdk["convergence_client"].endswith("RealConvergenceClient")
    assert sdk["engine_reported_mock"] is True
    assert sdk["convergence_is_mock"] is True


def test_real_engine_judges_mark_bundle_real(monkeypatch):
    from deepaudit.core.pipeline import run_deepaudit_scan
    from deepaudit.sandbox.runner import LocalRunner
    from deepaudit.sdk.client import RealConvergenceClient

    _fake_claudopus(monkeypatch, is_mock=False)
    fixture = _fixture("sql_injection")
    result = run_deepaudit_scan(fixture, runner=LocalRunner(fixture),
                                convergence_client=RealConvergenceClient("http://x"))
    sdk = result.bundle.sdk
    assert sdk["engine_reported_mock"] is False
    assert sdk["convergence_is_mock"] is False
    assert sdk["engine_reported_degraded"] is False


def test_cli_warning_names_what_actually_ran(monkeypatch, capsys):
    """No stale 'always mock' warning: the CLI reports the convergence the
    bundle recorded."""
    from deepaudit.cli import main as cli
    from deepaudit.sdk.client import RealConvergenceClient

    _fake_claudopus(monkeypatch, is_mock=False)
    monkeypatch.setattr(RealConvergenceClient, "available", staticmethod(lambda base, timeout=2.0: True))
    rc = cli.main(["scan", "tests/fixtures/sql_injection", "--authorized", "--format", "text",
                   "--output", _tmp_out("real-engine.json")])
    err = capsys.readouterr().err
    assert rc == 0
    assert "MOCK" not in err

    _fake_claudopus(monkeypatch, is_mock=True)
    cli.main(["scan", "tests/fixtures/sql_injection", "--authorized", "--format", "text",
              "--output", _tmp_out("mock-engine.json")])
    err = capsys.readouterr().err
    assert "answered with MOCK judges" in err
