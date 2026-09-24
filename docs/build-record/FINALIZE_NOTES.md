# FINALIZE_NOTES — DeepAudit v1 (run 2026-06-25T13-12-07Z-code-07c0ebd5)

Finalizer pass over the converged cooperative build. Working-tree edits only; nothing
committed. Full report: the run's `finalize_report.md`. Precise diff: `finalizer.patch`
in the run directory.

## What changed (and why)

The build was sound, but its **signed bundle claimed isolation it never applied** — for a
"prove-it-in-a-sandbox" security tool that is the most important thing to get right.

1. **Honest sandbox descriptor (critical).** `config.sandbox_config()` hardcoded
   `network: "none"` / `repo_mount: "copy"` into the signed bundle while the default
   `LocalRunner` runs harnesses as bare host subprocesses (full network, real repo as
   cwd). The bundle's `sandbox` block now comes from `runner.describe()` (new) via
   `pipeline._describe_sandbox`. Local honestly reports
   `network: host, isolation_applied: false, repo_mount: in-place`.
   Files: `sandbox/runner.py`, `core/pipeline.py`, `config/defaults.py`.

2. **No silent docker downgrade.** `cli/main.py` parsed `--sandbox-mode` but always built
   `LocalRunner`; `--sandbox-mode docker` silently ran unisolated. It now builds
   `DockerRunner` and warns that v1 Docker is a stub (proofs → UNVERIFIED).

3. **Scrubbed harness env (credential boundary).** `LocalRunner` no longer forwards the
   full host environment into the harness; only an allowlist (`PATH` kept for shell
   exploits) plus `LC_*`. Opt-out: `LocalRunner(..., env_passthrough=True)`.

4. **No silent drops.** `DockerRunner` forwards `compat_patch` and `channels` to the impl.

5. **Dynamic `sdk_info`.** `assemble_bundle` no longer hardcodes the convergence client;
   `pipeline._sdk_info` reports the real class, `claudopus_available`, `convergence_is_mock`.

6. **Valid SARIF.** `uriBaseId` is now the symbolic `SRCROOT` resolved via
   `originalUriBaseIds` (was a raw path).

+7 regression tests in `tests/test_smoke.py` lock all of the above. Suite: **32 passed**
on real disk.

## Known limitations / deferred (BUGS)

### BUG (DEFERRED): Docker sandbox is a stub — v1 proves locally, without container isolation
- **Status:** WONTFIX-in-v1 (feature, not a finalize edit). Surfaced honestly.
- **Symptom:** `sandbox/docker_runner.py` returns `status="crash"` for every harness;
  `--sandbox-mode docker` therefore yields 0 proven findings.
- **Repro:** `deepaudit scan tests/fixtures/sql_injection --authorized --sandbox-mode docker`
  → warning + bundle `sandbox.isolation_applied=false`, `findings=[]`.
- **Real env needs (v2):** container runtime with `--network none --cap-drop ALL
  --user nobody --security-opt no-new-privileges --tmpfs /tmp ...` per spec §6, plus the
  env-probe-in-container path. Until then, treat `proven` findings as reproduced on the
  host, exactly as the bundle now states.

### BUG (DEFERRED): convergence uses the mock judge in v1
- **Status:** WONTFIX-in-v1. Made loud + recorded in the bundle.
- **Symptom:** the pipeline never instantiates `sdk/client.py::RealConvergenceClient`;
  the mock agrees on every candidate (the sandbox proof is the real gate).
- **Why not wired:** `RealConvergenceClient.judge` calls `claudopus.convergence.judge(...)`,
  an SDK surface that cannot be verified from the build environment. Wiring it on an
  unverified API would violate the no-assumption rule. The bundle now records
  `sdk.convergence_is_mock=true` and the CLI warns.

### BUG (DEFERRED): `verify_bundle` trusts the embedded public key
- **Status:** documented design limitation.
- **Symptom:** the signature object carries its own `public_key`; verification proves
  integrity-since-signing, not authenticity. A tampered bundle re-signed with a fresh key
  passes `verify`.
- **Fix (v2):** pin/trust-root the signer key out-of-band before treating "valid" as
  "from a trusted auditor."

### ENV NOTE: SQLite acceptance test can't run on a FUSE mount
- `tests/test_smoke.py::test_acceptance_fixture` fails with `sqlite3.OperationalError:
  disk I/O error` only when the repo lives on the Cowork FUSE mount. It passes on
  sandbox-local `/tmp` and on the Mac. Run the suite from a real disk path.
