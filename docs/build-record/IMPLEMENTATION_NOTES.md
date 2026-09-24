# DeepAudit — Round 2 Implementation Notes

## What changed

- **Bundle serialization and signing** (`deepaudit/core/findings.py`, `deepaudit/crypto/signing.py`)
  - The previous code signed an empty `{}` payload and wrote `bundle.__dict__` to disk, which
    produced non-JSON strings for nested dataclasses. The bundle now uses a recursive
    `to_plain()` / `bundle_to_json()` helper to serialize dataclasses, lists, and tuples into
    JSON-safe primitives.
  - The signature is now computed over the canonicalized bundle payload (excluding the signature
    object itself) using Ed25519.
  - `--signing-key` is supported: an existing PEM key is loaded, and a missing key path is
    auto-generated and persisted.
  - Canonicalization uses RFC 8785 (JCS) when the `jcs` package is installed, otherwise a stable
    sorted compact JSON fallback.

- **Bundle verification** (`deepaudit/core/findings.py`, `deepaudit/cli/main.py`)
  - Added `verify_bundle(path_or_dict)` that verifies the Ed25519 signature and checks that the
    embedded `sentinel_hash` in each differential proof matches a sentinel string found in the
    stored exploit harness source.
  - Added `deepaudit verify <bundle>` CLI subcommand, with optional `--re-run <repo>` that
    re-executes each stored exploit/control harness pair against the supplied repo and confirms
    the differential still holds.
  - Added `resign_bundle()` so the CLI can re-sign the bundle after post-filtering
    (`--severity`, `--include-unverified`) and keep the on-disk artifact internally consistent.

- **Configuration** (`deepaudit/config/defaults.py`)
  - Added `signing_key` to `DeepAuditConfig`.

- **Dependencies** (`pyproject.toml`)
  - Moved `cryptography` from an optional extra to the core dependency list, matching the spec.

- **Tests** (`tests/test_smoke.py`)
  - Added `test_bundle_signing_and_verification` to exercise the on-disk bundle serialization,
    signature, and verification path.

## Verification

```bash
python3 -m pytest tests/test_smoke.py tests/fixtures/path_traversal/reader.py -v
```

All 7 tests pass.

```bash
DEEPAUDIT_AUTHORIZED=1 python3 -m deepaudit.cli.main scan tests/fixtures/sql_injection --mock-sdk --output /tmp/bundle.json
python3 -m deepaudit.cli.main verify /tmp/bundle.json
python3 -m deepaudit.cli.main verify /tmp/bundle.json --re-run tests/fixtures/sql_injection
```

All commands succeed and report the bundle valid.

---

# DeepAudit — Round 3 Implementation Notes

## What changed

- **Code injection template alignment** (`deepaudit/templates/code_injection_exec.py`)
  - The `eval`/`exec` PoC harness now uses the Python-expression payload specified in
    spec §6.7: `print("{sentinel}")` for the exploit and `42` for the control.
  - Removed the harness-level `if sentinel in str(result)` check; the spec harness
    relies on the payload itself writing the sentinel to stdout.

- **Command injection precondition guard** (`deepaudit/templates/command_injection_echo.py`)
  - Added the explicit `sink_metadata.is_code_exec is False` precondition required by
    spec §6.4/§6.6 so the template can never match an `eval`/`exec` sink.

- **Code injection fixture and test** (`tests/fixtures/code_injection/`, `tests/test_smoke.py`)
  - Added `tests/fixtures/code_injection/app.py` and `handler.py` mirroring the other
    cross-file fixture pattern (request parameter source → eval sink in a separate module).
  - Added `test_fixture_code_injection` to prove the finding is proven with the
    `code_injection_exec` template.

## Verification

```bash
python3 -m pytest tests/test_smoke.py -v
```

All 11 tests pass (the original 10 plus the new code-injection fixture test).

---

# DeepAudit — Round 5 Implementation Notes

## What changed

- **Config-driven compat patch** (`deepaudit/core/pipeline.py`)
  - `run_deepaudit_scan()` now reads `config.compat_patch` and passes it to the default
    `LocalRunner`. Previously the config field was only honored when the caller built the
    runner themselves, so direct API usage silently dropped the patch.

- **Full SHA-256 sentinel hash** (`deepaudit/sandbox/sentinel.py`, `deepaudit/core/proof_oracle.py`, `deepaudit/cli/main.py`)
  - `hash_sentinel()` now returns the complete SHA-256 digest instead of a 16-character
    truncation. The spec §6.19/§7.3 describe the field as the SHA-256 of the sentinel; proof
    generation and verification now match that contract end-to-end.

- **Configurable convergence lineages** (`deepaudit/core/convergence.py`, `deepaudit/core/pipeline.py`)
  - `judge_candidate()` accepts an optional `lineages` list and falls back to the legacy
    `["lineage-A", "lineage-B"]` default. The pipeline now passes
    `config.convergence_lineages`, making the config field effective instead of dead.

- **CLI `--scan-timeout` alias** (`deepaudit/cli/main.py`)
  - Changed `--scan-timeout` default from `60` to `None` so that `--sandbox-timeout` is
    honored when the newer alias is not supplied. Previously both defaults were truthy, so
    the legacy flag was always ignored.

- **Tests** (`tests/test_smoke.py`)
  - Added `test_config_compat_patch_reaches_default_runner`,
    `test_config_convergence_lineages_propagate`, `test_sentinel_hash_is_full_sha256`,
    and the two CLI timeout-alias tests to lock in the fixes above.

## Verification

```bash
python3 -m pytest tests/ -v
```

All 20 tests pass.
