# DeepAudit v1

**Prove-It-Or-Don't-Ship Security Auditor**

DeepAudit is a standalone security auditor that reports only vulnerabilities it has proven exploitable through a sandboxed, differential execution trace. Every shipped finding carries a captured exploit/control differential: a sentinel that appears in the exploit run and is absent from the matched control run. Anything that cannot be reproduced this way is labeled `UNVERIFIED` and is permanently excluded from the signed findings bundle.

- **Status:** v1 working engine (Python target, architecture is language-agnostic)
- **Runtime:** Python 3.11+
- **Core engine:** `claudopus` Python SDK (`import claudopus`) — the adversarial convergence engine is invoked, never reimplemented
- **Scope:** Working technology only. No pricing, billing, accounts, or telemetry.

---

## What it does

1. **Maps the repository** — builds a cross-file call graph, data-flow edges, and trust-boundary tags for every Python file in the target.
2. **Finds candidates** — enumerates taint paths from untrusted sources to dangerous sinks.
3. **Converges with adversarial review** — routes each candidate through the `claudopus` convergence judge with cross-lineage agreement.
4. **Proves or rejects** — generates exploit and control harnesses, executes them in a sandbox, and keeps only findings where the exploit produces a sentinel the control does not.
5. **Ships a signed bundle** — emits a signed, canonicalized JSON bundle with findings, traces, and reproduction artifacts.

Static findings (hardcoded secrets) bypass the proof pipeline and are detected directly during mapping.

---

## Quick start

DeepAudit requires **Python 3.11 or newer**. Install the package in editable mode:

```bash
python3.12 -m venv .venv
source .venv/bin/activate
pip install -e .
```

Run the smoke tests:

```bash
python3 -m pytest tests/test_smoke.py -v
```

Scan one of the bundled fixtures:

```bash
python3 -m deepaudit scan tests/fixtures/sql_injection --authorized --mock-sdk
```

The `--mock-sdk` flag replaces the real `claudopus` convergence engine with a deterministic mock so the tool can run in CI without SDK credentials. With the mock, all candidates are accepted for proof, which is useful for testing the harness and sandbox layers.

---

## CLI usage

```bash
deepaudit scan <repo> [options]
```

Required:

- `<repo>` — repository root to audit.
- `--authorized` — confirm the operator owns or is authorized to test the code. Equivalent to `DEEPAUDIT_AUTHORIZED=1`.

Output options:

| Flag | Description | Default |
|------|-------------|---------|
| `-o, --output <path>` | Signed bundle destination | `./deepaudit-findings.json` |
| `--format <fmt>` | Output format: `json` \| `text` | `json` |
| `--severity <level>` | Minimum severity to ship: `critical` \| `high` \| `medium` \| `low` | `low` |
| `--include-unverified` | Populate `unverified[]` with diagnostic details | off |

Execution options:

| Flag | Description | Default |
|------|-------------|---------|
| `--sandbox-mode <mode>` | `local` (subprocess) or `docker` | `local` |
| `--sandbox-timeout <sec>` | Per-harness wall-clock limit | `30` |
| `--no-sandbox` | Skip proof execution; no finding can be proven | off |
| `--dry-run` | Map and converge only; skip proof execution | off |
| `--mock-sdk` | Use the built-in mock convergence client | off |
| `--no-static` | Disable static secret scan | off |
| `--no-write-bundle` | Do not write the findings bundle to disk | off |

Miscellaneous:

| Flag | Description | Default |
|------|-------------|---------|
| `--config <path>` | Path to `deepaudit.toml` | none |
| `--max-candidates <n>` | Soft cap on candidate enumeration | `200` |
| `-v, --verbose` | Repeat for more detail | off |
| `-q, --quiet` | Suppress all output except the final summary | off |

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | Scan completed. Bundle emitted. May contain zero or more proven findings. |
| `1` | Fatal infrastructure error (Docker, parser, SDK, signing, image build). |
| `2` | Specified for "scan completed but no candidates passed proof". Not implemented in v1: that case exits `0` with an empty `findings` list. |
| `3` | Invalid input or authorization not granted. |

### Stdout summary

```text
DeepAudit scan finished.
  Target:         ./repo
  Files parsed:   247
  Candidates:     14
  Converged:      5
  Proven:         2
  Unverified:     12
  Static findings: 3
  Bundle:         ./deepaudit-findings.json
  Signature:      valid (Ed25519, fingerprint a1b2c3…)
```

---

## Architecture overview

The pipeline has four stages:

```text
Stage 1      → Stage 2        → Stage 3        → Stage 4
Repo Map     → Convergence    → Proof Exec     → Bundle + Sign
  cross-file    candidates       proven +         findings
  call graph    with taint       unverified       + traces
  data flows    flows            sentinel diff    + signature
  trust boundaries
  static scan ─────────────────────────────────→ static findings
```

Static findings (secrets in code) bypass Stages 2 and 3. There is no separate adversarial-attack stage in v1 — the Sneferu `POST /sdk/judge` call (`claudopus.Client.judge`, unanimous agreement across distinct trainer lineages) **is** the cross-lineage adversarial convergence gate.

The specification is in [`../docs/specification/`](../docs/specification/). The build record (implementation notes, finalizer notes) is in [`../docs/build-record/`](../docs/build-record/).

See [`docs/TEMPLATES.md`](docs/TEMPLATES.md) for the PoC template catalog and adapter design.

---

## Testing

The smoke-test suite exercises the whole pipeline on small, intentionally vulnerable fixtures:

```bash
python3 -m pytest tests/test_smoke.py -v
```

Current fixtures:

- `sql_injection` — f-string SQL query in a cross-file call.
- `command_injection` — `os.system` with shell injection.
- `unsafe_deserialization` — `pickle.loads` on user input.
- `path_traversal` — open-with-traversal on a user-supplied path.

Run the full test suite with:

```bash
python3 -m unittest discover -s tests -t .
```

---

## Security and authorization

DeepAudit executes code extracted from the target repository in a sandbox. It is designed to run only against code the operator owns or is explicitly authorized to test. The CLI requires `--authorized` (or `DEEPAUDIT_AUTHORIZED=1`) and refuses to run without it. In v1, proof execution runs each harness as a host subprocess (`--sandbox-mode local`, the default) with a scrubbed, allowlisted environment and a timeout, but without container or network isolation. `--sandbox-mode docker` is a stub in v1: every proof comes back UNVERIFIED. The signed bundle's `sandbox` block records which of these applied.

---

## Project layout

```text
deepaudit/
├── cli/                  # argparse entry point and orchestration
├── core/                 # pipeline, repo map, taint, proof, bundle
├── languages/            # pluggable language frontends
│   └── python/           # Python parser, sources, sinks, sanitizers
├── sandbox/              # Docker/runner execution environment
├── templates/            # deterministic PoC harness templates
├── source_adapters.py    # source-kind → harness injection strategies
├── sdk/                  # ConvergenceClient protocol and mock
├── models/               # taint, candidate, finding data classes
├── crypto/               # Ed25519 signing and canonicalization
├── config/               # default configuration loader
├── fixtures/             # vulnerable test repositories
├── docs/                 # documentation
└── README.md             # this file
```

---

## License

See the repository's top-level license file. DeepAudit is a research/engineering artifact; it is not a SaaS product.
