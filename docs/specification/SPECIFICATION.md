# DeepAudit v1 — Prove-It-Or-Don't-Ship Security Auditor

**Status:** Canonical root specification (revision 5, reframed template and adapter system).  
**Runtime:** Python 3.11+.  
**Target language (v1):** Python. Architecture exposes language-agnostic seams at every pluggable boundary.  
**Core engine:** `claudopus` Python SDK (`import claudopus`). The adversarial convergence engine is invoked, never reimplemented.  
**Scope:** Working technology only. No pricing, tiers, billing, accounts, SaaS, or telemetry.

---

## 1. System Identity

`deepaudit scan <repo>` is a standalone CLI that audits a codebase and reports **only** vulnerabilities it has proven exploitable through a sandboxed execution trace. Each shipped finding carries a captured differential: a sentinel observable produced during the exploit run and absent from a matched control run. Anything that cannot be reproduced this way is labeled `UNVERIFIED` and permanently excluded from the signed findings bundle.

The tool evaluates code the operator owns or is explicitly authorized to test. Output is remediation-oriented: locate the flaw, demonstrate the exploit, prescribe the fix. Nothing in the pipeline targets third-party systems. The `--authorized` flag enforces this at the CLI level — the tool refuses to run without it.

This specification defines the working engine only. If the proof engine cannot demonstrate a real exploit, there is nothing to commercialize. The business wraps around later; the technology must stand on its own first.

### 1.1 Reframing From Prior Revisions

Prior revisions left four of six PoC templates unspecified, assigned `eval`/`exec` sinks to a shell-command template that produces syntactically invalid harnesses, assumed the Flask adapter could conjure a Flask app object without describing how, and over-claimed CLI adapter coverage for `argparse` patterns it cannot handle. This revision reframes the template system:

- **Seven templates, all fully specified.** Each registered template now has a complete harness design section with substitution variables, exploit/control harness source, and sentinel verification. `eval`/`exec` sinks are split into a dedicated `code_injection_exec` template with Python-expression payloads, not shoehorned into the shell-based `command_injection_echo` template.
- **Flask adapter creates its own minimal app.** The `FlaskRequestParamAdapter` does not need to discover the target's Flask app object. Flask's `request` proxy is thread-local; any Flask app's `test_request_context()` activates it. The adapter creates `Flask(__name__)` in the harness. This is documented as a deliberate design choice, not an omission.
- **CLI adapter scoped to `sys.argv` only.** The `CLIArgAdapter` detection criteria no longer include `argparse` namespace access. The adapter handles direct `sys.argv` indexing only. `argparse`-based sources are honestly out of v1 adapter coverage.
- **Adapter priority is numeric and deterministic.** Each adapter has a `priority: int` field. Selection sorts by priority descending; ties broken by registration order. No ambiguity.
- **`SandboxEnvironment` populated by in-container probe.** After image build, a probe script runs inside the container to collect Python version, installed packages, and SQLite availability.
- **Compatibility probe runs in full sandbox isolation.** Same `--network none`, resource limits, non-root user, and seccomp as proof containers.
- **`fix.patch_unified_diff` removed from bundle schema.** v1 provides text fix summaries only. Automatic patch generation is deferred to v2.
- **Severity escalation conditions removed.** v1 uses fixed severities per exploit class. No unverifiable "data exfiltration" criteria.
- **`unverified` array always present in bundle.** Possibly empty. No conditional emission ambiguity.

### 1.2 Design Rationale

Scorers diverged most sharply on **implementability** (spread: 37) and **completeness** (spread: 28). The implementability gap traced to three root causes: (1) four templates had no harness design, (2) `eval`/`exec` were assigned to a template that generates broken harnesses, and (3) the Flask and CLI adapters were underspecified. This revision provides complete harness designs for all seven templates, splits code injection into its own template, and grounds every adapter in a concrete, testable injection strategy.

---

## 2. CLI Surface

### 2.1 Invocation

```
deepaudit scan <repo> [options]
```

### 2.2 Flags

```
Required:
  <repo>                     Repository root to audit.
  --authorized               Confirm operator owns or is authorized
                             to test this code. Without this flag or
                             DEEPAUDIT_AUTHORIZED=1, the tool aborts.

Output:
  -o, --output <path>        Signed bundle destination.
                             Default: ./deepaudit-findings.json
  --format <fmt>             json (default) | sarif | text
  --severity <level>         Minimum severity to ship: critical | high | medium | low
                             Default: low (ship all proven findings)
  --include-unverified       Also populate unverified[] with diagnostic details.
                             Always present in schema; flag controls whether
                             entries are populated or left as empty array.

Execution:
  --sandbox-image <img>      Docker image for proof execution.
                             Default: python:3.11-slim
  --sandbox-timeout <sec>    Per-harness wall-clock limit (each exploit or
                             control run). Default: 60
  --scan-timeout <sec>       Total scan wall-clock limit. Default: 1800
  --jobs <n>                 Parallel sandbox executions. Default: 1
  --no-sandbox               Skip Docker. No finding can be proven.
  --dry-run                  Map and converge only; skip proof execution.
                             All candidates become UNVERIFIED.
  --mock-sdk                 Use built-in mock convergence client instead of
                             the real claudopus SDK. For CI and development.
  --compat-patch <path>      Python file executed before importing the target
                             module in the sandbox. Used to monkey-patch
                             dependencies that cause import-time side effects
                             (database connections, network calls, etc.).

Verification:
  --verify <bundle>          Validate signature and internal consistency of
                             an existing bundle. Checks Ed25519 signature,
                             RFC 8785 canonicalization, and that
                             sentinel_hash matches the sentinel embedded
                             in the stored harness source code.
  --verify <bundle>          Re-run sentinel differentials against the
      --re-run <repo>        specified repo. Extracts the sentinel from
                             the stored harness source, rebuilds the
                             sandbox, and executes both exploit and
                             control harnesses. Reports whether the
                             differential still holds.

Miscellaneous:
  --signing-key <path>       Ed25519 private key (PEM). Auto-generated if absent.
  --config <path>            Path to deepaudit.toml overriding defaults.
  --max-candidates <n>       Soft cap on candidate enumeration. Default: 200.
                             Candidates are sorted deterministically before
                             truncation (see §4.6).
  -v, --verbose              Repeat for more detail. -vv = debug.
  -q, --quiet                Suppress all output except final summary.
  -h, --help                 Show usage.
```

### 2.3 Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Scan completed. Bundle emitted. May contain zero or more proven findings. |
| 1 | Fatal infrastructure error. Docker unavailable, parser crash, SDK failure, signing error, image build failure. |
| 2 | Scan completed but no candidates passed proof. Bundle contains zero findings. |
| 3 | Invalid input. Path not found, not a repository, or authorization not granted. |

### 2.4 Stdout Summary

After every scan, a compact human-readable summary prints:

```
DeepAudit scan finished.
  Target:         ./repo
  Files parsed:   247
  Candidates:     14
  Converged:      5
  Proven:         2
  Unverified:     12  (excluded from shipped findings)
  Static findings: 3  (secrets in code)
  Bundle:         ./deepaudit-findings.json
  Signature:      valid (Ed25519, fingerprint a1b2c3…)
```

---

## 3. Architecture and Module Boundaries

### 3.1 Pipeline

```
┌──────────┐     ┌───────────────┐     ┌────────────┐     ┌──────────┐
│ Stage 1  │────▶│   Stage 2     │────▶│  Stage 3   │────▶│ Stage 4  │
│ Repo Map │     │  Convergence  │     │ Proof Exec │     │  Bundle  │
│tree-sitter│    │ claudopus SDK │     │  Docker    │     │  + Sign  │
└──────────┘     └───────────────┘     └────────────┘     └──────────┘
  cross-file       candidates           proven +           findings
  call graph       with taint           unverified         + traces
  data flows       flows                sentinel diff      + signature
  trust boundaries
  static scan ──────────────────────────────────────────▶ static
  (secrets)                                                findings
```

The pipeline has four stages. Static findings (secrets in code) bypass Stages 2 and 3 entirely — they are detected during Stage 1 and routed directly to Stage 4. There is no separate adversarial-attack stage in v1 — the `claudopus.convergence.judge` call with `require_agreement="all"` IS the cross-lineage adversarial convergence gate. The SDK's separate `claudopus.adversarial.attack` feature is available in the SDK but is not invoked by v1. See §10 for the complete SDK usage contract.

### 3.2 Module Layout

```
deepaudit/
├── __main__.py                     # entry: python -m deepaudit
├── cli/
│   └── main.py                     # argparse, orchestration, exit codes
├── core/
│   ├── pipeline.py                 # stage sequencing, timeout, error routing
│   ├── repo_map.py                 # Stage 1: tree-sitter mapping
│   ├── taint_engine.py             # cross-file taint propagation (abstract domain in §4.7)
│   ├── candidate_gen.py            # source→sink path enumeration
│   ├── static_scan.py              # Stage 1b: secret pattern detection (bypasses convergence)
│   ├── convergence.py              # Stage 2: claudopus SDK thin shim
│   ├── proof_oracle.py             # Stage 3: sandbox execution + differential
│   ├── poc_gen.py                  # PoC harness generation (template system in §6.7)
│   ├── source_adapters.py          # Source-kind-to-mock-injection mapping (§6.2)
│   ├── compat_probe.py             # Pre-proof environment compatibility check (§6.11)
│   ├── env_probe.py                # Sandbox environment discovery (§6.14)
│   └── findings.py                 # Stage 4: bundle assembly + signing
├── sandbox/
│   ├── docker_runner.py            # container lifecycle
│   ├── image_builder.py            # sandbox image generation + build error handling
│   └── sentinel.py                 # sentinel injection + differential check
├── crypto/
│   └── signing.py                  # Ed25519 key management, RFC 8785 canonicalization
├── languages/
│   ├── base.py                     # LanguageFrontend protocol
│   └── python/
│       ├── frontend.py             # PythonLanguageFrontend
│       ├── sources.py              # untrusted input taxonomy + source-kind detection
│       ├── sinks.py                # dangerous sink taxonomy + sink metadata extraction
│       ├── sanitizers.py           # sanitization function taxonomy
│       └── queries.py              # tree-sitter query patterns
├── sdk/
│   ├── client.py                   # ConvergenceClient protocol + real SDK adapter
│   └── mock.py                     # MockConvergenceClient for CI
├── models/
│   ├── taint.py                    # taint flow data structures
│   ├── candidate.py                # vulnerability candidate (with sink_metadata, source_kind)
│   ├── finding.py                  # proven finding + bundle (differential + static)
│   └── trace.py                    # execution trace
├── config/
│   └── defaults.py                 # default config + loader
├── templates/
│   ├── sql_injection_read.py       # SQL injection (SELECT) harness template
│   ├── command_injection_echo.py   # command injection (shell=True) harness template
│   ├── code_injection_exec.py      # eval/exec code injection harness template
│   ├── path_traversal_read.py      # path traversal harness template
│   ├── deserialization_pickle.py   # unsafe deserialization harness template
│   ├── template_injection_jinja2.py # SSTI harness template
│   └── auth_bypass_direct.py       # auth bypass harness template
└── fixtures/
    ├── acceptance_repo/            # §12.1 acceptance test fixture
    ├── cmd_injection_repo/         # §12.6 command injection fixture
    ├── deserialization_repo/       # §12.6 deserialization fixture
    └── path_traversal_repo/        # §12.6 path traversal fixture
```

### 3.3 Hard Module Boundaries

1. **`convergence.py` is a thin shim.** It translates DeepAudit's candidate format into the SDK's expected input dict (schema defined in §5.3), calls the SDK via a `ConvergenceClient` protocol (enabling mock injection), and maps the result back. It must not contain model-specific logic, prompts, scoring thresholds, or lineage configuration. If convergence semantics shift, the shift happens in `claudopus`, not here.

2. **`sandbox/` is the only layer that touches Docker or subprocess.** The `core/` and `languages/` modules must not import `docker`, `subprocess`, or any process-execution primitive. This keeps the static analysis pipeline testable without a Docker daemon.

3. **`findings.py` reads only the differential verdict and captured trace.** It must not depend on how the verdict was produced or which exploit class was exercised. Bundle assembly is a pure transformation from proof results to signed JSON.

4. **`languages/` modules are pluggable.** Adding a language means implementing the `LanguageFrontend` protocol and registering it. No core module may import a language-specific module directly.

5. **`templates/` contains only deterministic template code.** No LLM calls. Each template is a Python module with a `preconditions()` function, an `environmental_preconditions()` function, a `generate_exploit()` function, and a `generate_control()` function. Templates are registered by exploit class name and dispatched by the proof oracle.

6. **`source_adapters.py` maps source kinds to harness injection strategies.** Templates use adapters to generate the mock-injection portion of the harness. No template hard-codes a single mocking pattern. Each adapter has a numeric `priority` field; selection is deterministic.

7. **`static_scan.py` bypasses convergence.** Secrets-in-code findings are detected by pattern matching during Stage 1 and routed directly to `findings.py`. They do not pass through `taint_engine.py`, `candidate_gen.py`, or `convergence.py`. This is by design — static findings have no taint path and no sandbox proof.

### 3.4 LanguageFrontend Protocol

```python
from typing import Protocol

class LanguageFrontend(Protocol):
    """Pluggable language parser. v1 ships PythonFrontend only."""

    name: str

    def parse_file(self, source: str, filename: str) -> object: ...
    def extract_sources(self, tree: object, filename: str) -> list[SourceNode]: ...
    def extract_sinks(self, tree: object, filename: str) -> list[SinkNode]: ...
    def extract_sanitizers(self, tree: object, filename: str) -> list[SanitizerNode]: ...
    def extract_call_edges(self, tree: object, filename: str) -> list[CallEdge]: ...
    def extract_imports(self, tree: object, filename: str) -> list[ImportEdge]: ...
    def extract_function_signatures(self, tree: object, filename: str) -> list[FunctionSignature]: ...
```

The `extract_function_signatures` method enables the source adapter system to determine whether a source root identifier is a function parameter or a module-level global.

### 3.5 ConvergenceClient Protocol

The SDK adapter and mock share this protocol, enabling dependency injection for CI:

```python
from typing import Protocol

class ConvergenceClient(Protocol):
    """Interface for convergence judgement — real SDK or mock."""

    def judge(
        self,
        candidate: dict,
        *,
        lineages: list[str],
        require_agreement: str,
        on_disagreement: str,
    ) -> "ConvergenceResult": ...

    def trace_last(self, verdict: "ConvergenceResult") -> "TraceRecord": ...
```

The real adapter (`sdk/client.py`) wraps `claudopus.convergence.judge` and `claudopus.trace.last`. The mock (`sdk/mock.py`) returns deterministic verdicts based on the candidate's exploit class and taint path shape. See §11.3 for the mock specification.

### 3.6 SourceAdapter Protocol

```python
from typing import Protocol

class SourceAdapter(Protocol):
    """Maps a detected source kind to a harness injection strategy.
    
    Each adapter has a numeric priority. Higher priority = more specific.
    Framework-specific adapters (Flask) have priority 100.
    Pattern-specific adapters (FunctionParamRequest) have priority 90.
    Kind-specific adapters (CLIArg, EnvVar, etc.) have priority 80.
    Generic fallback has priority 0.
    
    Selection: filter to can_handle()==True, sort by priority descending,
    select first. Ties broken by registration order (stable sort).
    """

    kind: str
    priority: int

    def can_handle(
        self,
        source: ProgramPoint,
        candidate: VulnerabilityCandidate,
        repo_model: RepoModel,
    ) -> bool:
        """Return True if this adapter can handle the detected source pattern.
        Checks the source expression text, the source kind, and whether the
        source root identifier is a function parameter or module-level global.
        """
        ...

    def generate_setup(
        self,
        source: ProgramPoint,
        sentinel: str,
        is_exploit: bool,
        candidate: VulnerabilityCandidate,
    ) -> str:
        """Return Python code that sets up the mock environment before
        importing the target module. For Flask, this creates a Flask app
        and test request context. For CLI args, this sets sys.argv. For env
        vars, this sets os.environ. For function parameters, this creates
        the mock object. The code is inserted into the harness before the
        target module import.
        """
        ...

    def generate_invocation(
        self,
        source: ProgramPoint,
        sentinel: str,
        is_exploit: bool,
        candidate: VulnerabilityCandidate,
    ) -> str:
        """Return Python code that invokes the vulnerable function
        with the mock input. For function-parameter sources, this
        passes the mock as an argument. For global-import sources,
        this calls the function with no arguments (the mock is in
        the environment).
        """
        ...
```

**Adapter priority assignment (deterministic, documented):**

| Adapter | Priority | Rationale |
|---------|----------|-----------|
| `FlaskRequestParamAdapter` | 100 | Framework-specific, most specific match |
| `FlaskRequestBodyAdapter` | 100 | Framework-specific, most specific match |
| `FunctionParamRequestAdapter` | 90 | Pattern-specific (`.args.get()` on function param) |
| `CLIArgAdapter` | 80 | Kind-specific (`sys.argv` direct access) |
| `EnvVarAdapter` | 80 | Kind-specific (`os.environ` access) |
| `FileReadAdapter` | 80 | Kind-specific (`open()` source) |
| `UserInputAdapter` | 80 | Kind-specific (`input()` source) |
| `GenericFunctionParamAdapter` | 0 | Fallback — lowest priority by design |

**Selection algorithm (deterministic):**
1. From the `VulnerabilityCandidate`, extract `source_kind`, `source_is_parameter`, and the source expression.
2. Filter registered adapters to those where `can_handle()` returns `True`.
3. Sort matching adapters by `priority` descending. Python's `sorted()` is stable, so adapters with equal priority retain registration order.
4. Select the first adapter in the sorted list.
5. If no adapter matches, the candidate is marked `UNVERIFIED (no_source_adapter)` and does not proceed to harness generation.

---

## 4. Stage 1 — Repository Mapping

### 4.1 Objective

Produce a cross-file program model that captures the call graph, data-flow edges, and trust boundaries spanning the entire repository. This is not per-file analysis. The model must connect a function call in `handlers.py` to its definition in `db.py` through import resolution, and must propagate taint across that edge.

Additionally, `static_scan.py` runs during Stage 1 to detect hardcoded secrets. These are routed directly to the findings pipeline and do not pass through taint analysis or convergence (see §7.6).

### 4.2 Tree-Sitter Parsing

Every `.py` file in the target directory is parsed using the `tree-sitter-python` grammar. Virtual environments, `__pycache__`, `.git`, and dependency directories are skipped. Parse failures are recorded but do not halt the scan. The scan summary reports the count of files that failed to parse.

### 4.3 Resource Limits (Mapper Defensive Bounds)

The mapper enforces defensive resource limits to prevent pathological repos from hanging the process:

| Limit | Value | Enforcement |
|-------|-------|-------------|
| Per-file parse timeout | 10 seconds | `signal.alarm` (Unix) or thread-based timeout wrapper. Files exceeding this are recorded as parse failures. |
| Global mapper memory (hard) | 4 GB | `resource.setrlimit(RLIMIT_AS, 4 * 1024 * 1024 * 1024)` at process start. The OS enforces this as a hard limit. |
| Global mapper memory (soft advisory) | 3.5 GB | Checked via `psutil.Process().memory_info().rss` after each file. If exceeded, scan gracefully exits with exit code 1. |
| Import resolution depth | 20 levels | Circular or excessively deep import chains are truncated and recorded. |
| Per-file AST node count | 100,000 nodes | Files exceeding this are skipped with a parse failure record. |

### 4.4 Cross-File Model Construction

The mapper resolves:

- **Imports:** `from a.b import c as d` and `import a.b.c` — bind call sites to defining modules, including relative imports and package-root resolution.
- **Qualified names:** Every function and class is addressable as `module.path.object`.
- **Call edges:** A call in `views.py` to `store.search(...)` resolves to `store.py:search`. Nodes are functions, methods, lambdas, and classmethods.
- **Data-flow edges:** Track variable assignments, return values, argument passing, tuple unpacking, collection literal construction, string formatting, and string concatenation within and across function boundaries.
- **Function signatures:** Each function's parameter list is extracted, including parameter names, defaults, and annotations. This enables the source adapter system to determine whether a source root identifier (e.g., `request`) is a function parameter or a module-level import.
- **Trust boundaries:** Entrypoints — HTTP route handlers, CLI argument parsers (`sys.argv` direct access), socket listeners, file readers, environment variable access, `input()` calls — are tagged as untrusted sources, annotated by kind: `http_param`, `http_body`, `cli_arg`, `env_var`, `file_read`, `socket_recv`, `user_input`. Additionally, **public function parameters** (functions not prefixed with `_`) are tagged as potential untrusted sources with kind `generic_param`. This is conservative — the convergence gate and proof oracle filter out false positives. A function parameter source is tagged `http_param_func` if the expression contains `.args.get()` or `.GET.get()` and the root identifier is a function parameter.

The intermediate model is persisted to `.deepaudit/model/` for debugging and inspection.

### 4.5 Taint Propagation Rules

1. **Assignment:** If `x = tainted_source()`, then `x` is tainted.
2. **Return:** If `def f(param): return param + suffix` and `param` is tainted, the return value of `f` is tainted.
3. **Argument passing:** If `g(tainted_val)` calls `def g(arg):`, then `arg` is tainted inside `g`.
4. **Inter-procedural cross-file:** When module A calls a function defined in module B, an argument tainted in A taints the corresponding parameter in B. If B returns a value derived from that parameter to A, the assignment site in A is tainted.
5. **String formatting:** If `f"...{tainted}..."` or `"...{}".format(tainted)` or `"...%s" % tainted` is constructed, the resulting string is tainted.
6. **Collection construction:** If `[tainted, ...]` or `{tainted, ...}` or `{k: tainted, ...}` is constructed, the collection is tainted (whole-object taint, no field sensitivity).
7. **Tuple unpacking:** If `a, b = func_returning_tainted()`, both `a` and `b` are tainted (conservative).
8. **Sanitizer barrier:** If a recognized sanitizer appears on the path between source and sink, and the data-flow graph shows the sanitizer's output reaching the sink while the pre-sanitizer value does not, taint is cleared for that path. The clipping is recorded for audit.
9. **Sanitizer bypass:** If the sanitizer is on one branch but the data-flow graph shows an alternative path from source to sink that bypasses the sanitizer, taint persists on the bypass path. The two paths generate separate candidates — the sanitized path is suppressed, the bypassed path is kept.
10. **Single-file rejection:** If the entire data flow from source to sink never leaves a single file (no import-controlled call edges), the candidate is downgraded to `SINGLE_FILE_REJECTED` and never proceeds to convergence.

### 4.6 Candidate Ordering and Deterministic Truncation

Candidates are enumerated and sorted by the deterministic key `(source.file, source.line, source.column, sink.file, sink.line, sink.column)`. When `--max-candidates` is exceeded, candidates are truncated from the end of this sorted list. This ensures that two scans of the same repository produce the same candidate set (modulo timestamps and sentinel values), preserving the idempotency guarantee in §16.2.

### 4.7 Taint Abstract Domain (v1 Scope)

The taint engine implements a concrete abstract domain. The following table defines what is tracked and what is explicitly NOT tracked in v1.

**Tracked constructs:**

| Construct | How it is modeled |
|-----------|-------------------|
| Variable assignment | Taint transfers from RHS to LHS variable |
| Function parameters | Taint transfers from call-site argument to parameter |
| Return values | Taint transfers from returned expression to call-site variable |
| Tuple unpacking | Conservative: all unpacked variables are tainted |
| String formatting (f-string, .format(), %) | Result string is tainted if any interpolation argument is tainted |
| String concatenation (+) | Result is tainted if either operand is tainted |
| List/dict/set literals | Collection is tainted if any element is tainted |
| Direct function calls (by qualified name) | Resolved through import graph; taint flows through arguments and returns |
| Method calls (by class name + method name) | Resolved through import graph; no MRO, no dynamic dispatch |
| Field access (obj.attr) | Whole-object taint: if obj is tainted, obj.attr is tainted and vice versa |

**Not tracked (out of v1 scope):**

| Construct | Why it is excluded | Impact |
|-----------|--------------------|--------|
| Dynamic dispatch (`getattr`, `__getattribute__`, `functools.singledispatch`) | Cannot resolve target at static analysis time | May miss vulnerabilities dispatched through dynamic attribute access |
| Metaclass magic, `__init_subclass__`, `__set_name__` | Execution-time class construction is not modeled | May miss vulnerabilities in class construction paths |
| Decorator transformation | The decorated function's body is analyzed as-is; the decorator's wrapping behavior is not modeled | May miss vulnerabilities introduced by decorator code |
| Closures and nested function capture (beyond 1 level) | Capture chain is not traced | May miss vulnerabilities where taint flows through nested closure variables |
| Callback registration and invocation | Event-driven flow is not modeled | May miss vulnerabilities in callback-based architectures |
| Generator yield values | Yield-based data flow is not modeled | May miss vulnerabilities in generator pipelines |
| Comprehension internal flow | Comprehension variables are not tracked as taint intermediaries | May miss vulnerabilities in comprehension-based data transformation |
| `functools.partial` binding | Partial application is not modeled | May miss vulnerabilities where taint is bound through partial |
| Async/await flow | Coroutine data flow is not modeled | May miss vulnerabilities in async code paths |
| Class inheritance and MRO | Only direct class name resolution; no MRO traversal | May miss vulnerabilities in inherited methods |
| `super()` calls | Not modeled | May miss vulnerabilities in parent class method overrides |
| Property descriptors (`@property`) | Not modeled as data flow | May miss vulnerabilities in property access |
| Context manager `__enter__`/`__exit__` return values | Not modeled | May miss vulnerabilities in context manager return value flow |
| Exception-based control flow | Exception propagation is not modeled (see §4.8) | May miss vulnerabilities where taint flows through caught exceptions |

### 4.8 Exception-Based Taint and Sanitizer Bypass (Known Limitation)

v1 does not model exception-based taint propagation. A sanitizer like `int(var)` raises `ValueError` on invalid input. In the normal control flow path, the taint is cleared — `int()` produces a clean integer or the program crashes. However, if the calling code catches the exception and continues using the original tainted string value, that bypass path is invisible to v1.

v1 treats all recognized sanitizers as absolute barriers on the normal path. This is a sound over-approximation for the sanitized path (no false negatives on the bypass) but an unsound under-approximation for the bypass path (may miss real vulnerabilities where exception handling creates a bypass). This trade-off is documented as a known v1 limitation. v2 may add exception-aware taint propagation.

The sanitizer taxonomy (§9.3) distinguishes between **strong sanitizers** (parameterized queries, `shlex.quote`, `hmac.compare_digest`) and **weak sanitizers** (type coercion, regex validation). Both are treated as absolute barriers in v1, but the bundle records which type was encountered so a human reviewer can assess whether the barrier is genuinely absolute.

### 4.9 Sink Metadata Extraction

During taint analysis, the mapper extracts metadata from sink expressions that templates need for precondition checking:

```python
@dataclass
class SinkMetadata:
    """Metadata extracted from the sink expression during taint analysis.
    Populated by the language frontend's sink extractor."""
    shell_enabled: bool | None
        # True if the sink is subprocess.call/Popen with shell=True
        # False if shell=False is explicitly set
        # None if not applicable (e.g., SQL sinks)
    query_type: str | None
        # "SELECT", "INSERT", "UPDATE", "DELETE" for SQL sinks
        # None for non-SQL sinks
    template_engine: str | None
        # "jinja2" for Jinja2 template sinks
        # None for non-template sinks
    is_code_exec: bool | None
        # True if the sink is eval() or exec()
        # False if the sink is a shell command (os.system, subprocess)
        # None if not applicable
```

The `shell_enabled` field is populated by inspecting the AST of the sink expression. For `subprocess.call(cmd, shell=True)`, `shell_enabled=True`. For `subprocess.call([cmd, arg])` without `shell=True`, `shell_enabled=False`. For `os.system(cmd)`, `os.popen(cmd)`, `shell_enabled=True` by default (these are inherently shell-enabled).

The `is_code_exec` field distinguishes `eval()`/`exec()` sinks from shell command sinks. For `eval(var)` and `exec(var)`, `is_code_exec=True` and `shell_enabled=True` (code execution is inherently dangerous). For `os.system(var)`, `is_code_exec=False` and `shell_enabled=True`. This distinction enables template selection: `code_injection_exec` handles `is_code_exec=True` sinks; `command_injection_echo` handles `is_code_exec=False` and `shell_enabled=True` sinks.

The `query_type` field is populated by inspecting the SQL query string in the sink expression.

### 4.10 Defect Condition

If the mapper cannot trace a call from `app.py` to a function defined in `db.py` through a resolved import edge, the analysis core is defective and the build has failed its primary purpose. Single-file pattern matching — finding a sink in a file and searching for a source in the same file — is explicitly a defect, not a degraded mode.

---

## 5. Stage 2 — Candidate Generation and SDK Convergence

### 5.1 Candidate Generation

From the cross-file data-flow graph, the candidate generator enumerates paths from untrusted sources to dangerous sinks. Each path becomes a `VulnerabilityCandidate`:

```python
@dataclass
class VulnerabilityCandidate:
    id: str                          # UUID4
    exploit_class: str               # "sql_injection", "command_injection", "code_injection", etc.
    source: ProgramPoint             # file, line, column, expression
    sink: ProgramPoint
    taint_path: list[ProgramPoint]   # ordered traversal, may span files
    sanitizers_on_path: list[ProgramPoint]
    sanitizer_bypassed: bool         # true if a bypass path exists
    cross_file: bool                 # true if path spans ≥2 files
    sink_metadata: SinkMetadata      # shell_enabled, query_type, is_code_exec, etc. (§4.9)
    source_kind: str                 # detected source kind: "http_param", "cli_arg", etc.
    source_is_parameter: bool        # True if source root is a function parameter
    source_module: str               # module containing the source (for adapter)
    source_function: str             # function containing the source (for adapter)
    sink_module: str                 # module containing the sink (for adapter)
    sink_function: str               # function containing the sink (for adapter)

@dataclass
class ProgramPoint:
    file: str
    line: int
    column: int
    expression: str
    function: str                    # the function containing this point
```

Deduplication: identical `(source, sink, path)` triples collapse to one candidate. Multiple distinct paths between the same source-sink pair remain separate candidates.

### 5.2 SDK Convergence — The Analysis Gate

Each candidate is submitted to the `claudopus` SDK for cross-lineage adversarial convergence via the `ConvergenceClient` protocol (§3.5). The client — real SDK or mock — routes each candidate to independently trained models from distinct trainer lineages that each judge whether the candidate represents a genuine, exploitable vulnerability. A candidate advances **only if all participating lineages agree** it is exploitable.

Candidates that fail convergence are **dropped entirely** — they are not promoted to proof execution, and they do not receive the `UNVERIFIED` label. The `UNVERIFIED` designation is reserved exclusively for candidates that pass convergence but fail the sandbox proof.

Any dissent or abstention — including `LineageUnavailableError` or `ConvergenceTimeoutError` — drops the candidate. The build does not override this.

### 5.3 `taint_candidate_dict` — SDK Input Schema

The `convergence.py` adapter constructs a `taint_candidate_dict` from each `VulnerabilityCandidate` and passes it to the SDK's `judge` method. The schema is:

```python
taint_candidate_dict = {
    "id": str,
    "exploit_class": str,
    "source": {
        "file": str, "line": int, "column": int,
        "expression": str, "kind": str,
    },
    "sink": {
        "file": str, "line": int, "column": int,
        "expression": str, "kind": str,
    },
    "taint_path": [
        {"file": str, "line": int, "column": int,
         "expression": str, "function": str}
    ],
    "sanitizers_on_path": [
        {"file": str, "line": int, "column": int,
         "expression": str, "function": str}
    ],
    "sanitizer_bypassed": bool,
    "cross_file": bool,
}
```

The mapping is a direct field-to-field serialization with no transformation except adding the `kind` fields. The `sink_metadata`, `source_kind`, `source_is_parameter`, and module/function fields are NOT included — they are used only by the PoC generator, not by the SDK.

### 5.4 Convergence Result

```python
@dataclass
class ConvergenceResult:
    candidate_id: str
    agreed: bool
    lineages_judged: tuple[str, ...]
    per_lineage: dict[str, LineageVerdict]
    rationale: str

@dataclass
class LineageVerdict:
    lineage_id: str
    judgment: str                         # "exploitable", "not_exploitable", "abstain"
    confidence: float
    reasoning: str
```

Only candidates where `agreed == True` proceed to Stage 3. The convergence evidence is attached to the candidate record and included in the signed bundle's provenance section. The adapter also calls `claudopus.trace.last(verdict)` to obtain a `TraceRecord` for auditability.

### 5.5 Convergence Wrapper Contract

The `convergence.py` module:
1. Receives a `VulnerabilityCandidate` and a `ConvergenceClient` (injected by the pipeline).
2. Serializes the candidate into `taint_candidate_dict` per §5.3.
3. Calls `client.judge(candidate=taint_candidate_dict, lineages=..., require_agreement="all", on_disagreement="reject")`.
4. If the verdict is `agreed`, calls `client.trace_last(verdict)` to obtain the trace record.
5. Returns a `ConvergenceResult` with the verdict and trace attached.

The module contains no scoring thresholds, no prompt text, and no lineage configuration. All convergence semantics live in the `claudopus` SDK (or the mock for CI).

---

## 6. Stage 3 — Proof Execution

### 6.1 Objective

For every candidate that survives convergence, generate the smallest possible proof-of-concept using a deterministic template and a source-kind-aware adapter, execute it inside an isolated Docker sandbox against the operator's own code, and confirm a sentinel differential. The differential — sentinel present in the exploit run, absent in the control run — constitutes the proof. No other form of evidence is accepted.

### 6.2 Source Adapter System

The PoC generator uses a **source adapter** to map each detected source kind to a concrete harness injection strategy. This replaces the naive global-variable monkey-patching approach from prior revisions.

**Why adapters are necessary:** Python web frameworks use different patterns for accessing untrusted input:
- **Flask:** `request` is a thread-local proxy imported from `flask`. The correct approach is Flask's test request context: `with app.test_request_context('/?q=<payload>'): handler()`. **The adapter creates its own minimal Flask app** (`Flask(__name__)`) for the test request context. This works because Flask's `request` object is a `LocalProxy` that looks up the request from the current request context, which is thread-local. Any Flask app's `test_request_context()` pushes a request context that makes `request` accessible. The handler does NOT need to be a registered route on the adapter's app — it just needs a request context to be active when it accesses `flask.request`. The target's own Flask app object is not needed.
- **Django/generic function param:** `request` is passed as a function parameter to view functions. The harness creates a mock request object and passes it as an argument: `handler(mock_request)`.
- **CLI args (`sys.argv` only):** The harness sets `sys.argv` before calling the handler. Only direct `sys.argv` indexing is supported. `argparse`-based sources where the parsed namespace is accessed are NOT supported in v1 — the adapter cannot infer how to invoke the parsing function or provide required flags.
- **Environment variables:** `os.environ`. The harness sets the environment variable before calling the handler.
- **Function parameters (generic):** The source root is a function parameter. The harness creates a mock object and passes it as an argument.

**Registered adapters (v1):**

| Adapter | Kind | Priority | Detection Criteria | Injection Strategy |
|---------|------|----------|-------------------|-------------------|
| `FlaskRequestParamAdapter` | `http_param_flask` | 100 | Source expression contains `request.args`, `request.form`, `request.json`, or `flask.request`; source root `request` is NOT a function parameter | Creates a minimal `Flask(__name__)` app and uses `test_request_context` to set query parameters |
| `FlaskRequestBodyAdapter` | `http_body_flask` | 100 | Source expression contains `request.json` or `request.data`; source root is NOT a function parameter | Creates a minimal Flask app and uses `test_request_context` with JSON body |
| `FunctionParamRequestAdapter` | `http_param_func` | 90 | Source expression contains `.args.get(` or `.GET.get(`; source root IS a function parameter | Creates a mock request object with `.args.get()` / `.GET.get()` returning the payload, passes it as an argument |
| `CLIArgAdapter` | `cli_arg` | 80 | Source kind is `cli_arg`; source expression contains `sys.argv` (direct indexing only, NOT `argparse` namespace access) | Sets `sys.argv = ['prog', '<payload>']` before importing and calling the handler |
| `EnvVarAdapter` | `env_var` | 80 | Source kind is `env_var`; source expression contains `os.environ.get` or `os.getenv` | Sets `os.environ['VAR_NAME'] = '<payload>'` before importing and calling the handler |
| `FileReadAdapter` | `file_read` | 80 | Source kind is `file_read`; source expression contains `open(` or `read_text(` | Creates a sentinel file at a known path and sets the file path argument to point to it |
| `UserInputAdapter` | `user_input` | 80 | Source kind is `user_input`; source expression contains `input(` | Monkey-patches `builtins.input` to return the payload |
| `GenericFunctionParamAdapter` | `generic_param` | 0 | Fallback: source root is a function parameter but no specific adapter matches | Creates a string mock and passes it as the corresponding function argument |

**Adapter selection algorithm (deterministic):**
1. From the `VulnerabilityCandidate`, extract `source_kind`, `source_is_parameter`, and the source expression.
2. Filter registered adapters to those where `can_handle()` returns `True`.
3. Sort matching adapters by `priority` descending (stable sort preserves registration order for ties).
4. Select the first adapter in the sorted list.
5. If no adapter matches, the candidate is marked `UNVERIFIED (no_source_adapter)` and does not proceed to harness generation.

**Concrete example — `FunctionParamRequestAdapter` (used by the acceptance fixture):**

The acceptance fixture's `handle_search(request)` function receives `request` as a parameter. The adapter detects that `request.args.get('q')` is in the source expression and that `request` is a function parameter (not a module-level import). It generates:

```python
# generate_setup() output for exploit run:
class _MockArgs:
    @staticmethod
    def get(key, default=''):
        if key == 'q':
            return "' UNION SELECT 'SENTINEL_VALUE' --"
        return default

class _MockRequest:
    args = _MockArgs()

# generate_invocation() output:
import app
result = app.handle_search(_MockRequest())
```

**Concrete example — `FlaskRequestParamAdapter`:**

For a Flask app where `request` is a module-level import:

```python
# generate_setup() output:
from flask import Flask
_test_app = Flask(__name__)
_test_app.config['TESTING'] = True

# generate_invocation() output:
with _test_app.test_request_context('/?q=%27%20UNION%20SELECT%20%27SENTINEL_VALUE%27%20--'):
    import app
    result = app.handle_search()
```

The adapter creates its own minimal Flask app. It does NOT attempt to discover the target's Flask app object — this is by design, not an omission. Flask's `request` proxy is thread-local and works with any app's request context.

### 6.3 PoC Generation — Template System

The PoC generator is a **bounded template system**, not a general-purpose exploit synthesizer. Each exploit class has one or more registered templates. Each template declares preconditions (both syntactic and environmental), and if no template's preconditions match a candidate, the candidate is marked `UNVERIFIED (no_template_coverage)`.

**Template interface:**

```python
class PoCTemplate(Protocol):
    name: str
    exploit_class: str

    def preconditions(self, candidate: VulnerabilityCandidate) -> bool: ...
    def environmental_preconditions(
        self, candidate: VulnerabilityCandidate, sandbox_env: SandboxEnvironment
    ) -> bool: ...
    def generate_exploit(
        self, candidate: VulnerabilityCandidate, sentinel: str, adapter: SourceAdapter
    ) -> str: ...
    def generate_control(
        self, candidate: VulnerabilityCandidate, sentinel: str, adapter: SourceAdapter
    ) -> str: ...
    def sentinel_channels(self) -> list[str]: ...
```

**SandboxEnvironment (used by `environmental_preconditions`):**

```python
@dataclass
class SandboxEnvironment:
    """Describes what is available in the sandbox container.
    Populated by the environment probe (§6.14) after image build."""
    python_version: str
    installed_packages: set[str]     # from pip list in the container
    has_sqlite: bool                 # True if sqlite3 is importable
    network_available: bool          # False in v1 (--network none)
    writable_paths: list[str]        # ["/repo", "/tmp", "/work"]
```

**Template selection algorithm:**
1. For a given candidate, iterate registered templates for the candidate's `exploit_class`.
2. Call `preconditions(candidate)` — checks syntactic patterns and sink metadata.
3. For templates that pass syntactic preconditions,call `environmental_preconditions(candidate, sandbox_env)`.
4. If exactly one template passes both checks, use it.
5. If multiple templates pass, use the first in registration order (deterministic).
6. If no template passes syntactic preconditions, candidate → `UNVERIFIED (no_template_coverage)`.
7. If a template passes syntactic but fails environmental preconditions, candidate → `UNVERIFIED (environmental_incompatibility)` with details.

### 6.4 Registered Templates (v1)

Seven templates are registered. Each has a complete harness design in §6.5–§6.11.

| Template Name | Exploit Class | Syntactic Preconditions | Environmental Preconditions | Sentinel Channel |
|---------------|--------------|------------------------|----------------------------|------------------|
| `sql_injection_read` | sql_injection | `sink_metadata.query_type == "SELECT"`; sink expression matches f-string or string concatenation; containing function has a return statement | `sandbox_env.has_sqlite is True` OR target database is file-based SQLite | stdout |
| `command_injection_echo` | command_injection | `sink_metadata.shell_enabled is True` AND `sink_metadata.is_code_exec is False`; sink is `os.system`, `subprocess.call(shell=True)`, `subprocess.Popen(shell=True)`, or `os.popen` | None specific | stdout |
| `code_injection_exec` | code_injection | `sink_metadata.is_code_exec is True`; sink is `eval(var)` or `exec(var)` | None specific | stdout |
| `path_traversal_read` | path_traversal | Sink is `open()` or `Path()` with user-controlled path argument | Sentinel file can be pre-placed at `/tmp/sentinel-target-{id}` in container | stdout |
| `deserialization_pickle` | unsafe_deserialization | Sink is `pickle.loads`, `yaml.load` (without SafeLoader), or `marshal.loads` with tainted argument | For `marshal.loads`: target code must subsequently `exec()` the result | file at `/tmp/sentinel-{id}` |
| `template_injection_jinja2` | template_injection | `sink_metadata.template_engine == "jinja2"`; sink is `render_template_string`, `jinja2.Environment.from_string`, or `jinja2.Template` | `jinja2` in `sandbox_env.installed_packages` | stdout |
| `auth_bypass_direct` | auth_bypass | Sink is direct `==` comparison of user-supplied value to a hardcoded constant (not `hmac.compare_digest`); hardcoded value is extractable from AST | None specific | stdout |

**Critical distinction — `command_injection_echo` vs `code_injection_exec`:**

The `command_injection_echo` template's `preconditions()` explicitly checks `sink_metadata.is_code_exec is False`. If the sink is `eval()` or `exec()`, `is_code_exec` is `True`, and this template does NOT match. The `code_injection_exec` template handles those sinks with a Python-expression payload (`print("{sentinel}")`), not a shell command (`echo {sentinel}`). This prevents the fatal mismatch where a shell-chaining payload is generated for a Python code-execution sink.

**Explicitly deferred to v2 (no v1 template):**

| Exploit Class | Why Deferred |
|---------------|-------------|
| SSRF | Requires bridge network provisioning, mock HTTP server lifecycle, and per-candidate network policy — cannot be safely specified within v1's `--network none` sandbox posture. See §6.12. |
| Race / TOCTOU | Requires timing-sensitive harness generation with concurrent thread/process coordination. |
| Logic flaw | By definition application-specific; no general template can capture the exploit logic. |
| Blind SQL injection | Sentinel cannot be observed through defined channels. Time-based and boolean-based blind techniques require fundamentally different proof infrastructure. See §6.10. |
| Blind command injection | Sentinel may not surface if the command output is discarded or redirected. |
| SQL injection (write) | Target table name extraction from INSERT/UPDATE/DELETE is fragile. Read-back verification requires schema inference. Deferred to v2. |

### 6.5 Template Detail — SQL Injection Read (Acceptance Fixture Template)

This is the template used by the acceptance test (§12). It demonstrates how templates integrate with source adapters.

**Syntactic preconditions:**
- `candidate.exploit_class == "sql_injection"`
- `candidate.sink_metadata.query_type == "SELECT"`
- Sink expression matches regex `\.execute\s*\(\s*f["'].*SELECT` or `\.execute\s*\(\s*["'].*SELECT.*\+`
- The function containing the sink has a return statement that returns the query results

**Environmental preconditions:**
- `sandbox_env.has_sqlite is True` OR the target code's database connection string resolves to a file path

**Substitution variables (extracted from candidate):**
- `{repo_path}` → `/repo`
- `{source_module}` → `candidate.source_module`
- `{handler_function}` → `candidate.source_function`
- `{source_param_name}` → extracted from the source expression by parsing
- `{sink_module}` → `candidate.sink_module`
- `{sink_function}` → `candidate.sink_function`
- `{sentinel}` → the generated sentinel value

**Harness structure (exploit):**
```python
#!/usr/bin/env python3
"""PoC exploit — sql_injection_read template."""
import sys, os
sys.path.insert(0, "/repo")

# --- Source adapter injection (FunctionParamRequestAdapter) ---
class _MockArgs:
    @staticmethod
    def get(key, default=''):
        if key == '{source_param_name}':
            return f"' UNION SELECT '{sentinel}' --"
        return default

class _MockRequest:
    args = _MockArgs()

# --- Pre-import setup (compat-patch if provided) ---

# --- Import target ---
import {source_module}

# --- Invoke vulnerable function ---
result = {source_module}.{handler_function}(_MockRequest())

# --- Sentinel check ---
SENTINEL = "{sentinel}"
if SENTINEL in str(result):
    print(SENTINEL)
```

**Harness structure (control):**
```python
#!/usr/bin/env python3
"""PoC control — sql_injection_read template."""
import sys
sys.path.insert(0, "/repo")

class _MockArgs:
    @staticmethod
    def get(key, default=''):
        if key == '{source_param_name}':
            return "benign_search_term"
        return default

class _MockRequest:
    args = _MockArgs()

import {source_module}

result = {source_module}.{handler_function}(_MockRequest())

SENTINEL = "{sentinel}"
if SENTINEL in str(result):
    print(SENTINEL)  # Should NOT print
```

**Sentinel channel:** `stdout`

**Note on return-value dependency:** The template requires the sink's containing function to return query results. If the sentinel does not appear in the return value (e.g., results are paginated or wrapped), the harness's `SENTINEL in str(result)` check fails, and the candidate is marked `UNVERIFIED (exploit_failed)`. This is an honest v1 limitation.

### 6.6 Template Detail — Command Injection Echo

**Syntactic preconditions:**
- `candidate.exploit_class == "command_injection"`
- `candidate.sink_metadata.shell_enabled is True`
- `candidate.sink_metadata.is_code_exec is False` — excludes `eval`/`exec` sinks
- Sink is `os.system`, `subprocess.call(shell=True)`, `subprocess.Popen(shell=True)`, or `os.popen`

**Environmental preconditions:** None specific — no external service needed.

**Substitution variables:**
- `{repo_path}`, `{source_module}`, `{handler_function}`, `{sentinel}` — as in §6.5
- `{sink_module}`, `{sink_function}` — for direct invocation if the source function is separate from the sink function

**Harness structure (exploit):**
```python
#!/usr/bin/env python3
"""PoC exploit — command_injection_echo template."""
import sys, os
sys.path.insert(0, "/repo")

# --- Source adapter injection (GenericFunctionParamAdapter) ---
# (For a function-param source, the payload is passed as argument)

# --- Import target ---
import {source_module}

# --- Invoke vulnerable function ---
# The payload chains: benign_input; echo {sentinel}
_payload = "test; echo {sentinel}"
result = {source_module}.{handler_function}(_payload)

# --- Sentinel check ---
# os.system output goes to stdout; the harness captures it.
# The sentinel appears in stdout because echo prints it.
# No explicit check needed — the sentinel channel is stdout.
print("__HARNESS_DONE__")
```

**Harness structure (control):**
```python
#!/usr/bin/env python3
"""PoC control — command_injection_echo template."""
import sys, os
sys.path.insert(0, "/repo")

import {source_module}

_payload = "benign_input"
result = {source_module}.{handler_function}(_payload)

print("__HARNESS_DONE__")
```

**Sentinel channel:** `stdout` — the sentinel appears in stdout because `echo {sentinel}` is executed by the shell. The harness does not need to check explicitly; the sentinel observer scans all captured stdout for the sentinel string.

**How the sentinel surfaces:** When the vulnerable function does `os.system(f"echo {user_input}")` with `user_input = "test; echo {sentinel}"`, the shell executes `echo test; echo {sentinel}`, printing `test` and then the sentinel to stdout. The control run uses `"benign_input"`, so the shell only prints `benign_input` — no sentinel. The differential holds.

### 6.7 Template Detail — Code Injection Exec

This template handles `eval()` and `exec()` sinks — Python code execution, not shell command execution. The payload is a Python expression, not a shell command.

**Syntactic preconditions:**
- `candidate.exploit_class == "code_injection"`
- `candidate.sink_metadata.is_code_exec is True`
- Sink is `eval(var)` or `exec(var)`

**Environmental preconditions:** None specific.

**Harness structure (exploit):**
```python
#!/usr/bin/env python3
"""PoC exploit — code_injection_exec template."""
import sys, os
sys.path.insert(0, "/repo")

# --- Source adapter injection ---
# (Payload is a Python expression that prints the sentinel)

# --- Import target ---
import {source_module}

# --- Invoke vulnerable function ---
# The payload is a Python expression: print("{sentinel}")
# When the target does eval(user_input), this executes print("{sentinel}")
_payload = 'print("{sentinel}")'
result = {source_module}.{handler_function}(_payload)

print("__HARNESS_DONE__")
```

**Harness structure (control):**
```python
#!/usr/bin/env python3
"""PoC control — code_injection_exec template."""
import sys, os
sys.path.insert(0, "/repo")

import {source_module}

_payload = '42'
result = {source_module}.{handler_function}(_payload)

print("__HARNESS_DONE__")
```

**Sentinel channel:** `stdout` — when the target does `eval('print("{sentinel}")')`, Python executes `print("{sentinel}")`, writing the sentinel to stdout. The control run uses `'42'` (a benign Python expression), so `eval('42')` returns `42` and prints nothing. The differential holds.

**Why this is separate from `command_injection_echo`:** The shell template uses `echo {sentinel}` (a shell command). If this payload were fed to `eval()`, Python would try to evaluate `echo SENTINEL` as a Python expression, raising `NameError: name 'echo' is not defined`. The code injection template uses `print("{sentinel}")` (a Python expression), which is valid for `eval()` and `exec()`.

### 6.8 Template Detail — Path Traversal Read

**Syntactic preconditions:**
- `candidate.exploit_class == "path_traversal"`
- Sink is `open()` or `Path()` with user-controlled path argument

**Environmental preconditions:**
- Sentinel file can be pre-placed at `/tmp/sentinel-target-{id}` in the container. This is verified by checking that `/tmp` is in `sandbox_env.writable_paths`.

**Substitution variables:**
- `{repo_path}`, `{source_module}`, `{handler_function}`, `{sentinel}` — as in §6.5
- `{sentinel_file_path}` → `/tmp/sentinel-target-{candidate_id}`

**Pre-proof sentinel file placement:** Before the exploit harness runs, the proof oracle writes the sentinel value to `{sentinel_file_path}` inside the container. This is done as a Docker `exec` command after container start but before harness execution: `docker exec <container> sh -c 'echo -n {sentinel} > /tmp/sentinel-target-{id}'`. The control container does NOT receive this file — the file is placed only in the exploit container.

**Harness structure (exploit):**
```python
#!/usr/bin/env python3
"""PoC exploit — path_traversal_read template."""
import sys, os
sys.path.insert(0, "/repo")

# --- Source adapter injection (FunctionParamRequestAdapter) ---
class _MockArgs:
    @staticmethod
    def get(key, default=''):
        if key == 'file':
            # Path traversal: ../../tmp/sentinel-target-{id}
            return "../../../../tmp/sentinel-target-{candidate_id}"
        return default

class _MockRequest:
    args = _MockArgs()

# --- Import target ---
import {source_module}

# --- Invoke vulnerable function ---
# The target does: open(f'/data/{path}').read()
# With path = ../../../../tmp/sentinel-target-{id}
# This resolves to /tmp/sentinel-target-{id}
result = {source_module}.{handler_function}(_MockRequest())

# --- Sentinel check ---
SENTINEL = "{sentinel}"
if SENTINEL in str(result):
    print(SENTINEL)
```

**Harness structure (control):**
```python
#!/usr/bin/env python3
"""PoC control — path_traversal_read template."""
import sys, os
sys.path.insert(0, "/repo")

class _MockArgs:
    @staticmethod
    def get(key, default=''):
        if key == 'file':
            return "normal_file.txt"  # benign path
        return default

class _MockRequest:
    args = _MockArgs()

import {source_module}

result = {source_module}.{handler_function}(_MockRequest())

SENTINEL = "{sentinel}"
if SENTINEL in str(result):
    print(SENTINEL)  # Should NOT print — benign path does not traverse
```

**Sentinel channel:** `stdout` — the harness reads the sentinel file via the path traversal and prints the sentinel if found in the result. The control run uses a benign filename that does not traverse, so the sentinel file is not read.

**How the sentinel surfaces:** The vulnerable function does `open(f'/data/{user_path}').read()` where `user_path = '../../../../tmp/sentinel-target-{id}'`. Python's `open()` resolves the path, reading `/tmp/sentinel-target-{id}` (which contains the sentinel). The function returns the file contents, and the harness checks for the sentinel in the return value. The control run uses `"normal_file.txt"`, which resolves to `/data/normal_file.txt` — a file that either does not exist (causing `FileNotFoundError`, which is caught by the harness) or does not contain the sentinel.

**Harness error handling for control run:** If `open('/data/normal_file.txt')` raises `FileNotFoundError`, the harness catches it:
```python
try:
    result = {source_module}.{handler_function}(_MockRequest())
except Exception:
    result = ""
```
This ensures the control run does not crash — it simply produces no sentinel.

### 6.9 Template Detail — Deserialization (Class-Agnostic Payload)

The `deserialization_pickle` template uses a **class-agnostic payload** that does not need to know the target's expected class hierarchy. The payload exploits the pickle protocol's `__reduce__` mechanism, which executes arbitrary code during deserialization regardless of what class the target expects.

**Syntactic preconditions:**
- `candidate.exploit_class == "unsafe_deserialization"`
- Sink is `pickle.loads`, `yaml.load` (without SafeLoader), or `marshal.loads` with tainted argument

**Environmental preconditions:**
- For `marshal.loads`: target code must subsequently `exec()` the result (detected by AST analysis of the sink's containing function). If `exec()` is not called on the result, the template does not match.

**Exploit payload construction for `pickle.loads`:**

```python
import pickle

class _SentinelPayload:
    """Class-agnostic pickle payload. When unpickled, the __reduce__
    method is called by the pickle protocol regardless of what class
    the target code expects."""
    def __reduce__(self):
        return (exec, (
            "open('/tmp/sentinel-{candidate_id}', 'w').write('{sentinel}')",
        ))

malicious_data = pickle.dumps(_SentinelPayload())
```

When the target code does `pickle.loads(malicious_data)`, the pickle protocol calls `_SentinelPayload.__reduce__()`, which returns `(exec, ("open('/tmp/sentinel-...', 'w').write('...')",))`. The pickle protocol then calls `exec(...)`, writing the sentinel to `/tmp/sentinel-{candidate_id}`. This works regardless of what class the target expects because the pickle protocol always executes `__reduce__` during deserialization.

**Exploit payload for `yaml.load` (without SafeLoader):**

```yaml
!!python/object/apply:exec
args: ["open('/tmp/sentinel-{candidate_id}', 'w').write('{sentinel}')"]
```

**Exploit payload for `marshal.loads`:**

```python
import marshal
code = compile(
    "open('/tmp/sentinel-{candidate_id}', 'w').write('{sentinel}')",
    '<sentinel>', 'exec'
)
malicious_data = marshal.dumps(code)
```

**Important limitation for `marshal.loads`:** `marshal.loads` returns a code object but does NOT execute it. The target code must subsequently call `exec()` on the result. The template's `environmental_preconditions()` checks via AST analysis whether the deserialized object is passed to `exec()`.

**Harness structure (exploit):**
```python
#!/usr/bin/env python3
"""PoC exploit — deserialization_pickle template."""
import sys, os, pickle
sys.path.insert(0, "/repo")

# --- Source adapter injection (GenericFunctionParamAdapter) ---
# The payload is a file path; the source function reads the file and
# passes the bytes to pickle.loads.

# --- Create malicious pickle data file ---
class _SentinelPayload:
    def __reduce__(self):
        return (exec, (
            "open('/tmp/sentinel-{candidate_id}', 'w').write('{sentinel}')",
        ))

_malicious = pickle.dumps(_SentinelPayload())
with open('/tmp/malicious-{candidate_id}.pkl', 'wb') as f:
    f.write(_malicious)

# --- Import target ---
import {source_module}

# --- Invoke vulnerable function ---
# The source function reads a file and passes contents to pickle.loads
result = {source_module}.{handler_function}('/tmp/malicious-{candidate_id}.pkl')

print("__HARNESS_DONE__")
```

**Harness structure (control):**
```python
#!/usr/bin/env python3
"""PoC control — deserialization_pickle template."""
import sys, os, pickle
sys.path.insert(0, "/repo")

# Create a benign pickle file
_benign = pickle.dumps("benign_string")
with open('/tmp/benign-{candidate_id}.pkl', 'wb') as f:
    f.write(_benign)

import {source_module}

result = {source_module}.{handler_function}('/tmp/benign-{candidate_id}.pkl')

print("__HARNESS_DONE__")
```

**Sentinel channel:** `file at /tmp/sentinel-{id}` — the exploit run writes the sentinel to this file via the pickle `__reduce__` payload. The control run uses a benign pickle object that does not trigger `__reduce__`. The sentinel observer checks for the existence of `/tmp/sentinel-{id}` and whether it contains the sentinel value.

**Safety:** The payload uses `exec()` with a file-write operation, which is safe inside the sandbox (writable `/tmp`, no network, non-root user, seccomp). The payload does not use `os.system` or shell commands.

### 6.10 Template Detail — Template Injection Jinja2

**Syntactic preconditions:**
- `candidate.exploit_class == "template_injection"`
- `candidate.sink_metadata.template_engine == "jinja2"`
- Sink is `render_template_string`, `jinja2.Environment.from_string`, or `jinja2.Template`

**Environmental preconditions:**
- `jinja2` in `sandbox_env.installed_packages`

**Harness structure (exploit):**
```python
#!/usr/bin/env python3
"""PoC exploit — template_injection_jinja2 template."""
import sys, os
sys.path.insert(0, "/repo")

# --- Source adapter injection ---
# The payload is a Jinja2 SSTI expression that prints the sentinel.
# Using the built-in __class__ chain to reach os.system or print.
# Simplest payload: {{ "{sentinel}" }}
# This causes Jinja2 to render the sentinel string as output.

_payload = '{{ "{sentinel}" }}'

# --- Import target ---
import {source_module}

# --- Invoke vulnerable function ---
result = {source_module}.{handler_function}(_payload)

# --- Sentinel check ---
SENTINEL = "{sentinel}"
if SENTINEL in str(result):
    print(SENTINEL)
```

**Harness structure (control):**
```python
#!/usr/bin/env python3
"""PoC control — template_injection_jinja2 template."""
import sys, os
sys.path.insert(0, "/repo")

_payload = 'Hello World'  # benign template string

import {source_module}

result = {source_module}.{handler_function}(_payload)

SENTINEL = "{sentinel}"
if SENTINEL in str(result):
    print(SENTINEL)  # Should NOT print
```

**Sentinel channel:** `stdout` — the Jinja2 template `{{ "{sentinel}" }}` renders the sentinel string into the output. The vulnerable function returns the rendered template, and the harness checks for the sentinel. The control run uses a benign template string that does not contain the sentinel.

**Why `{{ "{sentinel}" }}` suffices:** If the target does `render_template_string(user_input)`, passing `{{ "{sentinel}" }}` causes Jinja2 to evaluate the expression `"{sentinel}"`, rendering the sentinel string into the output. This proves the user input is interpreted as a template — the definition of SSTI. More complex payloads (RCE via `__class__.__mro__` chains) are not needed for proof; demonstrating template evaluation is sufficient.

### 6.11 Template Detail — Auth Bypass Direct

**Syntactic preconditions:**
- `candidate.exploit_class == "auth_bypass"`
- Sink is direct `==` comparison of user-supplied value to a hardcoded constant (not `hmac.compare_digest`)
- The hardcoded value is extractable from AST — the comparison must be against a string literal, numeric literal, or a variable assigned a literal value in the same function scope.

**Environmental preconditions:** None specific.

**Substitution variables:**
- `{hardcoded_value}` → extracted from the AST by analyzing the `==` comparison. The extractor looks for the non-tainted operand of the `==` expression. If it is a literal (string, int), it extracts it directly. If it is a variable, it traces the variable's assignment in the same function scope to find the literal.

**Harness structure (exploit):**
```python
#!/usr/bin/env python3
"""PoC exploit — auth_bypass_direct template."""
import sys, os
sys.path.insert(0, "/repo")

# --- Source adapter injection ---
# The payload is the exact hardcoded value extracted from the AST.
# By supplying the correct secret, the auth check returns True.

_payload = {hardcoded_value!r}  # repr() to handle string/numeric

# --- Import target ---
import {source_module}

# --- Invoke vulnerable function ---
# The target function compares user_input == hardcoded_secret
# and returns True/False based on the comparison.
result = {source_module}.{handler_function}(_payload)

# --- Sentinel check ---
# If the auth function returns True (bypass succeeded), print sentinel.
SENTINEL = "{sentinel}"
if result is True or result == True:
    print(SENTINEL)
```

**Harness structure (control):**
```python
#!/usr/bin/env python3
"""PoC control — auth_bypass_direct template."""
import sys, os
sys.path.insert(0, "/repo")

# Provide an incorrect value — auth check should return False
_payload = "incorrect_value_that_does_not_match"

import {source_module}

result = {source_module}.{handler_function}(_payload)

SENTINEL = "{sentinel}"
if result is True or result == True:
    print(SENTINEL)  # Should NOT print — wrong value
```

**Sentinel channel:** `stdout` — the exploit harness supplies the exact hardcoded secret extracted from the AST, causing the `==` comparison to return `True`. The harness checks if the function returned `True` and prints the sentinel. The control run supplies an incorrect value, so the comparison returns `False` and the sentinel is not printed.

**How `{hardcoded_value}` is extracted:** The taint engine identifies the `==` comparison sink. The sink extractor examines the AST node for the comparison. If one operand is the tainted variable and the other is a literal, the literal is extracted. If the other operand is a variable, the extractor traces the variable's assignment within the same function scope. If the variable is assigned a literal value (e.g., `SECRET = "admin123"`), that literal is extracted. If the variable's value cannot be resolved to a literal (e.g., it is read from a file or environment variable), the template's `preconditions()` returns `False` — the hardcoded value is not extractable, and the candidate is marked `UNVERIFIED (no_template_coverage)`.

**Why this proves the vulnerability:** The vulnerability is that the auth check uses `==` (timing-attack-vulnerable, and the secret is in source code). The proof demonstrates that supplying the extracted secret bypasses the check. This proves two things: (1) the comparison is bypassable by anyone who reads the source, and (2) the secret is hardcoded in the code. The fix suggestion recommends replacing `==` with `hmac.compare_digest` and moving the secret to an environment variable.

### 6.12 Blind Vulnerabilities and Observable Sentinel Channels

v1 supports only vulnerabilities where the sentinel is observable through one of these channels:

1. **stdout** — the harness prints output containing the sentinel
2. **file at `/tmp/sentinel-{id}`** — the exploit writes a file containing the sentinel
3. **database query** — the harness reads back from a database and the sentinel appears in results

If a vulnerability cannot produce a sentinel observable through these channels, the candidate is marked `UNVERIFIED (no_observable_sentinel_channel)`. This is a v1 scope limitation. Blind SQL injection, blind command injection, out-of-band SSRF, and time-based attacks are explicitly out of v1 scope. v2 may add these channels.

### 6.13 SSRF — Deferred to v2

SSRF proofs require bridge network provisioning, a mock HTTP server, per-candidate network policy, and mock server lifecycle management. The v1 sandbox posture is `--network none` for all proofs. SSRF candidates are detected by the taint engine and pass through convergence, but at the proof stage they are marked `UNVERIFIED (exploit_class_deferred_v2)`.

### 6.14 Sandbox Environment Probe

After the sandbox image is built but before any proof harness runs, the proof oracle executes an **environment probe** inside the container to populate the `SandboxEnvironment` dataclass:

**Probe script (`env_probe.py`):**
```python
#!/usr/bin/env python3
"""Environment probe — runs inside the sandbox container after image build.
Outputs JSON to stdout describing the available environment."""
import json, sys

result = {
    "python_version": f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}",
    "installed_packages": [],
    "has_sqlite": False,
    "writable_paths": [],
}

# Check installed packages
try:
    import importlib.metadata
    result["installed_packages"] = sorted(
        dist.metadata["Name"].lower()
        for dist in importlib.metadata.distributions()
    )
except Exception:
    pass

# Check SQLite
try:
    import sqlite3
    result["has_sqlite"] = True
except ImportError:
    result["has_sqlite"] = False

# Check writable paths
import os, tempfile
for path in ["/repo", "/tmp", "/work"]:
    if os.path.isdir(path) and os.access(path, os.W_OK):
        result["writable_paths"].append(path)

print(json.dumps(result))
```

**Execution:** The probe runs as a Docker `exec` command inside the built image:
```
docker run --rm --network none --user nobody \
  --security-opt no-new-privileges:true --cap-drop ALL \
  <image> python /env_probe.py
```

The probe uses the same isolation posture as proof containers (§6.15). The output JSON is parsed by `env_probe.py` (the host-side module in `core/`) into a `SandboxEnvironment` dataclass. This dataclass is passed to each template's `environmental_preconditions()` call.

**Caching:** The probe result is cached per image build. If the same image is used for multiple candidates (which it is — all proofs against the same repo use the same image), the probe runs once after image build and the result is reused.

### 6.15 Compatibility Probe

**Problem:** Many real-world repositories execute expensive or network-dependent code at module import time. The sandbox's `--network none` policy will cause these imports to hang or crash. Without a mechanism to handle this, the proof phase fails for a large fraction of real-world code.

**Solution — Compatibility Probe:** Before attempting any proof, the proof oracle runs a **compatibility probe** for each unique source module in the candidate set:

1. Copy the repo into a container (same image used for proofs).
2. Run a probe script that attempts `import {source_module}` with a 30-second timeout.
3. If the import succeeds, the module is marked compatible.
4. If the import fails (timeout, crash, ImportError), the module is marked incompatible and the failure reason is recorded.

**Critical: Full sandbox isolation.** The compatibility probe runs in a container with **identical security posture** as proof containers:
- `--network none` — no network access
- `--memory 512m` — same memory limit
- `--cpus 1.0` — same CPU limit
- `--user nobody` — non-root
- `--security-opt no-new-privileges:true --cap-drop ALL` — seccomp + no privileges
- `--tmpfs /tmp:rw,noexec,nosuid,size=100m` — same tmpfs
- `--rm` — cleanup on exit

The probe container is a fresh, isolated container — no state shared with proof containers. An attacker providing a crafted repository cannot use the probe to exfiltrate data, perform network attacks, or consume excessive resources, because the probe runs under the same restrictions as all sandbox executions.

**Probe result caching:** The probe result is cached per-repo (not per-candidate). Candidates whose source module is incompatible are marked `UNVERIFIED (import_failure)` with the probe's error details.

**Pre-Import Hooks (`--compat-patch`):** The operator can provide a `--compat-patch <path>` flag pointing to a Python file that is executed inside the sandbox before importing the target module. This file can monkey-patch problematic dependencies:

```python
# compat_patch.py — example: suppress PostgreSQL connection at import time
import unittest.mock
with unittest.mock.patch('psycopg2.connect') as _mock:
    _mock.return_value = unittest.mock.MagicMock()
```

The compat patch is inserted into the harness source code between the source adapter's setup code and the target module import. If a compat patch is provided, the compatibility probe is re-run with the patch applied. If the import still fails, the candidate is `UNVERIFIED (import_failure)`.

**Out-of-scope declaration:** If a repository requires external services that cannot be mocked by a compat patch, the proof phase marks all candidates from that repository as `UNVERIFIED (environmental_incompatibility)`. This is an honest limitation — v1's sandbox is network-isolated and cannot provision external services.

### 6.16 Sandbox Specification

**Container image:** Derived from `python:3.11-slim`. The target repository is **copied** into `/repo` (writable) during image build. The repo is NOT bind-mounted from the host. Dependencies are installed from the repo's `requirements.txt` or `pyproject.toml` during image build.

**Why copy, not bind-mount read-only:** The target code does `sqlite3.connect('app.db')` which needs to write to the database file. On a read-only mount, `sqlite3.connect()` fails. The container itself is the isolation boundary — `--network none`, resource limits, non-root user, seccomp, and `--rm` cleanup provide containment without requiring a read-only repo mount.

**Image build error handling:** If the image build fails, the pipeline catches the error, logs the build output, and exits with code 1: `"Sandbox image build failed: <details>. Use --no-sandbox to skip proof execution."` No `UNVERIFIED` records are produced because no proof could be attempted.

**Network:** `--network none` for all v1 exploit classes.

**Filesystem:** Writable `/repo`, writable `/tmp` tmpfs (`--tmpfs /tmp:rw,noexec,nosuid,size=100m`), writable `/work` directory.

**Security:** Seccomp default profile, `--security-opt no-new-privileges:true`, `--cap-drop ALL`, non-root user (`--user nobody`).

**Resources:** 512 MB RAM, 1.0 CPU, 60-second wall-clock timeout per harness run (exploit or control). OOM or timeout marks the candidate `UNVERIFIED`.

**Isolation:** Each exploit/control pair runs in a fresh container. No container reuse. `--rm` on exit.

**Determinism:** `PYTHONHASHSEED=0` set in the container.

### 6.17 Sentinel Protocol

1. Generate a cryptographically random 64-character hex sentinel, unique per candidate.
2. **Sentinel leak test (pre-proof gate):** Before running the exploit, run the **control harness** and check that the sentinel does NOT appear in any captured channel. If the sentinel appears in the control run's output, the template is buggy and the candidate is marked `UNVERIFIED (sentinel_leak_in_control)`. The exploit run is not attempted.
3. **Exploit run:** Execute the exploit harness. Capture stdout, stderr, exit code, file writes under `/tmp`, and wall-clock duration. The run passes if the sentinel appears in any captured channel listed by the template's `sentinel_channels()`.
4. **Control run:** Execute the control harness in a fresh container. Capture identical artifacts. The run passes if the sentinel is absent from all captured channels.
5. **Differential verdict:**

```
finding_proven = sentinel_present(EXPLOIT) AND NOT sentinel_present(CONTROL)
```

Strict AND. Both-present and neither-present both fail.

| Outcome | Reason | Verdict |
|---------|-------|---------|
| Sentinel in exploit, absent in control | — | **PROVEN** |
| Sentinel in both | `sentinel_not_differential` | UNVERIFIED |
| Sentinel in neither | `exploit_failed` | UNVERIFIED |
| Exploit crashed | `exploit_crash` | UNVERIFIED |
| Exploit timed out | `exploit_timeout` | UNVERIFIED |
| Control crashed on benign input | `control_unexpected_exit` | UNVERIFIED |
| Sentinel in control pre-check | `sentinel_leak_in_control` | UNVERIFIED |
| Resource limit exceeded (OOM) | `resource_exhausted` | UNVERIFIED |
| No template matched | `no_template_coverage` | UNVERIFIED |
| Environmental preconditions failed | `environmental_incompatibility` | UNVERIFIED |
| Exploit class deferred to v2 | `exploit_class_deferred_v2` | UNVERIFIED |
| No source adapter matched | `no_source_adapter` | UNVERIFIED |
| Requires external database | `requires_external_database` | UNVERIFIED |
| Import failure in sandbox | `import_failure` | UNVERIFIED |
| No observable sentinel channel | `no_observable_sentinel_channel` | UNVERIFIED |

### 6.18 Execution Trace Capture

For each run (exploit and control), the sandbox captures:

```python
@dataclass
class SandboxRunResult:
    run_kind: str               # "exploit" or "control"
    status: str                 # "ok", "timeout", "crash", "oom"
    exit_code: int
    stdout: str                 # truncated to 1 MB
    stderr: str                 # truncated to 1 MB
    sentinel_observed: bool
    duration_ms: int
    files_written: list[str]    # paths under /tmp that were created
    image_digest: str           # Docker image SHA256
```

### 6.19 Proof Result

```python
@dataclass
class DifferentialProof:
    kind: str = "differential"
    verdict: str                # "proven" or "unverified"
    unverified_reason: str | None
    exploit_run: SandboxRunResult
    control_run: SandboxRunResult
    sentinel_hash: str          # SHA-256 of the sentinel value
    poc_exploit: str            # exploit harness source code (contains sentinel as literal)
    poc_control: str            # control harness source code (contains sentinel as literal)
    template_name: str
    adapter_name: str
```

The harness source code contains the sentinel as a literal string, enabling `deepaudit verify --re-run` to extract the sentinel and re-execute the proof.

---

## 7. Stage 4 — Signed Findings Bundle

### 7.1 Finding Types

The bundle supports two proof types, discriminated by the `reproduction.kind` field:

**Differential findings** (sandbox-proven):
```python
@dataclass
class ProvenFinding:
    finding_id: str
    exploit_class: str
    severity: str               # fixed per exploit class (§7.2)
    source: ProgramPoint
    sink: ProgramPoint
    cross_file_path: list[ProgramPoint]
    sanitizers_on_path: list[ProgramPoint]
    reproduction: DifferentialProof | StaticProof
    fix_suggestion: str         # text summary only; no auto-generated patch
    provenance: dict
```

**Static findings** (no sandbox execution — used for secrets-in-code):
```python
@dataclass
class StaticProof:
    kind: str = "static"
    verdict: str = "proven"
    evidence_description: str
    evidence_location: ProgramPoint
    pattern_matched: str
    pattern_id: str
```

### 7.2 Severity Assignment

v1 uses **fixed severities** per exploit class. No escalation conditions. The prior revision's "Critical if PoC demonstrates data exfiltration" was unverifiable and has been removed.

| Class | Severity | Rationale |
|-------|----------|-----------|
| SQL injection | High | Data exposure via injection; fixed severity, no escalation |
| Command injection | Critical | Shell execution with user input |
| Code injection | Critical | eval/exec with user input |
| Unsafe deserialization | Critical | Arbitrary code execution via deserialization |
| Template injection | High | SSTI; RCE possible but not always demonstrated |
| Path traversal | High | Arbitrary file read |
| Auth bypass | High | Authentication circumvention |
| Secrets in code | Medium | Hardcoded credentials; High if key pattern matches known active service |

### 7.3 Bundle Signing — RFC 8785 Canonicalization and Verification

The bundle is canonicalized using **RFC 8785 (JSON Canonicalization Scheme)**.

**Field exclusion order:** The `signature` field is removed from the bundle object before canonicalization. The canonicalization is applied to the resulting object. The signed payload SHA-256 is computed over the RFC 8785 canonical bytes. The signature is then computed over the same canonical bytes and added back as the `signature` field.

**Verification (`deepaudit verify <bundle>`):**
1. Remove the `signature` field from the bundle.
2. Re-canonicalize with RFC 8785.
3. Recompute the SHA-256 of the canonical bytes.
4. Check it against `signature.signed_payload_sha256`.
5. Verify the Ed25519 signature against the canonical bytes using the public key in `signature.public_key_b64`.
6. Extract the sentinel from the stored `poc_exploit` harness source code.
7. Compute SHA-256 of the extracted sentinel and check it against `reproduction.sentinel_hash`.
8. Validate internal consistency: `reproduction.exploit_run.sentinel_observed == True`, `reproduction.control_run.sentinel_observed == False`, `reproduction.differential == True`.

**Re-run verification (`deepaudit verify <bundle> --re-run <repo>`):**
1. Perform all steps from standard verification above.
2. Extract `poc_exploit` and `poc_control` from the bundle.
3. Build a fresh sandbox container with the specified repo copied in.
4. Execute both harnesses in separate containers.
5. Report whether the sentinel differential still holds.

The signing key is loaded from `DEEPAUDIT_SIGNING_KEY_PATH` or `--signing-key`. If no key is provided, the CLI auto-generates a keypair at `~/.config/deepaudit/signing.key` with `0600` permissions.

### 7.4 Findings Bundle Schema

```jsonc
{
  "schema_version": "1.0.0",
  "scan_id": "<uuid>",
  "started_at": "<iso8601>",
  "finished_at": "<iso8601>",
  "repo": {
    "path": "<repo path>",
    "language": "python",
    "files_scanned": 247,
    "tree_sitter_grammar": "tree-sitter-python"
  },
  "sdk": {
    "package": "claudopus",
    "version": "<resolved>",
    "lineages_used": ["lineage-A", "lineage-B"],
    "mock": false
  },
  "sandbox": {
    "image": "python:3.11-slim",
    "network": "none",
    "timeout_s": 60,
    "repo_mount": "copy"
  },
  "findings": [
    {
      "id": "<uuid>",
      "exploit_class": "sql_injection",
      "severity": "high",
      "source":     { "file": "app.py", "line": 42, "column": 15,
                      "expression": "request.args.get('q')",
                      "function": "handle_search" },
      "intermediate": [
        { "file": "db.py", "line": 17, "column": 4,
          "expression": "lookup_item(query)", "function": "search_raw" }
      ],
      "sink":       { "file": "db.py", "line": 88, "column": 12,
                      "expression": "cursor.execute(f\"SELECT ...\")",
                      "function": "search_raw" },
      "sanitizers_on_path": [],
      "cross_file": true,
      "convergence": {
        "agreed": true,
        "lineages_judged": ["lineage-A", "lineage-B"],
        "per_lineage": {},
        "rationale": "...",
        "trace": { "lineage": "...", "steps": [], "inputs_hash": "...", "outputs_hash": "..." }
      },
      "reproduction": {
        "kind": "differential",
        "verdict": "proven",
        "template_name": "sql_injection_read",
        "adapter_name": "FunctionParamRequestAdapter",
        "exploit_outcome":  { "exit_code": 0, "sentinel": true,
                              "stdout_tail": "...", "stderr_tail": "...",
                              "wall_clock_s": 0.21 },
        "control_outcome":  { "exit_code": 0, "sentinel": false,
                              "stdout_tail": "...", "stderr_tail": "...",
                              "wall_clock_s": 0.19 },
        "differential": true,
        "sentinel_hash": "sha256:...",
        "poc_exploit": "#!/usr/bin/env python3\n...",
        "poc_control": "#!/usr/bin/env python3\n...",
        "captured_trace": {
          "exploit_run": { "command": ["python", "/exploit.py"], "env": {},
                           "stdout_b64": "...", "stderr_b64": "...",
                           "sentinel_evidence": "..." },
          "control_run": { "command": ["python", "/control.py"], "env": {},
                           "stdout_b64": "...", "stderr_b64": "...",
                           "sentinel_evidence": null }
        }
      },
      "fix": {
        "summary": "Use parameterized queries in search_raw.",
        "references": ["CWE-89"]
      }
    }
  ],
  "static_findings": [
    {
      "id": "<uuid>",
      "exploit_class": "secrets_in_code",
      "severity": "medium",
      "source": { "file": "config.py", "line": 12, "column": 8,
                  "expression": "API_KEY = \"sk-...\"",
                  "function": "<module>" },
      "sink": null,
      "cross_file_path": [],
      "sanitizers_on_path": [],
      "cross_file": false,
      "convergence": null,
      "reproduction": {
        "kind": "static",
        "verdict": "proven",
        "evidence_description": "Hardcoded API key (AWS access key pattern)",
        "evidence_location": { "file": "config.py", "line": 12, "column": 8,
                               "expression": "API_KEY = \"AKIA...\"",
                               "function": "<module>" },
        "pattern_matched": "AKIA[0-9A-Z]{16}",
        "pattern_id": "aws_access_key_id"
      },
      "fix": {
        "summary": "Move secret to environment variable or secret manager.",
        "references": ["CWE-798"]
      }
    }
  ],
  "unverified": [],
  "signature": {
    "algorithm": "ed25519",
    "canonicalization": "RFC 8785",
    "public_key_b64": "...",
    "public_key_fingerprint": "sha256:...",
    "signature_b64": "...",
    "signed_payload_sha256": "..."
  }
}
```

**Changes from prior revisions:**
- `fix.patch_unified_diff` field removed. v1 provides text fix summaries only (`fix.summary`). Automatic patch generation is deferred to v2.
- `unverified` array is always present in the schema. It is an empty array `[]` when `--include-unverified` is not passed, and populated with diagnostic entries when the flag is passed. No conditional emission ambiguity.
- `static_findings` is a separate array with `convergence: null`.

### 7.5 Static Findings Pipeline (Secrets in Code)

Static findings follow a separate pipeline path that bypasses taint analysis, candidate generation, and convergence:

1. **Detection:** `static_scan.py` scans all `.py` files during Stage 1 for known secret patterns.
2. **Pattern registry:**

| Pattern ID | Regex | Description |
|------------|-------|-------------|
| `aws_access_key_id` | `AKIA[0-9A-Z]{16}` | AWS access key ID |
| `aws_secret_access_key` | `(aws_secret_access_key|aws_secret)\s*[=:]\s*["'][A-Za-z0-9/+=]{40}["']` | AWS secret access key |
| `google_api_key` | `AIza[0-9A-Za-z\-_]{35}` | Google API key |
| `github_token` | `gh[ps]_[A-Za-z0-9]{36}` | GitHub personal access token |
| `generic_api_key` | `(api_key|apikey|api-key)\s*[=:]\s*["'][^"']{20,}["']` | Generic API key (20+ chars) |
| `database_url` | `(postgres|postgresql|mysql|mongodb)://[^:\s]+:[^@\s]+@` | Database connection string with credentials |
| `private_key` | `-----BEGIN (RSA \|EC \|DSA )?PRIVATE KEY-----` | Private key block |

3. **Filtering:** Variable names containing `test`, `example`, `dummy`, `fake`, `sample` are excluded. Values that are obviously placeholders are excluded. Detections in `tests/`, `examples/`, `docs/` are flagged with lower severity.
4. **No convergence:** Static findings do NOT pass through `convergence.py`.
5. **Bundle assembly:** Static findings are placed in the `static_findings` array with `reproduction.kind = "static"` and `convergence = null`.

### 7.6 UNVERIFIED Records

The `unverified` array is always present in the bundle schema. When `--include-unverified` is passed, it is populated with diagnostic entries for candidates that passed convergence but failed the sandbox proof. When the flag is not passed, it is an empty array `[]`. These entries are never counted as findings and never appear in the `findings` array. The `unverified` entries do not contain exploit payloads.

---

## 8. The Substance Bar — Non-Negotiable Requirements

### 8.1 Pillar 1: Real Cross-File Taint

The analysis must trace a tainted value from an untrusted source to a dangerous sink across **file boundaries**, accounting for sanitizers on every path. The trace must include:

- The source location (file, line, expression).
- Every intermediate hop (file, line, function) the taint passes through.
- The sink location (file, line, expression).
- Every sanitizer on the path, with its location and whether it blocks or is bypassed.

**Explicitly unacceptable:** Matching a sink pattern in a file and searching for a source pattern in the same file. If the taint analysis is single-file pattern matching, the build has failed its core mission.

### 8.2 Pillar 2: Real Execution Oracle

A finding ships only if the generated PoC, executed in the Docker sandbox, produces the sentinel in the exploit run and does not produce it in the control run. Static findings (secrets in code) are the sole exception.

---

## 9. Exploit Class Catalog (Python v1)

### 9.1 Source Taxonomy

| Source Kind | Pattern Examples | Source Adapter |
|-------------|-----------------|----------------|
| HTTP parameter (Flask) | `flask.request.args`, `request.args.get(...)` where `request` is module-level import | `FlaskRequestParamAdapter` |
| HTTP parameter (function param) | `request.args.get(...)` where `request` is a function parameter | `FunctionParamRequestAdapter` |
| HTTP body (Flask) | `flask.request.json`, `request.data` | `FlaskRequestBodyAdapter` |
| CLI argument (sys.argv) | `sys.argv[1]`, `sys.argv` direct indexing | `CLIArgAdapter` |
| CLI argument (argparse) | `argparse` namespace access, `parser.parse_args()` | **NOT supported in v1** — detection excluded from CLIArgAdapter |
| Environment | `os.environ.get`, `os.getenv` | `EnvVarAdapter` |
| File read | `open(path).read()`, `pathlib.Path.read_text()` | `FileReadAdapter` |
| Network | `socket.recv()`, `httpx.get().text` | Deferred to v2 |
| User input | `input()` | `UserInputAdapter` |
| Generic function param | Fallback for any source that is a function parameter | `GenericFunctionParamAdapter` |

### 9.2 Sink Taxonomy

| Sink Class | Pattern Examples | v1 Template | Sink Metadata Extracted |
|------------|-----------------|-------------|------------------------|
| SQL execution | `cursor.execute(f"…{var}…")` | `sql_injection_read` | `query_type`: "SELECT" / etc. |
| Command execution (shell) | `os.system(var)`, `subprocess.call(var, shell=True)` | `command_injection_echo` | `shell_enabled`: True, `is_code_exec`: False |
| Command execution (no shell) | `subprocess.call([cmd, arg])` without `shell=True` | No v1 template | `shell_enabled`: False |
| Code execution | `eval(var)`, `exec(var)` | `code_injection_exec` | `shell_enabled`: True, `is_code_exec`: True |
| Unsafe deserialization | `pickle.loads(var)`, `yaml.load(var)` without SafeLoader | `deserialization_pickle` | None |
| Template injection | `render_template_string(var)` | `template_injection_jinja2` | `template_engine`: "jinja2" |
| Path operation | `open(user_path)` without canonicalization | `path_traversal_read` | None |
| Auth bypass | Direct `==` comparison to hardcoded secret | `auth_bypass_direct` | None |
| SSRF | `requests.get(user_url)` | **Deferred to v2** | None |
| Race / TOCTOU | File check-then-use | **Deferred to v2** | None |
| Logic flaw | Application-specific | **Deferred to v2** | None |
| Secrets in code | Hardcoded credentials | Static detection (no template) | None |

### 9.3 Sanitizer Taxonomy

| Sanitizer | Pattern Examples | Strength |
|-----------|-----------------|----------|
| SQL parameterization | `cursor.execute("…?", (var,))` | Strong |
| Shell quoting | `shlex.quote(var)`, `subprocess.call([cmd, arg])` without `shell=True` | Strong |
| Path canonicalization | `os.path.realpath(var)`, `Path(var).resolve()` with boundary check | Strong |
| HTML escaping | `html.escape(var)`, `markupsafe.escape(var)` | Strong |
| Cryptographic comparison | `hmac.compare_digest` | Strong |
| Input validation | Type coercion, regex validation | Weak (see §4.8) |

### 9.4 Extension Interface

New exploit classes are added by implementing a handler:

```python
class ExploitClassHandler(Protocol):
    exploit_class: str

    def generate_poc(self, candidate: VulnerabilityCandidate, sentinel: str, adapter: SourceAdapter) -> tuple[str, str]: ...
    def check_sentinel(self, run_result: SandboxRunResult, sentinel: str) -> bool: ...
    def suggest_fix(self, candidate: VulnerabilityCandidate) -> str: ...
```

The `suggest_fix()` method returns a text summary only. It does NOT generate a unified diff. Automatic patch generation is deferred to v2.

---

## 10. `claudopus_sdk_usage`

```yaml
claudopus_sdk_usage:
  package: claudopus
  import: "import claudopus"

  convergence:
    module: claudopus.convergence
    call: claudopus.convergence.judge(
      candidate=taint_candidate_dict,
      *,
      lineages=["lineage-A", "lineage-B"],
      require_agreement="all",
      on_disagreement="reject",
    )
    returns: claudopus.convergence.Verdict(
      agreed=bool,
      lineages_judged=tuple[str, ...],
      per_lineage=dict[str, claudopus.convergence.LineageVerdict],
      rationale=str,
    )

  trace:
    module: claudopus.trace
    call: claudopus.trace.last(verdict)
    returns: claudopus.trace.TraceRecord(
      lineage=str,
      steps=tuple[claudopus.trace.Step, ...],
      inputs_hash=str,
      outputs_hash=str,
    )

  errors:
    - claudopus.errors.LineageUnavailableError
    - claudopus.errors.ConvergenceTimeoutError
    - claudopus.errors.InvalidCandidateError

  taint_candidate_dict_schema:
    description: >
      The dict passed as `candidate=` to claudopus.convergence.judge.
    fields:
      id: str
      exploit_class: str
      source: {file: str, line: int, column: int, expression: str, kind: str}
      sink: {file: str, line: int, column: int, expression: str, kind: str}
      taint_path: list[{file: str, line: int, column: int, expression: str, function: str}]
      sanitizers_on_path: list[{file: str, line: int, column: int, expression: str, function: str}]
      sanitizer_bypassed: bool
      cross_file: bool

  forbidden:
    - claudopus.adversarial
    - claudopus.engine
    - claudopus.scoring
    - claudopus.prompts
    - claudopus.models
    - claudopus.training
    - any symbol not listed above

  version_pin: "claudopus>=1.0,<2.0"
  validation_rule: >
    Every identifier in this block must be validated verbatim against
    sdk/python/SDK_REFERENCE.md during the spec lint pass.
```

### 10.1 Convergence Agreement Rule

`require_agreement="all"` plus `on_disagreement="reject"` is the configuration that makes the SDK enforce cross-lineage agreement. Any dissent drops the candidate. The `findings[].convergence.lineages_judged` field must have length ≥ 2.

### 10.2 Adversarial Attack — Not Used in v1

v1 uses only `convergence.judge` with `require_agreement="all"`. The adversarial attack feature is available in the SDK but is not invoked.

### 10.3 Static Findings — No SDK Usage

Static findings do not invoke the SDK at all. They are detected by `static_scan.py` and routed directly to the bundle.

---

## 11. SDK Mock Interface for CI

### 11.1 Problem

The acceptance test requires convergence to pass candidates to proof. CI must be deterministic and self-contained.

### 11.2 MockConvergenceClient

```python
class MockConvergenceClient:
    def judge(self, candidate, *, lineages, require_agreement, on_disagreement):
        supported = {
            "sql_injection", "command_injection", "code_injection",
            "path_traversal", "unsafe_deserialization",
            "template_injection", "auth_bypass",
        }
        if (candidate["cross_file"] and
            candidate["exploit_class"] in supported and
            not candidate["sanitizer_bypassed"]):
            return ConvergenceResult(
                candidate_id=candidate["id"],
                agreed=True,
                lineages_judged=("mock-lineage-A", "mock-lineage-B"),
                per_lineage={
                    "mock-lineage-A": LineageVerdict(
                        "mock-lineage-A", "exploitable", 0.95,
                        "Mock: cross-file taint path with supported exploit class"
                    ),
                    "mock-lineage-B": LineageVerdict(
                        "mock-lineage-B", "exploitable", 0.92,
                        "Mock: cross-file taint path with supported exploit class"
                    ),
                },
                rationale="Mock convergence: cross-file taint path with supported exploit class",
            )
        return ConvergenceResult(
            candidate_id=candidate["id"],
            agreed=False,
            lineages_judged=("mock-lineage-A", "mock-lineage-B"),
            per_lineage={
                "mock-lineage-A": LineageVerdict(
                    "mock-lineage-A", "not_exploitable", 0.80,
                    "Mock: candidate does not meet convergence criteria"
                ),
                "mock-lineage-B": LineageVerdict(
                    "mock-lineage-B", "not_exploitable", 0.85,
                    "Mock: candidate does not meet convergence criteria"
                ),
            },
            rationale="Mock convergence: candidate rejected",
        )

    def trace_last(self, verdict):
        return TraceRecord(
            lineage="mock-lineage-A",
            steps=(),
            inputs_hash="mock-hash",
            outputs_hash="mock-hash",
        )
```

### 11.3 CI Configuration

The acceptance test runs with `--mock-sdk` by default. A separate integration test runs only when `DEEPAUDIT_REAL_SDK=1` is set.

---

## 12. Acceptance Test Fixture and Entry-Point Contract (Load-Bearing)

### 12.1 `run_deepaudit_scan` — Entry-Point Interface

```python
def run_deepaudit_scan(
    repo: Path,
    *,
    authorized: bool = False,
    mock_sdk: bool = False,
    output_path: Path | None = None,
    sandbox_image: str = "python:3.11-slim",
    sandbox_timeout: int = 60,
    scan_timeout: int = 1800,
    max_candidates: int = 200,
    severity_threshold: str = "low",
    config_path: Path | None = None,
    compat_patch: Path | None = None,
    no_sandbox: bool = False,
) -> ScanResult:
    """Run the full DeepAudit pipeline on a repository."""

@dataclass
class ScanResult:
    exit_code: int
    bundle: FindingsBundle | None
    bundle_path: Path | None
    summary: ScanSummary
    errors: list[str]

@dataclass
class ScanSummary:
    files_parsed: int
    files_failed: int
    candidates: int
    converged: int
    proven: int
    unverified: int
    static_findings: int
    bundle_path: str | None
    signature_fingerprint: str | None
```

### 12.2 Fixture Repository — SQL Injection (Primary Acceptance Fixture)

```
fixtures/acceptance_repo/
├── app.py          # SOURCE: untrusted HTTP input
├── sanitize.py     # SANITIZER: input escaping (third file)
├── db.py           # SINK: SQL execution
├── models.py       # data model (noise)
└── main.py         # entry point wiring
```

**app.py:**
```python
from sanitize import escape_query
from db import search_raw, search_safe

def handle_search(request):
    query = request.args.get('q', '')
    results_unsafe = search_raw(query)
    clean = escape_query(query)
    results_safe = search_safe(clean)
    return results_unsafe + results_safe
```

**sanitize.py:**
```python
def escape_query(value: str) -> str:
    return value.replace("'", "''")
```

**db.py:**
```python
import sqlite3

def search_raw(query: str):
    conn = sqlite3.connect('app.db')
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM items WHERE name = '{query}'")
    return cursor.fetchall()

def search_safe(query: str):
    conn = sqlite3.connect('app.db')
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM items WHERE name = ?", (query,))
    return cursor.fetchall()
```

**models.py:**
```python
class Item:
    def __init__(self, name, description):
        self.name = name
        self.description = description
```

**main.py:**
```python
from app import handle_search

if __name__ == '__main__':
    pass
```

**Database initialization:**
```python
# setup_db.py — run during image build
import sqlite3
conn = sqlite3.connect('/repo/app.db')
conn.execute('CREATE TABLE IF NOT EXISTS items (name TEXT, description TEXT)')
conn.execute("INSERT INTO items VALUES ('test', 'test item')")
conn.commit()
conn.close()
```

### 12.3 Why a Single-File / Regex Matcher Fails This Fixture

A regex scanner cannot trace taint across `app.py` → `db.py`. It either misses the finding (source is in a different file) or flags both `search_raw` and `search_safe` (cannot distinguish f-string interpolation from parameterization).

### 12.4 What DeepAudit Must Do

1. Catch the real flow: `request.args.get('q')` in `app.py` → `search_raw(query)` → `cursor.execute(f"...")` in `db.py`.
2. Not flag the sanitized path: taint through `escape_query()` in `sanitize.py` to `search_safe()` is blocked by the sanitizer.
3. Not flag the parameterized sink.
4. Select `FunctionParamRequestAdapter` (source is a function parameter).
5. Prove with `sql_injection_read` template + sentinel differential.
6. Emit signed bundle with one finding, zero false positives.

### 12.5 Machine-Checkable Assertions

```python
def test_acceptance_fixture():
    repo = Path("fixtures/acceptance_repo")
    result = run_deepaudit_scan(repo, authorized=True, mock_sdk=True)

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
    assert "search_raw" in finding.sink.expression

    for f in result.bundle.findings:
        assert "search_safe" not in f.sink.expression

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
```

### 12.6 Curated Vulnerability Repository Set

Four fixture repositories. The done condition requires ALL four to pass.

**Fixture 2 — Command Injection:**
```
fixtures/cmd_injection_repo/
├── handler.py     # SOURCE: function parameter
├── runner.py      # SINK: os.system
└── main.py        # wiring
```

**handler.py:**
```python
from runner import run_command

def handle_input(user_input: str):
    return run_command(user_input)
```

**runner.py:**
```python
import os

def run_command(cmd: str):
    return os.system(f"echo {cmd}")
```

**Assertions:** Exactly one finding, `exploit_class == "command_injection"`, `sink_metadata.shell_enabled is True`, `sink_metadata.is_code_exec is False`, `template_name == "command_injection_echo"`, adapter is `GenericFunctionParamAdapter`.

**Fixture 3 — Unsafe Deserialization:**
```
fixtures/deserialization_repo/
├── api.py         # SOURCE: file path parameter
├── loader.py      # SINK: pickle.loads
└── main.py        # wiring
```

**api.py:**
```python
from loader import load_data

def handle_upload(file_path: str):
    with open(file_path, 'rb') as f:
        data = f.read()
    return load_data(data)
```

**loader.py:**
```python
import pickle

def load_data(raw: bytes):
    return pickle.loads(raw)
```

**Assertions:** Exactly one finding, `exploit_class == "unsafe_deserialization"`, `template_name == "deserialization_pickle"`, sentinel channel is `file at /tmp/sentinel-{id}`, adapter is `GenericFunctionParamAdapter`.

**Fixture 4 — Path Traversal:**
```
fixtures/path_traversal_repo/
├── server.py      # SOURCE: HTTP parameter (function param)
├── reader.py      # SINK: open()
└── main.py        # wiring
```

**server.py:**
```python
from reader import read_file

def serve_file(request):
    filename = request.args.get('file', '')
    return read_file(filename)
```

**reader.py:**
```python
def read_file(path: str):
    with open(f'/data/{path}', 'r') as f:
        return f.read()
```

**Assertions:** Exactly one finding, `exploit_class == "path_traversal"`, `template_name == "path_traversal_read"`, adapter is `FunctionParamRequestAdapter`, sentinel channel is `stdout`.

### 12.7 Regex Baseline Falsification

```python
def test_regex_matcher_fails_on_fixture():
    repo = Path("fixtures/acceptance_repo")
    regex_findings = run_regex_scanner(repo)

    if regex_findings:
        flagged_sinks = [f.sink for f in regex_findings]
        assert "search_raw" in flagged_sinks
        assert "search_safe" in flagged_sinks  # false positive
    # Either way: the regex matcher cannot produce the correct answer
```

---

## 13. Done Definition and Falsification

### 13.1 Done — Mechanical Criteria (CI-Verifiable)

On the four curated fixture repositories, DeepAudit:

1. Flags exactly one finding per fixture — the real vulnerability with a cross-file taint path.
2. Does not flag sanitized paths, parameterized sinks, or safe code patterns.
3. Proves each finding with a sentinel differential.
4. Emits a signed bundle with RFC 8785 canonicalization that passes `verify_bundle()`.
5. The bundle records ≥2 lineages in `convergence.lineages_judged` for each differential finding.
6. Each finding's `reproduction.kind == "differential"` and `reproduction.template_name` is a registered template.
7. Each finding's `reproduction.adapter_name` is a registered source adapter.
8. The sentinel leak pre-check passes.

### 13.2 Done — Qualitative Criteria (Release Gate)

The qualitative done condition is evaluated against the **curated fixture repository set** (§12.2, §12.6):

1. All four fixture tests pass.
2. A human reviewer who inspects each finding's sandbox trace confirms the vulnerability is real and the sentinel differential is genuine.
3. The mechanical proxy for "zero false positives": every shipped finding has `reproduction.verdict == "proven"` AND `reproduction.exploit_run.sentinel_observed == True` AND `reproduction.control_run.sentinel_observed == False`.

### 13.3 Falsification of the Whole Thesis

The build is halted if any of the following is true:

- The `claudopus` SDK cannot be invoked AND the mock cannot demonstrate the pipeline end-to-end.
- Every shipped finding is a false positive once a human inspects the sandbox trace.
- The taint analysis is discovered to be single-file regex matching.
- Any of the four curated fixtures cannot be passed.
- Unverified candidates appear in the shipped findings.
- The source adapter system cannot generate working harnesses for any of the four fixture source patterns.

### 13.4 Partial Failure Diagnostics

| Failure Point | Diagnosis |
|---------------|-----------|
| Mapper works, convergence fails | SDK binding broken. Fix binding or revise SDK usage block. |
| Convergence works, proof always fails | Template preconditions too narrow, adapter mismatch, or sandbox broken. |
| Proof works but false positives | Sentinel protocol too weak or harness leaking. Check sentinel leak pre-check. |
| Everything works on fixtures but not on real repos | System working within v1 scope. Document which constructs fall outside v1's taint domain. |
| Template never matches | Preconditions too strict. Relax or add new templates. |
| Source adapter never matches | Source pattern not in registry. Add adapter or mark `UNVERIFIED (no_source_adapter)`. |
| Import fails in sandbox | Module has import-time side effects. Use `--compat-patch` or accept `UNVERIFIED (import_failure)`. |

---

## 14. Scope Limitations (Honest v1 Boundaries)

### 14.1 PoC Coverage

v1 template coverage: seven exploit classes with specific preconditions. Out-of-scope: blind SQLi, blind command injection, SSRF, race/TOCTOU, logic flaws, SQL injection (write), complex injection chains. Candidates outside coverage are marked `UNVERIFIED`.

### 14.2 Taint Analysis Coverage

The taint abstract domain (§4.7) defines which constructs are tracked. Real-world code using dynamic dispatch, decorators, closures, generators, async/await, or exception-based control flow may have vulnerabilities v1 cannot detect.

### 14.3 Source Adapter Coverage

Covered: Flask `request` (module-level import), function parameter `request`, `sys.argv` direct indexing, `os.environ`, file reads, `input()`, generic function parameters.

**NOT covered in v1:** `argparse` namespace access (adapter cannot infer parsing function invocation or required flags), FastAPI `Request` injection (deferred to v1.1), WebSocket sources, custom framework request objects.

### 14.4 Sandbox Environment Coverage

v1's sandbox is network-isolated. Repositories requiring PostgreSQL, MySQL, Redis, or external APIs are `UNVERIFIED (environmental_incompatibility)`. `--compat-patch` is a manual workaround.

### 14.5 What This Means

DeepAudit v1 is a **proving tool with bounded coverage**. It finds and proves certain classes of cross-file vulnerabilities in Python code within its scope. It misses vulnerabilities outside that scope. What it finds, it proves with a sandboxed differential.

---

## 15. Non-Goals

- No business layer. No pricing, tiers, billing, accounts, SaaS.
- No reimplementation of the claudopus engine.
- No single-file or regex-based taint detection.
- No third-party weaponization.
- No multi-language support in v1.
- No findings-quantity metric.
- No GUI. No telemetry. No inline fix-application.
- No continuous-mode scanning. Single-shot only.
- No SSRF, race/TOCTOU, or logic flaw exploitation in v1.
- No blind vulnerability proof in v1.
- No SQL injection write proof in v1.
- No adversarial attack rounds in v1.
- No external service provisioning in the sandbox.
- No automatic patch generation in v1. Text fix summaries only.
- No `argparse`-based CLI source adapter in v1.

---

## 16. Error Handling and Edge Cases

### 16.1 Graceful Degradation

| Condition | Behavior |
|-----------|----------|
| File fails to parse | Record, continue scan |
| File exceeds parse timeout (10s) | Record as parse failure, continue |
| File exceeds AST node count (100k) | Record as parse failure, continue |
| Mapper exceeds 3.5 GB soft memory | Exit 1 with message |
| Mapper exceeds 4 GB hard memory | OS kills process |
| Import resolution exceeds depth (20) | Truncate, record, continue |
| Image build failure | Exit 1 with message |
| SDK convergence error | `UNVERIFIED (convergence_error)` |
| Docker unavailable | Exit 1, or if `--no-sandbox`, UNVERIFIED for all |
| Sandbox timeout | `UNVERIFIED (exploit_timeout)` |
| Sandbox OOM | `UNVERIFIED (resource_exhausted)` |
| No template matches | `UNVERIFIED (no_template_coverage)` |
| No source adapter matches | `UNVERIFIED (no_source_adapter)` |
| Environmental preconditions fail | `UNVERIFIED (environmental_incompatibility)` |
| Import failure in sandbox | `UNVERIFIED (import_failure)` |
| Requires external database | `UNVERIFIED (requires_external_database)` |
| Sentinel leaked in control | `UNVERIFIED (sentinel_leak_in_control)` |
| Exploit class deferred to v2 | `UNVERIFIED (exploit_class_deferred_v2)` |
| No observable sentinel channel | `UNVERIFIED (no_observable_sentinel_channel)` |
| Signing key missing | Auto-generate, warn operator |
| Empty repository | Exit 0 with empty bundle |
| `InvalidCandidateError` from SDK | `UNVERIFIED (invalid_candidate_schema)` |

### 16.2 Idempotency

Running `deepaudit scan` with `--mock-sdk` twice on the same repository produces structurally identical bundles (modulo timestamps, sentinel values, and scan IDs). Candidate enumeration is sorted by `(source.file, source.line, source.column, sink.file, sink.line, sink.column)` before truncation.

**Idempotency does NOT hold with the real SDK.** The `claudopus.convergence.judge` call routes candidates to external models whose verdicts may vary. The guarantee is scoped to `--mock-sdk` only.

### 16.3 Authorization Gate

The tool refuses to run without `--authorized` or `DEEPAUDIT_AUTHORIZED=1`.

---

## 17. Configuration

`deepaudit.toml` (repo-local) and `~/.config/deepaudit/config.toml` (global). TOML format; repo-local wins.

```toml
[scan]
language = "python"
severity_threshold = "low"
scan_timeout = 1800
max_candidates = 200

[sandbox]
image = "python:3.11-slim"
timeout = 60
memory = "512m"
cpu = 1.0
network = "none"
repo_mount = "copy"

[convergence]
lineages = []
require_agreement = "all"
mock = false

[mapper]
per_file_timeout = 10
max_memory_mb_soft = 3584
max_memory_mb_hard = 4096
max_ast_nodes = 100000
max_import_depth = 20

[signing]
key_path = ""
canonicalization = "RFC 8785"

[output]
include_unverified = false
max_trace_bytes = 1048576

[static_scan]
enabled = true
exclude_dirs = ["tests", "test", "examples", "docs"]
exclude_var_names = ["test", "example", "dummy", "fake", "sample"]

[custom]
sinks = [
  { language = "python", exploit_class = "command_injection",
    pattern = "os.system(", kind = "call" },
]
sanitizers = [
  { language = "python", exploit_class = "sql_injection",
    function = "mypkg.db.parameterize" },
]
```

---

## 18. Security Posture

| Measure | What It Does | How It Is Verified |
|---------|-------------|-------------------|
| Authorization gate (`--authorized`) | Prevents accidental scans | CLI exits with code 3 if absent |
| Sandbox network isolation (`--network none`) | No network egress | Docker run command includes `--network none` |
| Repo copy (not bind-mount) | No host filesystem access | Image build includes `COPY . /repo` |
| Writable `/tmp` tmpfs (noexec, nosuid) | Sentinel files without code exec | `--tmpfs /tmp:rw,noexec,nosuid,size=100m` |
| Resource limits (512 MB, 1.0 CPU, 60s) | Prevents resource exhaustion | `--memory`, `--cpus`, timeout |
| Non-root container user | Unprivileged execution | `--user nobody` |
| Seccomp + no-new-privileges | Restricts syscalls, prevents escalation | `--security-opt no-new-privileges:true --cap-drop ALL` |
| Mapper resource limits | Prevents pathological repos from hanging | 10s/file, 4 GB RLIMIT_AS, 100k AST nodes |
| No telemetry | No data leaves the machine | No network calls in `core/` or `languages/` |
| Signing keys never transmitted | Only bundle signature exported | Key loaded from local path |
| Container cleanup (`--rm`) | No persistent state | `--rm` on all containers |
| Compat patch sandboxed | Runs inside sandbox, not on host | Injected into harness source in container |
| Sentinel leak pre-check | Detects buggy harnesses | Control runs before exploit; sentinel in control → `UNVERIFIED` |
| Compatibility probe isolation | Probe container same posture as proof | `--network none`, resource limits, non-root, seccomp, `--rm` |
| Environment probe isolation | Probe container same posture as proof | `--network none`, resource limits, non-root, seccomp, `--rm` |

---

## 19. Test Plan

- **Unit tests** per module.
- **SDK shim tests** — import surface verification.
- **Mock SDK tests** — verdict logic.
- **Source adapter tests** — `can_handle()`, `generate_setup()`, `generate_invocation()` for each adapter.
- **Template tests** — `preconditions()`, `environmental_preconditions()`, `generate_exploit()`, `generate_control()` for all seven templates. Verify output is valid Python, contains sentinel, uses correct adapter.
- **Sink metadata extraction tests** — `shell_enabled`, `query_type`, `template_engine`, `is_code_exec`.
- **Code injection template test** — verify `eval`/`exec` sinks select `code_injection_exec`, NOT `command_injection_echo`. Verify payload is `print("{sentinel}")`, not `echo {sentinel}`.
- **Sandbox tests** — Docker mocked; sentinel differential under all outcome cases.
- **Sentinel leak pre-check test** — harness leaking sentinel in control detected.
- **Image build failure tests** — exit code 1 with message.
- **Mapper resource limit tests** — per-file timeout, soft memory, hard RLIMIT_AS, AST node limit.
- **Compatibility probe tests** — import failure detected; `--compat-patch` resolves; probe container uses same isolation as proof.
- **Environment probe tests** — `SandboxEnvironment` populated correctly from in-container probe; `has_sqlite`, `installed_packages`, `writable_paths` verified.
- **Cross-file fixtures (§12)** — all four fixtures pass with `--mock-sdk`.
- **Negative-fixture tests** — sanitized paths never flagged.
- **Static finding tests** — `reproduction.kind == "static"`, `convergence: null`.
- **Bundle tests** — RFC 8785 round-trip, signature verification, `lineages_judged` ≥ 2, `unverified` always present (possibly empty).
- **Verify command tests** — signature, canonicalization, sentinel hash, `--re-run`.
- **Idempotency test (mock only)** — two scans produce identical candidate sets.
- **Adapter priority test** — verify deterministic selection when multiple adapters match; verify priority ordering (Flask > FunctionParamRequest > kind-specific > generic).
- **Auth bypass template test** — hardcoded value extraction from AST; harness supplies correct secret; sentinel printed when auth returns True.
- **Path traversal template test** — sentinel file pre-placement; traversal path resolves to sentinel file; control uses benign path.

---

## 20. Risks and How the Spec Fails Loud

| Risk | Detection Mechanism |
|------|-------------------|
| SDK symbols don't exist | Spec lint fails; build never starts |
| Convergence silently downgrades | `lineages_judged` length ≥ 2 enforced |
| Taint analysis degrades to single-file | Acceptance fixtures miss cross-file flow |
| PoC sentinel in both runs | Strict AND; `UNVERIFIED (sentinel_not_differential)` |
| Harness leaks sentinel | Sentinel leak pre-check; `UNVERIFIED (sentinel_leak_in_control)` |
| `eval`/`exec` assigned to shell template | `is_code_exec` field + `code_injection_exec` template; precondition check excludes code-exec from `command_injection_echo` |
| Template preconditions too narrow | High `no_template_coverage` ratio; diagnostic |
| Signed bundle tampered | `deepaudit verify` re-validates |
| PoC works only on fixtures | Acknowledged; v1 done condition is fixture-based |
| SDK non-deterministic | Idempotency scoped to `--mock-sdk` only |
| Repo requires external services | `UNVERIFIED (environmental_incompatibility)` |
| Probe container lacks isolation | Test verifies probe container has `--network none`, resource limits, non-root |
| Adapter selection non-deterministic | Priority field + stable sort; adapter priority test |
| Environment probe fails | Probe error logged; `SandboxEnvironment` fields default to safe values (empty set, False) |

---

## 21. Performance Budgets

- **Repository mapping:** 100k-line repo in under 60 seconds on a 4-core workstation.
- **Convergence gate:** Bounded by SDK latency; 120-second timeout per batch. Mock < 10ms.
- **Sandbox execution:** 60 seconds per harness run. Total per-proof-pair: 120 seconds.
- **Compatibility probe:** 30 seconds per unique source module. Cached per-repo.
- **Environment probe:** < 5 seconds. Cached per image build.
- **Memory:** Mapper and taint engine must not exceed 4 GB resident (hard RLIMIT_AS).

---

## 22. Dependencies

| Package | Purpose |
|---------|---------|
| `tree-sitter` | AST parsing |
| `tree-sitter-python` | Python grammar |
| `docker` | Container lifecycle |
| `cryptography` | Ed25519 signing |
| `claudopus` | SDK — convergence engine (optional with `--mock-sdk`) |
| `psutil` | Soft memory advisory in mapper |
| `resource` | Hard memory limit via RLIMIT_AS (stdlib, Unix only) |

**External:** Docker daemon, Python 3.11+.

---

## 23. Design Principles

- v1 ships Python-only. Architecture seams for v2.
- The proof oracle, not the model, is the product.
- Single-file linting is rejected at the spec level.
- The SDK binding is a hard contract.
- Template coverage is bounded and honest.
- Source adapters make harness generation concrete.
- The taint abstract domain is stated, not hidden.
- Static findings have their own pipeline path.
- RFC 8785 is the canonicalization standard.
- Idempotency is scoped honestly (`--mock-sdk` only).
- The done condition is falsifiable (curated fixtures).
- The sandbox model is self-consistent (writable copy).
- `eval`/`exec` sinks have a dedicated template, not shoehorned into shell commands.
- Adapter priority is numeric and deterministic.
- Fix suggestions are text-only; no auto-generated patches in v1.
- Severity is fixed per class; no unverifiable escalation conditions.

---

## 24. Glossary

- **SOURCE.** An entry point where untrusted value enters.
- **SINK.** A dangerous operation reached with tainted data.
- **SANITIZER.** A function that prunes taint on the path.
- **CROSS-FILE.** A data-flow path spanning ≥2 files.
- **DIFFERENTIAL.** `sentinel_present(EXPLOIT) AND NOT sentinel_present(CONTROL)`.
- **STATIC PROOF.** Evidence type for findings without sandbox execution.
- **UNVERIFIED.** A candidate that did not produce a passing differential.
- **CONVERGENCE.** SDK's cross-lineage judgement.
- **TEMPLATE.** Deterministic PoC harness code generator.
- **SOURCE ADAPTER.** Maps source kind to harness injection strategy.
- **SINK METADATA.** Structured info from sink expressions (`shell_enabled`, `query_type`, `template_engine`, `is_code_exec`).
- **COMPATIBILITY PROBE.** Pre-proof import check in isolated container.
- **ENVIRONMENT PROBE.** Post-build in-container script populating `SandboxEnvironment`.
- **COMPAT PATCH.** Operator-provided monkey-patch for import-time side effects.
- **SENTINEL LEAK PRE-CHECK.** Pre-proof gate running control before exploit.
- **TAINT ABSTRACT DOMAIN.** Set of tracked Python constructs (§4.7).
- **RFC 8785.** JSON Canonicalization Scheme.
- **CURATED FIXTURE.** Small, self-contained repo with known vulnerability.

---

## Obligation Responses

OBL-1: ADDRESSED — `eval`/`exec` sinks are assigned to a dedicated `code_injection_exec` template (§6.7) with Python-expression payloads (`print("{sentinel}")`), not the shell-based `command_injection_echo` template. The `SinkMetadata.is_code_exec` field (§4.9) distinguishes code-exec from shell sinks; `command_injection_echo` preconditions explicitly require `is_code_exec is False`.

OBL-2: ADDRESSED — §6.11 provides a complete `auth_bypass_direct` harness design: hardcoded value extracted from AST, exploit harness supplies the exact secret causing `==` to return `True`, sentinel printed when auth returns `True`, control supplies incorrect value, sentinel channel is `stdout`.

OBL-3: ADDRESSED — §6.8 provides a complete `path_traversal_read` harness design: sentinel file pre-placed at `/tmp/sentinel-target-{id}` via Docker exec, exploit payload traverses to the sentinel file, harness checks for sentinel in function return value, control uses benign path, sentinel channel is `stdout`, error handling for control run included.

OBL-4: ADDRESSED — §6.15 explicitly mandates the compatibility probe container uses identical isolation to proof containers: `--network none`, `--memory 512m`, `--cpus 1.0`, `--user nobody`, `--security-opt no-new-privileges:true --cap-drop ALL`, `--tmpfs /tmp:rw,noexec,nosuid,size=100m`, `--rm`.

OBL-5: ADDRESSED — §3.6 and §6.2 define adapter priority as a numeric `priority: int` field with documented values (Flask=100, FunctionParamRequest=90, kind-specific=80, generic=0). Selection sorts by priority descending using Python's stable `sorted()`, preserving registration order for ties.

OBL-6: ADDRESSED — §6.14 defines an environment probe script (`env_probe.py`) that runs inside the container after image build with full sandbox isolation. It outputs JSON with `python_version`, `installed_packages`, `has_sqlite`, and `writable_paths`. The host-side `core/env_probe.py` module parses this into `SandboxEnvironment`. Result is cached per image build.

OBL-7: ADDRESSED — All seven templates now have complete harness design sections: `sql_injection_read` (§6.5), `command_injection_echo` (§6.6), `code_injection_exec` (§6.7), `path_traversal_read` (§6.8), `deserialization_pickle` (§6.9), `template_injection_jinja2` (§6.10), `auth_bypass_direct` (§6.11). Each includes substitution variables, exploit/control harness source code, and sentinel verification mechanism.

OBL-8: ADDRESSED — §6.2 explicitly documents that `FlaskRequestParamAdapter` creates its own minimal `Flask(__name__)` app for `test_request_context()`. This works because Flask's `request` is a thread-local `LocalProxy` that resolves from the current request context, regardless of which app created it. The target's own Flask app object is not needed — this is a deliberate design choice, not an omission.

OBL-9: ADDRESSED — `CLIArgAdapter` detection criteria (§6.2, §9.1) are restricted to direct `sys.argv` indexing only. `argparse` namespace access is explicitly excluded from detection criteria and listed as NOT supported in v1 (§9.1, §14.3). The adapter no longer claims coverage it cannot provide.

OBL-10: ADDRESSED — `fix.patch_unified_diff` field removed from the bundle schema (§7.4). v1 provides text fix summaries only (`fix.summary`). The `ExploitClassHandler.suggest_fix()` method (§9.4) returns text only. Automatic patch generation is deferred to v2 and listed in Non-Goals (§15).

OBL-11: ADDRESSED — Severity escalation conditions removed entirely (§7.2). v1 uses fixed severities per exploit class with no conditional escalation. The prior "Critical if PoC demonstrates data exfiltration" criterion was unverifiable and has been eliminated. The severity table now includes a rationale column explaining the fixed assignment.