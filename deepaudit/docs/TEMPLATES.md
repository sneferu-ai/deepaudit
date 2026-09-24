# DeepAudit PoC Templates and Source Adapters

This document describes the v1 PoC template catalog and the source-adapter system that injects mock inputs into harnesses.

---

## 1. Vulnerability classes

DeepAudit v1 ships templates for the following exploit classes. Each template is a deterministic Python module under `deepaudit/templates/`.

| Exploit class | Template module | Sink pattern | Primary source kinds |
|---------------|-----------------|--------------|----------------------|
| `sql_injection` | `sql_injection_read.py` | SQL `cursor.execute(f"...{tainted}...")` | `http_param_func`, `http_param_flask`, `generic_param` |
| `command_injection` | `command_injection_echo.py` | `os.system(cmd)`, `subprocess.call(cmd, shell=True)` | `generic_param`, `http_param_*` |
| `code_injection` | `code_injection_exec.py` | `eval(expr)`, `exec(stmt)` | `generic_param`, `http_param_*` |
| `path_traversal` | `path_traversal_read.py` | `open(base + tainted)` | `generic_param`, `http_param_*`, `cli_arg` |
| `unsafe_deserialization` | `unsafe_deserialization_pickle.py` | `pickle.loads(data)` | `generic_param`, `http_param_*`, `file_read` |
| `template_injection` | `template_injection_jinja2.py` | `jinja2.Template(tainted).render()` | `generic_param`, `http_param_*` |
| `auth_bypass` | `auth_bypass_direct.py` | Hardcoded or weak authorization check | `generic_param`, `http_param_*` |

Templates are selected by `exploit_class`. Preconditions are checked against `candidate.sink_metadata` to avoid mismatches (e.g., a non-shell `subprocess` call should not be sent to the command-injection template).

---

## 2. Source adapters

A source adapter maps a *detected* source pattern to the *mock-injection* code that appears at the top of a harness. Adapters are selected deterministically by `priority`.

### 2.1 Priority table

| Adapter | Priority | Handles |
|---------|----------|---------|
| `FlaskRequestParamAdapter` | 100 | `request.args.get(...)` / `request.args[...]` where `request` is a function parameter |
| `FlaskRequestBodyAdapter` | 100 | `request.json`, `request.data`, `request.GET`, `request.POST` where `request` is a function parameter |
| `FunctionParamRequestAdapter` | 90 | Flask-like request access on a function parameter (fallback to minimal Flask app) |
| `CLIArgAdapter` | 80 | `sys.argv[...]` direct access |
| `EnvVarAdapter` | 80 | `os.environ[...]` or `os.getenv(...)` |
| `FileReadAdapter` | 80 | `open(...)` source that reads attacker-controlled data |
| `UserInputAdapter` | 80 | `input(...)` |
| `GenericFunctionParamAdapter` | 0 | Any function parameter when no specific adapter matches |

### 2.2 Adapter interface

```python
class SourceAdapter:
    kind: str
    priority: int

    def can_handle(self, source, candidate, repo_model) -> bool: ...
    def generate_setup(self, source, sentinel, is_exploit, candidate) -> str: ...
    def generate_invocation(self, source, sentinel, is_exploit, candidate) -> str: ...
```

`generate_setup()` returns the code that runs *before* the target module is imported. `generate_invocation()` returns the code that calls the vulnerable function.

### 2.3 Selection algorithm

1. Extract `source_kind`, `source_is_parameter`, and the source expression from the candidate.
2. Filter registered adapters to those where `can_handle()` returns `True`.
3. Sort by `priority` descending; stable sort preserves registration order on ties.
4. Select the first adapter.
5. If no adapter matches, mark the candidate `UNVERIFIED (no_source_adapter)`.

---

## 3. Template harness design

Every template produces two harnesses: an **exploit harness** and a **control harness**. Both share the same adapter-generated setup code, but differ in the payload embedded by the template.

### 3.1 Common harness structure

```python
# 1. Adapter setup: create mock input environment
{setup_code}

# 2. Make target importable
import sys
sys.path.insert(0, "/repo")

import {candidate.source_module} as _target

# 3. Adapter invocation: call the vulnerable function
{invocation_code}

# 4. Sentinel report (stdout channel)
print(sentinel)
print("__HARNESS_DONE__")
```

The harness is written to a sandbox, executed, and the configured channels are inspected for the sentinel value.

### 3.2 Sentinel channels

Templates declare which output channels the oracle should inspect:

- `stdout` — the default; the harness prints the sentinel if it appears in the result.
- `file:<path>` — the harness writes the sentinel to a file; the oracle checks the file after execution.

`sentinel_channels()` returns the *default* channels for the template. `resolved_channels(candidate)` may extend or specialize them based on sink metadata (e.g., a path-traversal template that writes the sentinel to a specific file path).

---

## 4. Template catalog

### 4.1 `sql_injection_read`

**Target sink:** SQL `cursor.execute(f"...{tainted}...")` or string-concatenated SQL query.

**Preconditions:** `candidate.exploit_class == "sql_injection"`. Optional: `sink_metadata.query_type` is `"SELECT"` (the v1 template uses SELECT-based UNION injection).

**Exploit payload:** A string that breaks out of the SQL string literal and injects `UNION SELECT '<sentinel>' --`.

**Control payload:** A benign string that matches the expected input shape but does not alter the query structure (e.g., a normal search term).

**Adapter:** `FlaskRequestParamAdapter` or `FunctionParamRequestAdapter` when the source is a Flask request parameter; `GenericFunctionParamAdapter` otherwise.

**Sentinel channel:** `stdout`.

**Verification:** The exploit run returns a result row containing the sentinel; the control run does not.

---

### 4.2 `command_injection_echo`

**Target sink:** `os.system(cmd)`, `os.popen(cmd)`, or `subprocess.call(..., shell=True)`.

**Preconditions:** `candidate.exploit_class == "command_injection"` and `sink_metadata.shell_enabled` is `True`.

**Exploit payload:** A command string ending with `; echo '<sentinel>'` or `&& echo '<sentinel>'`.

**Control payload:** A benign command argument that produces no sentinel output.

**Adapter:** `GenericFunctionParamAdapter` for function parameters; `CLIArgAdapter` for `sys.argv` sources.

**Sentinel channel:** `stdout`.

**Verification:** The exploit run prints the sentinel via the injected echo; the control run does not.

---

### 4.3 `code_injection_exec`

**Target sink:** `eval(expr)` or `exec(stmt)`.

**Preconditions:** `candidate.exploit_class == "code_injection"` and `sink_metadata.is_code_exec` is `True`.

**Exploit payload:** A Python expression whose evaluation produces the sentinel, e.g. `str('DA-' + '<sentinel>')` or `__import__('os').popen('echo <sentinel>').read()`.

**Control payload:** A benign Python literal that does not produce the sentinel.

**Adapter:** `GenericFunctionParamAdapter` for function parameters; `EnvVarAdapter` or `FileReadAdapter` for other sources.

**Sentinel channel:** `stdout`.

**Verification:** The exploit run returns the sentinel; the control run does not.

---

### 4.4 `path_traversal_read`

**Target sink:** `open(base_path + tainted)` or `open(os.path.join(base_path, tainted))`.

**Preconditions:** `candidate.exploit_class == "path_traversal"`.

**Exploit payload:** A relative path with enough `../` segments to escape the intended base directory and reach a sentinel file created by the harness, e.g. `../../../../tmp/sentinel-<id>`.

**Control payload:** A benign relative path that stays within the base directory and does not reach the sentinel file.

**Adapter:** `GenericFunctionParamAdapter` for function parameters; `CLIArgAdapter` for `sys.argv`; `FileReadAdapter` when the source is a file read.

**Sentinel channel:** `stdout` by default; the harness creates the sentinel file before the exploit call and verifies the function reads it. `resolved_channels()` may return `file:<path>` if the sink writes to a file instead of returning contents.

**Verification:** The exploit run returns the sentinel content; the control run does not.

---

### 4.5 `unsafe_deserialization_pickle`

**Target sink:** `pickle.loads(data)`.

**Preconditions:** `candidate.exploit_class == "unsafe_deserialization"` and the `pickle` module is available in the sandbox.

**Exploit payload:** A serialized `pickle` payload whose `__reduce__` writes the sentinel to a known file path (or prints it to stdout).

**Control payload:** A serialized benign object that does not produce the sentinel.

**Adapter:** `GenericFunctionParamAdapter` for function parameters; `FileReadAdapter` when the source is a file read.

**Sentinel channel:** `file:<sentinel_path>` by default; the exploit payload writes the sentinel file, and the oracle checks for its presence after execution.

**Verification:** The exploit run creates the sentinel file; the control run does not.

---

### 4.6 `template_injection_jinja2`

**Target sink:** `jinja2.Template(tainted).render(...)` or `Environment().from_string(tainted).render(...)`.

**Preconditions:** `candidate.exploit_class == "template_injection"` and `sink_metadata.template_engine == "jinja2"`.

**Exploit payload:** A Jinja2 expression that evaluates to the sentinel, e.g. `{{ '<sentinel>' }}` or `{{ 7*7 }}` variants that produce the sentinel.

**Control payload:** A literal template string that does not evaluate the sentinel.

**Adapter:** `GenericFunctionParamAdapter` for function parameters; `EnvVarAdapter` or `FileReadAdapter` for other sources.

**Sentinel channel:** `stdout`.

**Verification:** The exploit render output contains the sentinel; the control output does not.

---

### 4.7 `auth_bypass_direct`

**Target sink:** A hardcoded or weak authorization check (e.g., `if token == "secret":`, `if not user.is_admin:` with a bypassable parameter).

**Preconditions:** `candidate.exploit_class == "auth_bypass"`. Template preconditions inspect the sink expression for comparison against a constant or a role check that can be bypassed by an attacker-controlled value.

**Exploit payload:** The attacker-controlled value that satisfies the weak check (e.g., the hardcoded token, a truthy value for a boolean check, or a specially crafted role string).

**Control payload:** A value that fails the check.

**Adapter:** `GenericFunctionParamAdapter` for function parameters; `EnvVarAdapter` when the source is an environment variable.

**Sentinel channel:** `stdout`.

**Verification:** The exploit run reaches a protected branch and prints the sentinel; the control run does not.

---

## 5. Deterministic template dispatch

Template dispatch is entirely deterministic:

1. Look up registered templates by `candidate.exploit_class`.
2. Filter by `preconditions(candidate, repo_model)`.
3. Select the first template that passes.
4. If the template's `environmental_preconditions()` fails, the candidate is `UNVERIFIED (environmental_preconditions)`.

No template calls an LLM. No template contains model-specific logic. They are pure Python string generators that combine the adapter output with exploit/control payloads.

---

## 6. Extending templates

To add a new template:

1. Create a module under `deepaudit/templates/` implementing the `PoCTemplate` protocol.
2. Register it in the template registry by `exploit_class`.
3. Add a smoke-test fixture under `tests/fixtures/` that demonstrates a proven differential.
4. Add a test in `tests/test_smoke.py` asserting `summary.proven == 1` and the correct `exploit_class`.

To add a new source adapter:

1. Implement the `SourceAdapter` protocol in `deepaudit/source_adapters.py`.
2. Assign a `priority` that places it correctly in the hierarchy.
3. Register it in the adapter registry.
4. Add a unit test that asserts the adapter is selected for a matching source and rejected for non-matching sources.

All extensions must keep the existing hard module boundaries: `sandbox/` owns execution, `templates/` stays deterministic, and `convergence.py` stays a thin SDK shim.
