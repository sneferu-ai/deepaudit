#!/usr/bin/env python3
from __future__ import annotations
"""DeepAudit CLI entry point."""

import argparse
import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Any

from deepaudit.config.defaults import DeepAuditConfig, load_config
from deepaudit.core.findings import bundle_to_json, resign_bundle, verify_bundle
from deepaudit.core.pipeline import run_deepaudit_scan
from deepaudit.sandbox.runner import DockerRunner, LocalRunner
from deepaudit.sandbox.sentinel import SENTINEL_RE
from deepaudit.sdk.mock import MockConvergenceClient


def _build_scan_parser(subparsers: argparse._SubParsersAction) -> argparse.ArgumentParser:
    parser = subparsers.add_parser("scan", help="Audit a repository")
    parser.add_argument("repo", type=Path, help="Path to the repository to scan")
    parser.add_argument("--authorized", action="store_true", help="Confirm operator owns or is authorized to test this code")
    parser.add_argument("-o", "--output", type=Path, default=Path("deepaudit-findings.json"), help="Signed bundle destination")
    parser.add_argument("--format", choices=["json", "text", "text-verbose", "sarif"], default="json", help="Output format")
    parser.add_argument("--jobs", type=int, default=1, help="Parallel harness execution (default: 1; >1 logs a warning in v1)")
    parser.add_argument("--severity", choices=["critical", "high", "medium", "low"], default="low", help="Minimum severity to ship")
    parser.add_argument("--include-unverified", action="store_true", help="Populate unverified[] with diagnostic details")
    parser.add_argument("--sandbox-mode", choices=["local", "docker"], default="local", help="Sandbox execution mode")
    parser.add_argument("--no-sandbox", action="store_true", help="Skip Docker/proof execution; no finding can be proven")
    parser.add_argument("--sandbox-timeout", type=int, default=60, help="Per-harness wall-clock limit (legacy alias)")
    parser.add_argument("--scan-timeout", type=int, default=None, help="Per-harness wall-clock limit (overrides --sandbox-timeout)")
    parser.add_argument("--sandbox-image", type=str, default="python:3.11-slim", help="Docker base image for sandbox")
    parser.add_argument("--max-candidates", type=int, default=200, help="Soft cap on candidate enumeration")
    parser.add_argument("--include-single-file", action="store_true", help="Report single-file taint flows too (real bugs; default keeps only cross-file)")
    parser.add_argument("--no-static", action="store_true", help="Disable static secret scan")
    parser.add_argument("--no-write-bundle", action="store_true", help="Do not write the findings bundle to disk")
    parser.add_argument("--dry-run", action="store_true", help="Map and converge only; skip proof execution")
    parser.add_argument("--mock-sdk", action="store_true", help="Use the built-in mock convergence client")
    parser.add_argument("--compat-patch", type=Path, default=None, help="Python compat patch injected before harness import")
    parser.add_argument("--signing-key", type=Path, default=None, help="Ed25519 private key (PEM); generated if absent")
    parser.add_argument("--config", type=Path, default=None, help="Path to deepaudit.toml")
    parser.add_argument("-v", "--verbose", action="count", default=0, help="Increase verbosity")
    parser.add_argument("-q", "--quiet", action="store_true", help="Suppress all output except the final summary")
    return parser


def _build_verify_parser(subparsers: argparse._SubParsersAction) -> argparse.ArgumentParser:
    parser = subparsers.add_parser("verify", help="Validate a signed findings bundle")
    parser.add_argument("bundle", type=Path, help="Path to the signed bundle")
    parser.add_argument("--re-run", type=Path, default=None, help="Re-run harnesses against this repo path")
    return parser


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="deepaudit", description="Prove-It-Or-Don't-Ship Security Auditor")
    subparsers = parser.add_subparsers(dest="command", required=True)
    _build_scan_parser(subparsers)
    _build_verify_parser(subparsers)
    return parser.parse_args(argv)


def _severity_rank(level: str) -> int:
    return {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(level, 0)


def _filter_findings(bundle: Any, min_level: str) -> None:
    rank = _severity_rank(min_level)
    bundle.findings = [f for f in bundle.findings if _severity_rank(getattr(f, "severity", "low")) >= rank]


def _extract_sentinel(poc_exploit: str, sentinel_hash: str) -> str | None:
    for candidate in set(SENTINEL_RE.findall(poc_exploit)):
        if hashlib.sha256(candidate.encode()).hexdigest() == sentinel_hash:
            return candidate
    return None


def _clean_file_channels(channels: list[str]) -> None:
    for channel in channels:
        if channel.startswith("file:"):
            Path(channel.split(":", 1)[1]).unlink(missing_ok=True)


def _scan_command(args: argparse.Namespace) -> int:
    if not args.authorized and not os.environ.get("DEEPAUDIT_AUTHORIZED"):
        if not args.quiet:
            print("Error: authorization required. Use --authorized or set DEEPAUDIT_AUTHORIZED=1.", file=sys.stderr)
        return 3

    if not args.repo.exists():
        if not args.quiet:
            print(f"Error: repository not found: {args.repo}", file=sys.stderr)
        return 3

    if args.jobs > 1 and not args.quiet:
        print("Warning: parallel harness execution (--jobs > 1) is not yet implemented in v1; running sequentially.", file=sys.stderr)

    config = load_config(args.config)
    config.max_candidates = args.max_candidates
    config.skip_single_file = not args.include_single_file
    config.sandbox_mode = args.sandbox_mode
    config.sandbox_timeout = args.scan_timeout or args.sandbox_timeout
    config.sandbox_image = args.sandbox_image
    config.static_scan = not args.no_static
    config.write_bundle = not args.no_write_bundle
    config.output_dir = args.output.parent if args.output else Path("deepaudit-results")
    config.signing_key = args.signing_key
    config.compat_patch = args.compat_patch

    compat_patch = args.compat_patch.read_text() if args.compat_patch else None

    # Honor --sandbox-mode. Previously this flag was parsed and stored but the
    # runner was hardcoded to LocalRunner, so `--sandbox-mode docker` silently
    # ran WITHOUT the container isolation the operator asked for. A security
    # tool must never silently downgrade requested isolation.
    if config.sandbox_mode == "docker":
        if not args.quiet:
            print(
                "Warning: --sandbox-mode docker: the Docker sandbox is a v1 stub; no "
                "container isolation is available, so every proof will be reported "
                "UNVERIFIED. Use --sandbox-mode local to execute proofs on this host "
                "(host subprocess, no isolation).",
                file=sys.stderr,
            )
        runner = DockerRunner(args.repo, image_digest=None, compat_patch=compat_patch)
    else:
        runner = LocalRunner(args.repo, compat_patch=compat_patch)

    convergence_client = MockConvergenceClient() if args.mock_sdk else None

    result = run_deepaudit_scan(
        args.repo,
        config=config,
        convergence_client=convergence_client,
        runner=runner,
        dry_run=args.dry_run or args.no_sandbox,
    )

    # Say which convergence actually ran, from the bundle's own sdk block: the
    # built-in mock (--mock-sdk, or Sneferu unreachable), a Sneferu engine that
    # answered with mock judges, or real cross-lineage judging.
    sdk_block = (getattr(result.bundle, "sdk", None) or {}) if result.bundle else {}
    if sdk_block and not args.quiet:
        if sdk_block.get("engine_reported_mock"):
            print("Warning: the Sneferu engine answered with MOCK judges (is_mock=true); "
                  "findings are still gated by sandbox proof. The bundle records "
                  "convergence_is_mock=true.", file=sys.stderr)
        elif sdk_block.get("convergence_is_mock"):
            print("Warning: convergence used the built-in MOCK judge (every candidate is "
                  "treated as agreed); findings are still gated by sandbox proof. The "
                  "bundle records convergence_is_mock=true.", file=sys.stderr)

    if result.bundle and args.severity != "low":
        _filter_findings(result.bundle, args.severity)
        result.summary.proven = len(result.bundle.findings)

    if result.bundle and not args.include_unverified:
        result.bundle.unverified = []
        result.summary.unverified = 0

    if result.bundle:
        resign_bundle(result.bundle, config.signing_key)
        result.summary.signature_fingerprint = result.bundle.signature.get("fingerprint")

    if result.bundle_path and result.bundle and config.write_bundle:
        dest = Path(args.output)
        dest.parent.mkdir(parents=True, exist_ok=True)
        if Path(result.bundle_path).exists():
            Path(result.bundle_path).rename(dest)
        result.bundle_path = str(dest)
        with open(dest, "w", encoding="utf-8") as f:
            json.dump(bundle_to_json(result.bundle), f, indent=2, default=str)

    if not args.quiet:
        if args.format == "json":
            print(json.dumps(to_plain_summary(result.summary), indent=2, default=str))
        elif args.format == "text-verbose":
            print(f"DeepAudit scan finished.")
            print(f"  Target:          {args.repo}")
            print(f"  Files parsed:    {result.summary.files_parsed}")
            print(f"  Candidates:      {result.summary.candidates}")
            print(f"  Converged:       {result.summary.converged}")
            print(f"  Proven:          {result.summary.proven}")
            print(f"  Unverified:      {result.summary.unverified}")
            print(f"  Static findings: {result.summary.static_findings}")
            if result.bundle_path:
                print(f"  Bundle:          {result.bundle_path}")
            if result.summary.signature_fingerprint:
                print(f"  Signature:       {result.summary.signature_fingerprint}")
            if result.bundle and result.bundle.findings:
                print(f"\nFindings:")
                for f in result.bundle.findings:
                    print(f"  [{f.severity.upper()}] {f.exploit_class}")
                    print(f"    Source: {f.source.file}:{f.source.line}:{f.source.column}")
                    print(f"    Sink:   {f.sink.file}:{f.sink.line}:{f.sink.column}")
                    print(f"    Fix:    {f.fix_suggestion}")
        elif args.format == "sarif":
            sarif = _to_sarif(result.bundle, args.repo)
            print(json.dumps(sarif, indent=2, default=str))
        else:
            print(f"DeepAudit scan finished.")
            print(f"  Target:          {args.repo}")
            print(f"  Files parsed:    {result.summary.files_parsed}")
            print(f"  Candidates:      {result.summary.candidates}")
            print(f"  Converged:       {result.summary.converged}")
            print(f"  Proven:          {result.summary.proven}")
            print(f"  Unverified:      {result.summary.unverified}")
            print(f"  Static findings: {result.summary.static_findings}")
            if result.bundle_path:
                print(f"  Bundle:          {result.bundle_path}")
            if result.summary.signature_fingerprint:
                print(f"  Signature:       {result.summary.signature_fingerprint}")

    return result.exit_code


def to_plain_summary(summary: Any) -> dict[str, Any]:
    """Serialize a ScanSummary dataclass to a JSON-safe dict."""
    return bundle_to_json(summary)


def _to_sarif(bundle, repo_path: Path) -> dict[str, Any]:
    """Convert a FindingsBundle to a minimal SARIF 2.1.0 log."""
    from deepaudit.models.finding import FindingsBundle

    if not isinstance(bundle, FindingsBundle):
        return {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [],
        }

    # SARIF requires uriBaseId to be a *symbolic* id resolved via
    # originalUriBaseIds, not a raw filesystem path.
    try:
        src_root_uri = repo_path.resolve().as_uri()
        if not src_root_uri.endswith("/"):
            src_root_uri += "/"
    except Exception:
        src_root_uri = str(repo_path)

    results = []
    for finding in bundle.findings:
        loc = {
            "physicalLocation": {
                "artifactLocation": {"uri": finding.source.file, "uriBaseId": "SRCROOT"},
                "region": {
                    "startLine": finding.source.line,
                    "startColumn": finding.source.column,
                },
            }
        }
        results.append(
            {
                "ruleId": finding.exploit_class,
                "level": {"critical": "error", "high": "error", "medium": "warning", "low": "note"}.get(finding.severity, "warning"),
                "message": {"text": finding.fix_suggestion},
                "locations": [loc],
                "properties": {
                    "sink": f"{finding.sink.file}:{finding.sink.line}:{finding.sink.column}",
                    "cross_file": finding.cross_file,
                    "reproduction_kind": finding.reproduction.kind if finding.reproduction else "unknown",
                },
            }
        )

    for finding in bundle.static_findings:
        loc = {
            "physicalLocation": {
                "artifactLocation": {"uri": finding.source.file, "uriBaseId": "SRCROOT"},
                "region": {
                    "startLine": finding.source.line,
                    "startColumn": finding.source.column,
                },
            }
        }
        results.append(
            {
                "ruleId": finding.exploit_class,
                "level": {"critical": "error", "high": "error", "medium": "warning", "low": "note"}.get(finding.severity, "warning"),
                "message": {"text": finding.fix_suggestion},
                "locations": [loc],
                "properties": {"kind": "static"},
            }
        )

    tool = {
        "driver": {
            "name": "deepaudit",
            "version": "0.1.0",
            "informationUri": "https://github.com/deepaudit/deepaudit",
        }
    }

    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": tool,
                "originalUriBaseIds": {"SRCROOT": {"uri": src_root_uri}},
                "results": results,
                "invocations": [
                    {
                        "commandLine": f"deepaudit scan {repo_path}",
                        "executionSuccessful": True,
                    }
                ],
            }
        ],
    }


def _verify_command(args: argparse.Namespace) -> int:
    valid = verify_bundle(args.bundle)
    if not valid:
        print("verify: bundle is invalid or untrusted", file=sys.stderr)
        return 1

    if args.re_run:
        if not args.re_run.exists():
            print(f"verify: re-run repo not found: {args.re_run}", file=sys.stderr)
            return 1
        runner = LocalRunner(args.re_run)
        with args.bundle.open("r", encoding="utf-8") as f:
            data = json.load(f)
        for finding in data.get("findings", []):
            repro = finding.get("reproduction", {})
            if repro.get("kind") != "differential":
                continue
            sentinel = _extract_sentinel(repro.get("poc_exploit", ""), repro.get("sentinel_hash", ""))
            if sentinel is None:
                print("verify: could not extract sentinel for re-run", file=sys.stderr)
                return 1
            channels = repro.get("channels") or ["stdout"]
            _clean_file_channels(channels)
            control = runner.run_harness(repro["poc_control"], False, sentinel, channels=channels)
            if control.sentinel_observed:
                print("verify: re-run failed: sentinel observed in control", file=sys.stderr)
                return 1
            if control.status in ("timeout", "crash") or control.exit_code != 0:
                print("verify: re-run failed: control harness crashed unexpectedly", file=sys.stderr)
                return 1
            _clean_file_channels(channels)
            exploit = runner.run_harness(repro["poc_exploit"], True, sentinel, channels=channels)
            if not exploit.sentinel_observed:
                print("verify: re-run failed: sentinel not observed in exploit", file=sys.stderr)
                return 1

    print("verify: bundle is valid")
    return 0


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)

    if args.command == "scan":
        return _scan_command(args)
    if args.command == "verify":
        return _verify_command(args)

    return 3


if __name__ == "__main__":
    sys.exit(main())
