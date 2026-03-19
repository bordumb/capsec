#!/usr/bin/env python3
"""
Benchmark cargo-capsec audit against popular open-source Rust crates.

Clones each crate from crates.toml into a temp directory, runs
`cargo capsec audit --format json`, and produces a summary report.

Usage:
    python crates/cargo-capsec/bench/audit_wild.py                # run all
    python crates/cargo-capsec/bench/audit_wild.py --only serde   # run one
    python crates/cargo-capsec/bench/audit_wild.py --only serde,ripgrep

Output:
    crates/cargo-capsec/bench/results/<date>/
        summary.md   — human-readable markdown table
        raw.json     — full findings per crate
        meta.json    — versions, timing, system info

Requires:
    - cargo-capsec installed (cargo install --path crates/cargo-capsec)
    - git on PATH
    - python3 (no external dependencies)
"""

import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

BENCH_DIR = Path(__file__).resolve().parent
CRATES_TOML = BENCH_DIR / "crates.toml"
RESULTS_DIR = BENCH_DIR / "results"


def parse_crates_toml(path: Path) -> list[dict]:
    """Minimal TOML parser for the [[crate]] array. No dependencies."""
    crates = []
    current = None
    for line in path.read_text().splitlines():
        stripped = line.strip()
        if stripped == "[[crate]]":
            if current is not None:
                crates.append(current)
            current = {}
            continue
        if current is not None and "=" in stripped and not stripped.startswith("#"):
            key, _, value = stripped.partition("=")
            key = key.strip()
            value = value.strip().strip('"')
            current[key] = value
    if current is not None:
        crates.append(current)
    return crates


def get_capsec_version() -> str:
    """Get the installed cargo-capsec version."""
    result = subprocess.run(
        ["cargo", "capsec", "audit", "--help"],
        capture_output=True,
        text=True,
    )
    # Try to extract from help output or just return unknown
    for line in result.stdout.splitlines():
        if "version" in line.lower():
            return line.strip()
    return "unknown"


def get_system_info() -> dict:
    return {
        "platform": platform.platform(),
        "python": platform.python_version(),
        "rust": subprocess.run(
            ["rustc", "--version"], capture_output=True, text=True
        ).stdout.strip(),
        "cargo_capsec": get_capsec_version(),
    }


def clone_repo(repo_url: str, dest: Path) -> bool:
    """Shallow clone a repo. Returns True on success."""
    result = subprocess.run(
        ["git", "clone", "--depth", "1", "--quiet", repo_url, str(dest)],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        print(f"    CLONE FAILED: {result.stderr.strip()}", file=sys.stderr)
        return False
    return True


def run_audit(crate_dir: Path) -> dict:
    """Run cargo capsec audit on a directory. Returns parsed result."""
    start = time.monotonic()
    result = subprocess.run(
        ["cargo", "capsec", "audit", "--format", "json"],
        capture_output=True,
        text=True,
        cwd=crate_dir,
        timeout=300,  # 5 minute timeout per crate
    )
    elapsed = time.monotonic() - start

    output = {
        "exit_code": result.returncode,
        "elapsed_seconds": round(elapsed, 2),
        "stderr": result.stderr.strip(),
    }

    if result.stdout.strip():
        try:
            output["audit"] = json.loads(result.stdout)
        except json.JSONDecodeError:
            output["audit"] = None
            output["parse_error"] = "Failed to parse JSON output"
    else:
        output["audit"] = None

    return output


def summarize_findings(audit_data: dict | None) -> dict:
    """Extract summary stats from audit JSON output."""
    if not audit_data:
        return {"total": 0, "by_category": {}, "by_risk": {}}
    summary = audit_data.get("summary", {})
    return {
        "total": summary.get("total_findings", 0),
        "by_category": summary.get("by_category", {}),
        "by_risk": summary.get("by_risk", {}),
    }


def generate_summary_md(results: list[dict], run_date: str) -> str:
    """Generate a markdown summary table."""
    lines = [
        f"# capsec audit — wild crate benchmark",
        f"",
        f"**Date:** {run_date}",
        f"",
        f"## Results",
        f"",
        f"| Crate | Category | FS | NET | ENV | PROC | FFI | Total | Time |",
        f"|-------|----------|----|-----|-----|------|-----|-------|------|",
    ]

    for r in results:
        if r.get("error"):
            lines.append(
                f"| {r['name']} | {r['category']} | — | — | — | — | — | ERROR | — |"
            )
            continue

        s = r["summary"]
        cat = s["by_category"]
        lines.append(
            f"| {r['name']} | {r['category']} "
            f"| {cat.get('FS', 0)} "
            f"| {cat.get('NET', 0)} "
            f"| {cat.get('ENV', 0)} "
            f"| {cat.get('PROC', 0)} "
            f"| {cat.get('FFI', 0)} "
            f"| {s['total']} "
            f"| {r['elapsed_seconds']}s |"
        )

    lines.extend([
        "",
        "## Observations",
        "",
        "<!-- Fill in after reviewing results -->",
        "",
        "## Methodology",
        "",
        "Each crate was shallow-cloned from its GitHub repo and audited with",
        "`cargo capsec audit --format json`. Only first-party source code was",
        "scanned (dependencies are not included by default).",
        "",
        "Findings represent syntactic matches against known ambient authority",
        "patterns. Limitations:",
        "",
        "- Proc-macro-generated code is not visible to the scanner",
        "- No data flow analysis — dead code is flagged",
        "- Method call matching is contextual (e.g., `.output()` only flags",
        "  when `Command::new` is in the same function)",
        "- `extern` blocks are flagged but individual FFI calls are not categorized",
        "",
        f"Tool version: cargo-capsec from source (workspace)",
    ])

    return "\n".join(lines)


def main() -> None:
    # Parse --only filter
    only = None
    for arg in sys.argv[1:]:
        if arg.startswith("--only"):
            if "=" in arg:
                only = set(arg.split("=", 1)[1].split(","))
            elif sys.argv.index(arg) + 1 < len(sys.argv):
                only = set(sys.argv[sys.argv.index(arg) + 1].split(","))

    crates = parse_crates_toml(CRATES_TOML)
    if only:
        crates = [c for c in crates if c["name"] in only]

    if not crates:
        print("No crates to audit.", file=sys.stderr)
        sys.exit(1)

    run_date = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    run_dir = RESULTS_DIR / run_date
    run_dir.mkdir(parents=True, exist_ok=True)

    print(f"Auditing {len(crates)} crates — results in {run_dir}")
    print()

    results = []

    with tempfile.TemporaryDirectory(prefix="capsec-bench-") as tmp:
        tmp_path = Path(tmp)

        for crate_info in crates:
            name = crate_info["name"]
            repo = crate_info["repo"]
            category = crate_info.get("category", "unknown")

            print(f"  [{name}]", flush=True)
            print(f"    Cloning {repo}...", flush=True)

            clone_dir = tmp_path / name
            if not clone_repo(repo, clone_dir):
                results.append({
                    "name": name,
                    "category": category,
                    "error": "clone failed",
                })
                continue

            print(f"    Running audit...", flush=True)
            audit_result = run_audit(clone_dir)

            summary = summarize_findings(audit_result.get("audit"))

            entry = {
                "name": name,
                "repo": repo,
                "category": category,
                "expect": crate_info.get("expect", ""),
                "exit_code": audit_result["exit_code"],
                "elapsed_seconds": audit_result["elapsed_seconds"],
                "summary": summary,
                "findings": audit_result.get("audit"),
            }

            if audit_result.get("stderr"):
                entry["stderr"] = audit_result["stderr"]
            if audit_result.get("parse_error"):
                entry["error"] = audit_result["parse_error"]

            results.append(entry)

            cat = summary["by_category"]
            total = summary["total"]
            print(
                f"    {total} findings "
                f"(FS:{cat.get('FS', 0)} NET:{cat.get('NET', 0)} "
                f"ENV:{cat.get('ENV', 0)} PROC:{cat.get('PROC', 0)} "
                f"FFI:{cat.get('FFI', 0)}) "
                f"in {audit_result['elapsed_seconds']}s",
                flush=True,
            )
            print()

    # Write outputs
    meta = {
        "run_date": run_date,
        "crate_count": len(crates),
        "system": get_system_info(),
    }

    (run_dir / "meta.json").write_text(json.dumps(meta, indent=2))
    (run_dir / "raw.json").write_text(json.dumps(results, indent=2))
    (run_dir / "summary.md").write_text(generate_summary_md(results, run_date))

    # Update latest symlink
    latest = RESULTS_DIR / "latest"
    if latest.is_symlink() or latest.exists():
        latest.unlink()
    latest.symlink_to(run_date)

    print(f"Done. Results in {run_dir}/")
    print(f"  summary.md  — human-readable table")
    print(f"  raw.json    — full findings per crate")
    print(f"  meta.json   — system info and timing")


if __name__ == "__main__":
    main()
