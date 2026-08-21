#!/usr/bin/env python3
"""Baseline-diffed detect-secrets gate.

Scans the current working tree with `detect-secrets scan` and fails when a
finding is NOT present in the audited baseline, compared on
(path, type, hashed_secret) — deliberately NOT on line_number.

Why not `detect-secrets-hook --baseline`? The hook rewrites the baseline
whenever a finding's line number shifts and exits non-zero asking for a
re-commit — correct for a pre-commit hook, pure churn in CI, where the tree
is an ephemeral checkout. Moving code around never fails this gate; only a
genuinely NEW secret does.

The baseline file itself is excluded from the scan: it stores the triaged
hashes themselves, so scanning it would find them again as "new".

Output contract (consumed by action.yml): the LAST line is always
`NEW findings: <n>`. Exit codes: 0 = no new secrets, 1 = new secrets found,
2 = usage/IO error.
"""

from __future__ import annotations

import json
import subprocess
import sys


def tracked_files(baseline_path: str) -> list[str]:
    out = subprocess.run(
        ["git", "ls-files", "-co", "--exclude-standard"],
        check=True, capture_output=True, text=True,
    ).stdout
    return [line for line in out.splitlines() if line != baseline_path]


def fingerprint(findings: dict) -> set[tuple[str, str, str]]:
    """(path, type, hashed_secret) — deliberately NOT line_number (drift)."""
    return {
        (path, s["type"], s["hashed_secret"])
        for path, ss in findings.items()
        for s in ss
    }


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    baseline_path = args[0] if args else ".secrets.baseline"
    try:
        with open(baseline_path) as f:
            baseline = json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        print(f"cannot read baseline {baseline_path}: {exc}", file=sys.stderr)
        print("NEW findings: ?", flush=True)
        return 2

    files = tracked_files(baseline_path)
    if not files:
        print("no tracked files to scan")
        print("NEW findings: 0", flush=True)
        return 0

    proc = subprocess.run(
        ["detect-secrets", "scan", *files],
        capture_output=True, text=True,
    )
    if proc.returncode != 0:
        print(f"detect-secrets scan failed: {proc.stderr}", file=sys.stderr)
        print("NEW findings: ?", flush=True)
        return 2
    fresh = json.loads(proc.stdout)

    known = fingerprint(baseline["results"])
    current = fingerprint(fresh["results"])
    new = current - known

    if not new:
        print(
            f"secret-scan OK: {len(current)} finding(s), "
            f"all in the audited baseline ({len(known)} entries)"
        )
        print("NEW findings: 0", flush=True)
        return 0

    print("NEW untriaged secret finding(s) — triage, then update "
          "the baseline if they are false positives:")
    for path, kind, digest in sorted(new):
        print(f"  {path}: {kind} ({digest[:16]}…)")
    print(f"NEW findings: {len(new)}", flush=True)
    return 1


if __name__ == "__main__":
    sys.exit(main())
