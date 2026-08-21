#!/usr/bin/env python3
"""Integration fixtures for the CI workflow: build a throwaway git repo,
run the real gate.py inside it, and assert the exit code matches what the
scenario demands. Exit 0 here means the gate behaved as the scenario expects.

Scenarios:
- clean-passes (expect 0): a baseline holding one audited finding; the tree
  contains exactly that finding -> gate exits 0.
- planted-secret-fails (expect 1): a fresh GitHub-token-looking string the
  baseline does not know -> gate exits 1.
- drift-passes (expect 2): the audited finding moves to a different line
  number -> gate STILL exits 0 (the whole point of hash-based comparison).
"""

import json
import os
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent  # repo root (contains gate.py)


def sh(*cmd: str, cwd: Path) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, cwd=cwd, check=True, capture_output=True, text=True)


def build_fixture(root: Path, secret_line: str) -> Path:
    """A git repo with app.py containing secret_line, plus an audited
    baseline that knows about a DIFFERENT (benign) finding."""
    root.mkdir(parents=True)
    sh("git", "init", "-q", cwd=root)
    sh("git", "-c", "user.email=t@t", "-c", "user.name=t", "commit",
       "-q", "--allow-empty", "-m", "init", cwd=root)
    (root / "app.py").write_text(secret_line)
    # Baseline knows one finding: a hex string in consts.py (audited FP).
    (root / "consts.py").write_text('SALT = "0123456789abcdef0123456789abcdef01234567"\n')
    scan = json.loads(sh("detect-secrets", "scan", "consts.py", cwd=root).stdout)
    results = {}
    for path, findings in scan["results"].items():
        results[path] = [{**s, "is_secret": False} for s in findings]
    baseline = {"results": results}
    (root / ".secrets.baseline").write_text(json.dumps(baseline, indent=2))
    return root


def main() -> int:
    scenario = sys.argv[1]
    import tempfile

    with tempfile.TemporaryDirectory() as td:
        if scenario == "clean-passes":
            root = build_fixture(Path(td) / "repo", 'TOKEN = "not-a-token"\n')
        elif scenario == "planted-secret-fails":
            # A realistic GitHub token shape (prefix + base64-ish body) that
            # detect-secrets' GitHubTokenDetector recognizes.
            root = build_fixture(
                Path(td) / "repo",
                'TOKEN = "ghp_0123456789abcdefghijklmnopqrstuvwxyzABC"\n',
            )
        elif scenario == "drift-passes":
            # Audited finding exists, but with padding lines above it so its
            # line number differs from the baseline's — the hook would fail
            # here; the gate must not.
            root = build_fixture(Path(td) / "repo", 'TOKEN = "not-a-token"\n')
            p = root / "consts.py"
            p.write_text("# moved\n# moved\n" + p.read_text())
        else:
            print(f"unknown scenario: {scenario}", file=sys.stderr)
            return 64

        # The baseline must be committed: gate.py lists files with
        # `git ls-files -co --exclude-standard`, and an untracked baseline
        # would still be listed (-o), but commit anyway to mirror real use.
        sh("git", "add", "-A", cwd=root)
        sh("git", "-c", "user.email=t@t", "-c", "user.name=t", "commit",
           "-q", "-m", "fixture", cwd=root)

        proc = subprocess.run(
            [sys.executable, str(HERE / "gate.py"), ".secrets.baseline"],
            cwd=root, capture_output=True, text=True,
        )
        expected = {"clean-passes": 0, "planted-secret-fails": 1, "drift-passes": 0}[scenario]
        ok = proc.returncode == expected
        print(f"[{scenario}] gate exit {proc.returncode} (expected {expected}) "
              f"-> {'OK' if ok else 'FAIL'}")
        print(proc.stdout.strip())
        if proc.stderr.strip():
            print(proc.stderr.strip(), file=sys.stderr)
        return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
