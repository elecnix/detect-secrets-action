"""Unit tests for gate.py's comparison logic.

A detector that has never been seen to fail has not been tested. These drive
the gate against synthetic scan output and assert it fires on a genuinely NEW
finding — and stays silent on what it must NOT punish: line-number drift (the
whole reason this gate exists instead of `detect-secrets-hook --baseline`).
"""

import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

REPO_ROOT = Path(__file__).resolve().parent


def _load_gate():
    spec = importlib.util.spec_from_file_location("gate", REPO_ROOT / "gate.py")
    mod = importlib.util.module_from_spec(spec)
    sys.modules["gate"] = mod
    spec.loader.exec_module(mod)
    return mod


gate = _load_gate()


def _finding(path, kind, digest, line):
    return {
        "type": kind,
        "filename": path,
        "hashed_secret": digest,
        "line_number": line,
    }


def _scan_result(findings):
    results = {}
    for f in findings:
        results.setdefault(f["filename"], []).append(f)
    return {"results": results}


def _run_gate(baseline_findings, fresh_findings, monkeypatch, tmp_path):
    baseline_path = tmp_path / ".secrets.baseline"
    baseline_path.write_text(json.dumps({"results": _scan_result(baseline_findings)["results"]}))
    monkeypatch.setattr(gate, "tracked_files", lambda p: ["some_file.py"])
    monkeypatch.setattr(
        gate.subprocess, "run",
        lambda *a, **kw: SimpleNamespace(returncode=0, stdout=json.dumps(_scan_result(fresh_findings)), stderr=""),
    )
    return gate.main([str(baseline_path)])


def test_fingerprint_ignores_line_numbers():
    a = gate.fingerprint({"f.py": [_finding("f.py", "Secret Keyword", "abc", 10)]})
    b = gate.fingerprint({"f.py": [_finding("f.py", "Secret Keyword", "abc", 999)]})
    assert a == b


def test_fingerprint_distinguishes_path_type_and_hash():
    a = gate.fingerprint({"f.py": [_finding("f.py", "A", "h1", 1)]})
    assert gate.fingerprint({"f.py": [_finding("f.py", "A", "h2", 1)]}) != a
    assert gate.fingerprint({"f.py": [_finding("f.py", "B", "h1", 1)]}) != a
    assert gate.fingerprint({"g.py": [_finding("g.py", "A", "h1", 1)]}) != a


def test_passes_when_every_finding_is_in_the_baseline(monkeypatch, tmp_path):
    known = [_finding("f.py", "Secret Keyword", "abc", 10)]
    assert _run_gate(known, known, monkeypatch, tmp_path) == 0


def test_passes_when_a_line_number_drifts(monkeypatch, tmp_path):
    """The hook fails here; the gate must not (code moved, nothing added)."""
    known = [_finding("f.py", "Secret Keyword", "abc", 10)]
    drifted = [_finding("f.py", "Secret Keyword", "abc", 42)]
    assert _run_gate(known, drifted, monkeypatch, tmp_path) == 0


def test_fires_on_a_new_untriaged_finding(monkeypatch, tmp_path):
    known = [_finding("f.py", "Secret Keyword", "abc", 10)]
    fresh = known + [_finding("g.py", "GitHub Token", "xyz", 3)]
    assert _run_gate(known, fresh, monkeypatch, tmp_path) == 1


def test_passes_when_a_finding_disappears(monkeypatch, tmp_path):
    """Removal should not fail the build; the baseline entry is just stale."""
    known = [
        _finding("f.py", "Secret Keyword", "abc", 10),
        _finding("g.py", "GitHub Token", "xyz", 3),
    ]
    fresh = [_finding("f.py", "Secret Keyword", "abc", 10)]
    assert _run_gate(known, fresh, monkeypatch, tmp_path) == 0


def test_fails_loudly_on_a_missing_baseline(tmp_path):
    assert gate.main([str(tmp_path / "does-not-exist.json")]) == 2


def test_tracked_files_excludes_the_baseline(tmp_path, monkeypatch):
    """Scanning the baseline finds its own triaged hashes — it must be skipped."""
    (tmp_path / ".secrets.baseline").write_text("{}")
    (tmp_path / "real.py").write_text("x = 1\n")
    monkeypatch.chdir(tmp_path)

    def fake_run(cmd, **kw):
        return subprocess.CompletedProcess(cmd, 0, stdout=".secrets.baseline\nreal.py\n", stderr="")

    monkeypatch.setattr(gate.subprocess, "run", fake_run)
    assert gate.tracked_files(".secrets.baseline") == ["real.py"]
