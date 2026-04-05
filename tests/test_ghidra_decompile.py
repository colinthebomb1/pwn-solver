"""Tests for Ghidra headless decompilation helper."""

from __future__ import annotations

import os
import tempfile
from unittest.mock import Mock

import pytest

from agent.mcp_servers.exploit_tools import ghidra_decompile
from agent.mcp_servers.exploit_tools.ghidra_decompile import run_ghidra_decompile


def test_run_ghidra_decompile_empty_functions():
    r = run_ghidra_decompile(__file__, [])
    assert r.get("ok") is False
    assert "empty" in (r.get("error") or "").lower()


def test_run_ghidra_decompile_missing_binary():
    r = run_ghidra_decompile("/nonexistent/no_such_binary", ["main"])
    assert r.get("ok") is False
    assert "not found" in (r.get("error") or "").lower()


def test_run_ghidra_decompile_no_ghidra_home(monkeypatch):
    monkeypatch.delenv("GHIDRA_HOME", raising=False)
    monkeypatch.delenv("PWN_GHIDRA_HOME", raising=False)
    r = run_ghidra_decompile(__file__, ["main"])
    assert r.get("ok") is False
    assert "Ghidra" in (r.get("error") or "")


def test_run_ghidra_decompile_bad_explicit_home():
    r = run_ghidra_decompile(__file__, ["main"], ghidra_home="/definitely/not/ghidra")
    assert r.get("ok") is False
    assert "ghidra_home" in (r.get("error") or "").lower()


def test_build_headless_cmd_uses_import_without_cache(tmp_path):
    binary = tmp_path / "sample.bin"
    binary.write_bytes(b"hello")
    cfg = tmp_path / "cfg.json"
    cfg.write_text("{}", encoding="utf-8")
    info = {
        "project_dir": str(tmp_path / "proj"),
        "project_name": "projname",
        "program_name": "sample.bin",
        "project_file": str(tmp_path / "proj" / "projname.gpr"),
        "project_rep": str(tmp_path / "proj" / "projname.rep"),
    }
    cmd, cache_hit = ghidra_decompile._build_headless_cmd(
        "/opt/ghidra/support/analyzeHeadless",
        info,
        str(binary),
        str(cfg),
        use_cache=True,
    )
    assert cache_hit is False
    assert "-import" in cmd
    assert "-process" not in cmd


def test_build_headless_cmd_uses_process_with_cached_project(tmp_path):
    proj_dir = tmp_path / "proj"
    proj_dir.mkdir()
    (proj_dir / "projname.gpr").write_text("", encoding="utf-8")
    (proj_dir / "projname.rep").mkdir()
    binary = tmp_path / "sample.bin"
    binary.write_bytes(b"hello")
    cfg = tmp_path / "cfg.json"
    cfg.write_text("{}", encoding="utf-8")
    info = {
        "project_dir": str(proj_dir),
        "project_name": "projname",
        "program_name": "sample.bin",
        "project_file": str(proj_dir / "projname.gpr"),
        "project_rep": str(proj_dir / "projname.rep"),
    }
    cmd, cache_hit = ghidra_decompile._build_headless_cmd(
        "/opt/ghidra/support/analyzeHeadless",
        info,
        str(binary),
        str(cfg),
        use_cache=True,
    )
    assert cache_hit is True
    assert "-process" in cmd
    assert "sample.bin" in cmd
    assert "-import" not in cmd


def test_run_ghidra_decompile_reports_cache_hit(monkeypatch, tmp_path):
    binary = tmp_path / "sample.bin"
    binary.write_bytes(b"hello")
    digest = "abcd1234ef567890"
    proj_dir = tmp_path / "cache" / digest
    proj_dir.mkdir(parents=True)
    (proj_dir / f"autopwn_sample.bin_{digest}.gpr").write_text("", encoding="utf-8")
    (proj_dir / f"autopwn_sample.bin_{digest}.rep").mkdir()
    out_json = tmp_path / "out.json"

    monkeypatch.setattr(ghidra_decompile, "_ghidra_home_from_env", lambda: "/opt/ghidra")
    monkeypatch.setattr(
        ghidra_decompile,
        "_analyze_headless_path",
        lambda home: "/opt/ghidra/support/analyzeHeadless",
    )
    monkeypatch.setattr(ghidra_decompile, "_hash_file", lambda path: digest)
    monkeypatch.setattr(ghidra_decompile, "_ghidra_cache_root", lambda: str(tmp_path / "cache"))
    monkeypatch.setattr(ghidra_decompile, "_env_for_ghidra", lambda: {})
    monkeypatch.setattr(
        ghidra_decompile,
        "_write_config",
        lambda functions: (str(tmp_path / "cfg.json"), str(out_json)),
    )

    def fake_run(cmd, capture_output, text, timeout, env):
        out_json.write_text('{"main":{"c":"int main(void){return 0;}"}}', encoding="utf-8")
        return Mock(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(ghidra_decompile.subprocess, "run", fake_run)

    result = run_ghidra_decompile(str(binary), ["main"])
    assert result["ok"] is True
    assert result["cache"]["enabled"] is True
    assert result["cache"]["hit"] is True


def _ghidra_headless_available() -> bool:
    for key in ("GHIDRA_HOME", "PWN_GHIDRA_HOME"):
        gh = os.environ.get(key)
        if gh and os.path.isfile(os.path.join(gh, "support", "analyzeHeadless")):
            return True
    return False


@pytest.mark.skipif(
    not _ghidra_headless_available(),
    reason="Ghidra headless / GHIDRA_HOME not available",
)
def test_run_ghidra_decompile_smoke_ret2win(tmp_path, monkeypatch):
    """End-to-end headless run (requires Java + Ghidra on the runner)."""
    # Writable HOME so Ghidra can create ~/.config (CI/sandbox often lacks a real home).
    monkeypatch.setenv("HOME", str(tmp_path))

    here = os.path.dirname(__file__)
    chal = os.path.join(here, "challenges", "ret2win_x64")
    if not os.path.isfile(chal):
        pytest.skip("ret2win_x64 not built")

    r = run_ghidra_decompile(chal, ["main", "win"], timeout=900)
    assert r.get("ok") is True, r
    funcs = r.get("functions") or {}
    assert "main" in funcs
    assert "c" in funcs.get("main", {}) or "error" in funcs.get("main", {})
