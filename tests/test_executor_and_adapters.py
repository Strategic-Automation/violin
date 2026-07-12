from pathlib import Path

import pytest

from plugins.violin_guard import adapters, executor


def _engagement(tmp_path: Path) -> Path:
    eng = tmp_path / "engagement"
    (eng / "state").mkdir(parents=True)
    (eng / "evidence").mkdir()
    (eng / "state" / "history.md").write_text("# History\n", encoding="utf-8")
    return eng


def test_local_executor_records_receipt_and_history(tmp_path):
    eng = _engagement(tmp_path)
    receipt = executor.execute(
        "echo violin-test",
        eng_dir=str(eng),
        phase="recon",
        timeout_seconds=10,
        label="smoke",
    )
    assert receipt["executed"] is True
    assert receipt["exit_code"] == 0
    assert "violin-test" in receipt["stdout_preview"]
    assert (eng / receipt["evidence_paths"]["manifest"]).exists()
    assert "echo violin-test" in (eng / "state" / "history.md").read_text(encoding="utf-8")


def test_executor_rejects_cwd_escape(tmp_path):
    eng = _engagement(tmp_path)
    with pytest.raises(ValueError, match="inside the engagement"):
        executor.execute("echo blocked", eng_dir=str(eng), phase="recon", cwd="..")


def test_adapter_builders_are_structured_and_bounded():
    assert (
        adapters.build_nmap({"target": "10.0.0.1", "ports": "80,443"})
        == "nmap -sCV -p 80,443 10.0.0.1"
    )
    assert "FUZZ" in adapters.build_ffuf(
        {
            "url": "http://10.0.0.1/FUZZ",
            "wordlist": "/tmp/common.txt",
        }
    )
    with pytest.raises(ValueError):
        adapters.build_nmap({"target": "10.0.0.1", "ports": "80; rm -rf /"})


def test_search_exploit_reports_missing_tool(monkeypatch):
    monkeypatch.setattr(adapters.shutil, "which", lambda _: None)
    result = adapters.search_exploit({"product": "OpenSSH", "version": "9.0"})
    assert result["available"] is False
    assert result["executed_candidates"] is not True
