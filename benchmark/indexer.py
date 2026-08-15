"""indexer.py — Unified engagement directory artifact indexer with resource bounds."""

from __future__ import annotations

import contextlib
from pathlib import Path
from typing import Any

MAX_FILE_SIZE_BYTES = 2 * 1024 * 1024  # 2MB cap per file for text indexing


def collect_engagement_artifacts(
    eng_dir: Path, max_file_size: int = MAX_FILE_SIZE_BYTES
) -> dict[str, Any]:
    """Scan and index all relevant engagement files across evidence, state, exploits, and root."""
    artifacts: dict[str, Any] = {
        "evidence_files": [],
        "state_files": [],
        "exploit_files": [],
        "hypotheses_text": "",
        "history_text": "",
        "feedback_text": "",
    }

    def _read_file(path: Path) -> str:
        if path.stat().st_size > max_file_size:
            # Read first 2MB to keep memory bounded while capturing HTTP signatures
            with path.open("r", encoding="utf-8", errors="replace") as f:
                return f.read(max_file_size)
        return path.read_text(encoding="utf-8", errors="replace")

    # Evidence
    ev_dir = eng_dir / "evidence"
    if ev_dir.exists():
        for f in ev_dir.rglob("*"):
            if f.is_file():
                with contextlib.suppress(Exception):
                    artifacts["evidence_files"].append(
                        {
                            "path": f.relative_to(eng_dir).as_posix(),
                            "size": f.stat().st_size,
                            "content": _read_file(f),
                        }
                    )

    # State (check for misplaced evidence)
    st_dir = eng_dir / "state"
    if st_dir.exists():
        for f in st_dir.rglob("*"):
            if f.is_file() and not f.name.endswith(".lock"):
                with contextlib.suppress(Exception):
                    artifacts["state_files"].append(
                        {
                            "path": f.relative_to(eng_dir).as_posix(),
                            "size": f.stat().st_size,
                            "content": _read_file(f),
                        }
                    )

    # Exploits
    exp_dir = eng_dir / "exploits"
    if exp_dir.exists():
        for f in exp_dir.rglob("*"):
            if f.is_file():
                with contextlib.suppress(Exception):
                    artifacts["exploit_files"].append(
                        {
                            "path": f.relative_to(eng_dir).as_posix(),
                            "size": f.stat().st_size,
                            "content": _read_file(f),
                        }
                    )

    # Hypotheses
    hyp_path = eng_dir / "hypotheses.md"
    if hyp_path.exists():
        with contextlib.suppress(Exception):
            artifacts["hypotheses_text"] = hyp_path.read_text(encoding="utf-8", errors="replace")

    # History
    hist_path = eng_dir / "state" / "history.md"
    if not hist_path.exists():
        hist_path = eng_dir / "history.md"
    if hist_path.exists():
        with contextlib.suppress(Exception):
            artifacts["history_text"] = hist_path.read_text(encoding="utf-8", errors="replace")

    # Framework Feedback Log
    feedback_path = eng_dir / "state" / "framework_feedback.md"
    if feedback_path.exists():
        with contextlib.suppress(Exception):
            artifacts["feedback_text"] = feedback_path.read_text(encoding="utf-8", errors="replace")

    return artifacts
