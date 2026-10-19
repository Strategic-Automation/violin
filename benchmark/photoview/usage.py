"""Export only accounting columns from Hermes; never copy conversations or credentials."""

from __future__ import annotations

import sqlite3
from pathlib import Path

COLUMNS = (
    "id",
    "model",
    "started_at",
    "ended_at",
    "input_tokens",
    "output_tokens",
    "cache_read_tokens",
    "cache_write_tokens",
    "reasoning_tokens",
    "api_call_count",
    "estimated_cost_usd",
    "actual_cost_usd",
    "cost_status",
    "cost_source",
)


def collect_usage(home: Path, started_at: float) -> dict:
    sessions = []
    for path in sorted(home.rglob("state.db")):
        if path.is_symlink():
            continue
        with sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True) as db:
            db.row_factory = sqlite3.Row
            columns = {row["name"] for row in db.execute("PRAGMA table_info(sessions)")}
            if not set(COLUMNS) <= columns:
                continue
            rows = db.execute(
                "SELECT " + ", ".join(COLUMNS) + " FROM sessions WHERE started_at >= ?",
                (started_at,),
            ).fetchall()
            sessions.extend(
                {"database": path.relative_to(home).as_posix(), **dict(row)} for row in rows
            )
    billable = [row for row in sessions if row["api_call_count"]]
    actual_known = bool(billable) and all(row["actual_cost_usd"] is not None for row in billable)
    estimated_known = bool(billable) and all(
        row["estimated_cost_usd"] is not None for row in billable
    )
    return {
        "source": "Hermes session accounting for this fresh runtime",
        "sessions": sessions,
        "input_tokens": sum(row["input_tokens"] or 0 for row in sessions),
        "output_tokens": sum(row["output_tokens"] or 0 for row in sessions),
        "cache_read_tokens": sum(row["cache_read_tokens"] or 0 for row in sessions),
        "cache_write_tokens": sum(row["cache_write_tokens"] or 0 for row in sessions),
        "reasoning_tokens": sum(row["reasoning_tokens"] or 0 for row in sessions),
        "api_call_count": sum(row["api_call_count"] or 0 for row in sessions),
        "actual_cost_usd": sum(row["actual_cost_usd"] for row in billable)
        if actual_known
        else None,
        "estimated_cost_usd": sum(row["estimated_cost_usd"] for row in billable)
        if estimated_known
        else None,
        "actual_cost_complete": actual_known,
        "limitation": "Recorded provider cost is not an invoice; estimates never substitute for missing actual cost",
    }
