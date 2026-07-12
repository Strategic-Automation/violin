"""Doc-sync + heartbeat state machine for the Violin guard.

Single source of truth for the "update your tracking artifacts after every
command" enforcement and the periodic coarse review. Used by both the core
``violin_guard.py check-command`` path and the violin_guard plugin, so the
enforcement is identical no matter which entry point the LLM uses.

State files live under ``<eng_dir>/state/``:
  .violin_last_check.json     - last approved command (continuity)
  .violin_pending_sync.json   - a command was approved but its artifacts
                                (ptt.md / history.md / hypothesis-board.md)
                                have not yet been verified fresh
  .violin_heartbeat.json      - command + message counters
  .violin_heartbeat_pending.json - a periodic coarse review is due
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path

# Cadence. A doc-sync gate fires after *every* approved target command; a
# heartbeat (full engagement-file review) fires every COMMAND_INTERVAL commands
# or every MESSAGE_INTERVAL messages.
COMMAND_INTERVAL = 5
MESSAGE_INTERVAL = 10

# How many times the exact same command may be re-issued before check-command
# hard-blocks it and forces the LLM to stop retrying and do research instead.
RETRY_LIMIT = 3

# A pending-sync lock older than this many hours is treated as stale — almost
# certainly a leftover from a *prior* session that approved a command, ran it,
# recorded history, but died before calling sync-done. Auto-expire it so a
# brand-new session is never wedged by a stale lock (root-cause fix, issue 3).
# 12h comfortably spans an active session while expiring next-day leftovers.
PENDING_SYNC_TTL_HOURS = 12


# --------------------------------------------------------------------------- #
# state dir / paths
# --------------------------------------------------------------------------- #
def state_dir(eng_dir: str) -> Path:
    p = Path(eng_dir) / "state"
    p.mkdir(parents=True, exist_ok=True)
    return p


def _last_check_path(eng_dir: str) -> Path:
    return state_dir(eng_dir) / ".violin_last_check.json"


def _pending_sync_path(eng_dir: str) -> Path:
    return state_dir(eng_dir) / ".violin_pending_sync.json"


def _heartbeat_count_path(eng_dir: str) -> Path:
    return state_dir(eng_dir) / ".violin_heartbeat.json"


def _heartbeat_pending_path(eng_dir: str) -> Path:
    return state_dir(eng_dir) / ".violin_heartbeat_pending.json"


# --------------------------------------------------------------------------- #
# last approved command (continuity)
# --------------------------------------------------------------------------- #
def record_ok_check(eng_dir: str, command: str, phase: str) -> None:
    _last_check_path(eng_dir).write_text(json.dumps({
        "command": command,
        "phase": phase,
        "ts": datetime.now(timezone.utc).isoformat(),
    }))


def last_ok_check(eng_dir: str) -> dict | None:
    p = _last_check_path(eng_dir)
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text())
    except Exception:
        return None


# --------------------------------------------------------------------------- #
# DOC-SYNC GATE
# --------------------------------------------------------------------------- #
def mark_pending_sync(eng_dir: str, command: str, phase: str) -> None:
    """Called after a command is approved & returned to the operator."""
    _pending_sync_path(eng_dir).write_text(json.dumps({
        "command": command,
        "phase": phase,
        "ts": datetime.now(timezone.utc).isoformat(),
    }))


def clear_pending_sync(eng_dir: str) -> None:
    p = _pending_sync_path(eng_dir)
    if p.exists():
        p.unlink()


def _pending_ts(rec: dict) -> float:
    """Parse a pending record's ISO-8601 ``ts`` to a UTC epoch, or -1 if unparseable."""
    s = (rec or {}).get("ts", "")
    if not s:
        return -1.0
    try:
        parsed = datetime.fromisoformat(s.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.timestamp()
    except Exception:
        return -1.0


def force_clear_pending_sync(eng_dir: str) -> bool:
    """Unconditionally clear a pending-sync lock.

    Used for manual reconciliation and at session start (scoping bootstrap calls
    ``sync-clear``) to drop a leftover lock from a previous session that would
    otherwise wedge the new session (root-cause fix, issue 3).
    """
    p = _pending_sync_path(eng_dir)
    if p.exists():
        try:
            p.unlink()
            return True
        except OSError:
            return False
    return False


def has_pending_sync(eng_dir: str) -> dict | None:
    """Return the pending record if a prior command's artifacts are un-synced.

    ROOT-CAUSE FIX (issue 2): self-heals truly orphaned locks WITHOUT breaking
    the normal pending flow.

    Normal flow: a command is approved, ``mark_pending_sync`` arms the lock, THEN
    the LLM runs it and calls ``record-history`` — so for a brief, correct window
    the pending command is NOT yet in history.md. Clearing the lock in that window
    would destroy the doc-sync enforcement, so a missing-from-history command is
    treated as *genuinely pending* (the artifacts_are_fresh gate then decides).

    The lock is only auto-healed (cleared -> None) when it is unambiguously
    orphaned/stale:
      - the lock file is corrupt/unreadable (can never gate correctly), OR
      - state/history.md does not exist at all, meaning NOTHING was ever run in
        this engagement tree — exactly the incident case (a prior session's lock
        survived into a tree that was never executed). With no history, the lock
        can only be a leftover and would otherwise wedge every later session.
    """
    p = _pending_sync_path(eng_dir)
    if not p.exists():
        return None
    try:
        rec = json.loads(p.read_text())
    except Exception:
        # Unreadable lock is treated as stale -> clear and unblock.
        try:
            p.unlink()
        except OSError:
            pass
        return None
    hist = Path(eng_dir) / "state" / "history.md"
    if not hist.exists():
        # No history artifact at all -> nothing was ever run for this
        # engagement tree -> the pending command was released but never
        # executed. The lock is a leftover (the incident case) and would
        # otherwise wedge every later session. Clear it.
        try:
            p.unlink()
        except OSError:
            pass
        return None
    # TTL auto-expire: a lock older than PENDING_SYNC_TTL_HOURS is a leftover
    # from a prior session (command recorded in history but sync-done never
    # called). Expire it so a fresh session is not wedged.
    age = datetime.now(timezone.utc).timestamp() - _pending_ts(rec)
    if _pending_ts(rec) > 0 and age > PENDING_SYNC_TTL_HOURS * 3600:
        try:
            p.unlink()
        except OSError:
            pass
        return None
    return rec


def artifacts_are_fresh(eng_dir: str, pending: dict) -> bool:
    """Verify the tracking artifacts were updated AFTER the pending command ts.

    Rules:
      - state/history.md MUST contain the command string (continuity proven).
      - ptt.md MUST have a 'Last updated:' timestamp >= pending ts.
      - if phase in {vuln-research, exploitation}: hypothesis-board.md MUST have
        an 'Updated:' timestamp >= pending ts.
    Returns True only if all applicable checks pass.
    """
    from datetime import datetime as _dt

    def _ts(s: str) -> float:
        # Normalise every timestamp to an explicit-UTC, tz-aware value so the
        # comparison is consistent regardless of how it was written:
        #   - pending ts:  "2026-07-08T19:23:49.691262+00:00" (ISO, UTC)
        #   - ptt footer:  "*Last updated: 2026-07-08 19:29 UTC*"
        #   - history:     "- [2026-07-08T19:29:15Z] ..."
        #   - LLM manual:  "2026-07-08 19:25" (local wall-clock)
        # We convert " UTC"/"Z" to "+00:00" and, for bare local wall-clock
        # stamps, assume UTC (the operator's clock) so the pending/artifact
        # clocks are compared on the same basis.
        s = (s or "").strip()
        if not s:
            return -1.0
        # 1) ISO 8601 with optional offset / Z / fractional seconds
        #    e.g. "2026-07-08T19:40:15.760831+00:00", "2026-07-08T19:29:15Z".
        try:
            parsed = _dt.fromisoformat(s.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed.timestamp()
        except Exception:
            pass
        # 2) Plain wall-clock with a " UTC" marker, e.g. "2026-07-08 19:32 UTC".
        s2 = re.sub(r"\bUTC\b", "", s).strip()
        for fmt in ("%Y-%m-%d %H:%M", "%Y-%m-%dT%H:%M", "%Y-%m-%d %H:%M:%S"):
            try:
                parsed = _dt.strptime(s2, fmt)
                return parsed.replace(tzinfo=timezone.utc).timestamp()
            except Exception:
                continue
        # 3) Unparseable / placeholder stamp (e.g. "<YYYY-MM-DD HH:MM>") is
        #    treated as STALE, never "fresh".
        return -1.0

    # Strip markdown wrapping (*, **, - ) from a "*Last updated: ...*" style line
    # and return the bare label (lower) + value, or (None, None) if not a
    # "last updated"/"updated" field.
    _FIELD_RE = re.compile(r"^\s*(?:[-*]\s*)?\**\s*(last updated|updated)\s*[:*]\s*\**\s*(.*?)\s*\**\s*$",
                           re.IGNORECASE)

    d = Path(eng_dir)
    pending_ts = _ts(pending.get("ts", ""))
    # Artifacts are stamped at minute/second resolution (e.g. record-ptt writes
    # "%Y-%m-%d %H:%M UTC"), while the pending ts carries microsecond
    # resolution. Comparing directly would make a same-minute update look
    # stale, so we floor the pending ts to the minute for the freshness check.
    pending_min = pending_ts - (pending_ts % 60)
    # 1) history continuity
    hist = d / "state" / "history.md"
    if not (hist.exists() and pending.get("command", "") in hist.read_text(encoding="utf-8", errors="ignore")):
        return False
    # 2) ptt freshness  (deployed at state/ptt.md)
    ptt = d / "state" / "ptt.md"
    if ptt.exists():
        freshest = 0.0
        matched = False
        for line in ptt.read_text(encoding="utf-8", errors="ignore").splitlines():
            m = _FIELD_RE.match(line)
            if m and m.group(1).lower() == "last updated":
                matched = True
                freshest = max(freshest, _ts(m.group(2)))
        if not matched or freshest < pending_min:
            return False
    # 3) hypothesis board freshness (research/exploitation phases)
    #    deployed at hypotheses.md (top-level)
    if pending.get("phase") in ("vuln-research", "exploitation"):
        hb = d / "hypotheses.md"
        if hb.exists():
            freshest = 0.0
            matched = False
            for line in hb.read_text(encoding="utf-8", errors="ignore").splitlines():
                m = _FIELD_RE.match(line)
                if m and m.group(1).lower() == "updated":
                    matched = True
                    freshest = max(freshest, _ts(m.group(2)))
            if not matched or freshest < pending_min:
                return False
    return True


# --------------------------------------------------------------------------- #
# HEARTBEAT GATE
# --------------------------------------------------------------------------- #
def _read_counts(eng_dir: str) -> dict:
    p = _heartbeat_count_path(eng_dir)
    if p.exists():
        try:
            return json.loads(p.read_text())
        except Exception:
            pass
    return {"command_count": 0, "message_count": 0}


def tick_command(eng_dir: str) -> int:
    """Increment the approved-command counter; return the new count."""
    c = _read_counts(eng_dir)
    c["command_count"] = c.get("command_count", 0) + 1
    _heartbeat_count_path(eng_dir).write_text(json.dumps(c))
    return c["command_count"]


def tick_message(eng_dir: str) -> int:
    """Increment the message counter (LLM calls this per message); return new count."""
    c = _read_counts(eng_dir)
    c["message_count"] = c.get("message_count", 0) + 1
    _heartbeat_count_path(eng_dir).write_text(json.dumps(c))
    return c["message_count"]


def set_heartbeat_pending(eng_dir: str, reason: str) -> None:
    _heartbeat_pending_path(eng_dir).write_text(json.dumps({
        "reason": reason,
        "skill_review_required": True,
        "ts": datetime.now(timezone.utc).isoformat(),
    }))


def has_heartbeat_pending(eng_dir: str) -> dict | None:
    p = _heartbeat_pending_path(eng_dir)
    if not p.exists():
        return None
    try:
        return json.loads(p.read_text())
    except Exception:
        return None


def clear_heartbeat_pending(eng_dir: str) -> None:
    p = _heartbeat_pending_path(eng_dir)
    if p.exists():
        p.unlink()


# --------------------------------------------------------------------------- #
# STUCK / RETRY DETECTION
# --------------------------------------------------------------------------- #
def repeat_count(eng_dir: str, command: str) -> int:
    """Count exact occurrences of ``command`` in state/history.md.

    Used by check-command to block retry loops: re-issuing the same command
    over and over is the classic "stuck" anti-pattern. Returns 0 if history is
    absent.
    """
    hist = Path(eng_dir) / "state" / "history.md"
    if not hist.exists():
        return 0
    needle = command.strip()
    if not needle:
        return 0
    text = hist.read_text(encoding="utf-8", errors="ignore")
    return text.count(needle)
