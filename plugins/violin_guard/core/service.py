"""Single application facade for guarded execution."""
from __future__ import annotations
import json, os
from pathlib import Path
from . import state, command, execution, hypotheses, ptt, bootstrap

def _json(status_name, **payload):
    payload.pop("status", None)
    return json.dumps({"schema_version":2,"status":status_name,**payload})
def _result(r): return {"errors":r.errors,"warnings":r.warnings,"infos":r.infos}

def handle_check_command(a, **kwargs):
    r=command.check_command(command.CheckCommandArgs(a.get("command",""),a.get("phase",""),a.get("eng_dir",""),a.get("scope",""),a.get("session_id"),a.get("skill_loaded_file")))
    return _json("ok" if r.exit_code()==0 else "review" if r.exit_code()==2 else "block", **_result(r))

def handle_record_ptt(a, **kwargs):
    try:
        doc=ptt.parse_ptt(Path(a["eng_dir"])/"state"/"ptt.md"); p=state.get_pending_sync(a["eng_dir"])
        task=a.get("id"); note=(a.get("note") or "").strip()
        if not p: raise ValueError("no pending execution batch")
        if not task or not note: raise ValueError("task id and non-empty review note required")
        ptt.update_task(Path(a["eng_dir"])/"state"/"ptt.md", task, a.get("status","x"), note)
        state.mark_ptt_reviewed(a["eng_dir"],task,note)
        return _json("ok", task_id=task, batch_id=p.get("batch_id"))
    except Exception as e: return _json("error", error=str(e))

def handle_record_hypothesis(a, **kwargs):
    try:
        h=hypotheses.update_hypothesis(Path(a["eng_dir"])/"hypotheses.md", **{k:v for k,v in a.items() if k!="eng_dir"})
        return _json("ok", hypothesis=h.to_dict())
    except Exception as e:return _json("error",error=str(e))

def handle_sync_done(a, **kwargs):
    try:
        p=state.get_pending_sync(a["eng_dir"])
        if not p:return _json("ok", message="nothing pending")
        if not p.get("ptt_reviewed"): return _json("review", error="explicit PTT review required")
        state.clear_pending_sync(a["eng_dir"]); return _json("ok", batch_id=p.get("batch_id"))
    except Exception as e:return _json("error",error=str(e))

def handle_heartbeat_done(a, **kwargs): state.clear_heartbeat_pending(a["eng_dir"]); return _json("ok")
def handle_exec(a, **kwargs):
    gate=json.loads(handle_check_command(a))
    if gate["status"] not in ("ok",) and not (gate["status"]=="review" and os.environ.get("HERMES_YOLO_MODE")=="1"):
        status = "sync_required" if any("sync-credit" in str(x) or "not synced" in str(x) for x in gate.get("errors", [])) else "denied"
        return _json(status, executed=False, **gate)
    try:
        r=execution.execute(command=a["command"],eng_dir=a["eng_dir"],phase=a["phase"],backend=a.get("backend","local"),timeout_seconds=a.get("timeout_seconds",180),cwd=a.get("cwd",""),label=a.get("label",""))
        r.pop("status", None); return _json("ok",**r)
    except Exception as e:return _json("execution_failed",error=str(e),executed=False)
def handle_exec_status(a, **kwargs): return _json("ok", **execution.status(a.get("eng_dir"),a.get("execution_id")))
def handle_exec_cancel(a, **kwargs): return _json("ok", **execution.cancel(a.get("eng_dir"),a.get("execution_id")))
def handle_exec_burst(a, **kwargs):
    cmds=a.get("commands") or []
    if len(cmds)>20:return _json("error",error="burst limit is 20")
    return _json("batch_complete",results=[json.loads(handle_exec({**a,"command":c})) for c in cmds],executed=len(cmds))
def handle_target(a, **kwargs):
    p=Path(a["eng_dir"])/"scope"/"scope.yaml"; import yaml; d=yaml.safe_load(p.read_text()); ips=d.get("targets",{}).get("ip_addresses",[]); return _json("ok",value=ips[0]) if ips else _json("error",error="no targets in scope")
def handle_status(a, **kwargs): return _json("ok",sync_pending=state.has_pending_sync(a["eng_dir"]),sync_credit_remaining=state.sync_credit_remaining(a["eng_dir"]),command_count=state.read_counts(a["eng_dir"])["commands"])
def handle_search_exploit(a, **kwargs): return _json("ok", **__import__("plugins.violin_guard.core.adapters",fromlist=["search_exploit"]).search_exploit(a))
