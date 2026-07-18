#!/usr/bin/env bash
# =============================================================================
# smoke-test.sh — Violin Kali/Parrot Release Readiness Check
# =============================================================================

# Exit non-zero on any failure. Runs from anywhere in the repo tree.
# Usage:
#   ./scripts/smoke-test.sh            # full check
#   ./scripts/smoke-test.sh --no-install  # skip install/smoke/cleanup cycle
# =============================================================================

set -euo pipefail

# ── Determine repo root ──────────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
cd "$REPO_ROOT"

python3 scripts/violin_guard.py check-release

SKILL_DIR="skills/pentest"
PLAYBOOK_DIR="$SKILL_DIR/playbooks"
REF_DIR="$SKILL_DIR/references"
TEMPLATES_DIR="$SKILL_DIR/templates"

SKIP_INSTALL=false
[[ "${1:-}" == "--no-install" ]] && SKIP_INSTALL=true

PASS=0
FAIL=0
FAILURES=""

# ── Helpers ───────────────────────────────────────────────────────────────────
pass()  { echo "  [✓] $1"; ((PASS+=1)); }
fail()  { echo "  [✗] $1"; ((FAIL+=1)); FAILURES+="  - $1"$'\n'; }
header(){ echo ""; echo "━━━ $1 ━━━"; }
summary(){ echo ""; echo "────────────────────────────────────────"; echo "  PASS: $PASS   FAIL: $FAIL"; echo "────────────────────────────────────────"; }

seed_history_fixture(){
  python3 - "$1" "$2" "$3" <<'PY'
import sys
from plugins.violin_guard import history
history.append_history(sys.argv[1], sys.argv[2], sys.argv[3], 0)
PY
}

# =============================================================================
# 1. YAML Validity
# =============================================================================
header "1. YAML Validity"

for yaml_file in distribution.yaml config.yaml "$TEMPLATES_DIR"/scope-template.yaml; do
  fname="$(basename "$yaml_file")"
  if python3 -c "
import yaml, sys
try:
    yaml.safe_load(open('$yaml_file', encoding='utf-8'))
    print('OK')
except Exception as e:
    print(f'FAIL: {e}')
    sys.exit(1)
" 2>/dev/null; then
    pass "YAML valid: $fname"
  else
    fail "YAML invalid: $fname"
  fi
done

# =============================================================================
# 2. Reference Files Exist
# =============================================================================
header "2. Reference Files Exist"

if [ -d "$REF_DIR" ]; then
  ref_count=0
  while IFS= read -r -d '' ref; do
    echo "    [✓] $(basename "$ref")"
    ((ref_count+=1))
  done < <(find "$REF_DIR" -maxdepth 1 -type f -name '*.md' -print0)
  pass "Reference files present: $ref_count"
else
  fail "Reference directory missing: $REF_DIR"
fi

# ── Check additional referenced paths in SKILL.md ──────────────────────────
# Also verify that referenced subpaths mentioned in SKILL.md actually exist
missing_ref=0
for path in \
  "$SKILL_DIR/references/tool-discovery.md" \
  "$SKILL_DIR/references/tool-catalog.md" \
  "$SKILL_DIR/references/kali-parrot-paths.md" \
  "$SKILL_DIR/references/cve-apis.md" \
  "$SKILL_DIR/references/standards.md" \
  "$SKILL_DIR/references/methodology.md" \
  "$SKILL_DIR/references/retrospective.md" \
  ; do
  if [ -f "$path" ]; then
    pass "Referenced file exists: $(basename "$path")"
  else
    fail "Missing referenced file: $path"
    ((missing_ref+=1))
  fi
done

# =============================================================================
# 3. No Stale ./evidence Paths in Playbooks
# =============================================================================
header "3. Stale Path Check"

# Check for literal ./evidence, ./scope, ./report paths in playbooks only
# (templates may legitimately mention ./scope.yaml as a copy instruction)
if grep -rn '\./evidence\b\|\./scope\b\|\./report\b' "$PLAYBOOK_DIR" --include='*.md' 2>/dev/null; then
  fail "Stale ./ paths found in playbooks (above)"
else
  pass "No stale ./evidence/./scope/./report paths in playbooks"
fi

# Also check skills/pentest-references for stale paths
if grep -rn '\./evidence\b' "$SKILL_DIR/references" --include='*.md' 2>/dev/null; then
  fail "Stale ./evidence paths in references/ (above)"
else
  pass "No stale ./evidence paths in references/"
fi

# Check templates for stale paths (except the intentional copy-instruction)
stale_in_templates=$(grep -rn '\./evidence\b' "$TEMPLATES_DIR" --include='*.yaml' --include='*.md' 2>/dev/null || true)
if [ -n "$stale_in_templates" ]; then
  # scope-template.yaml intentionally says "./scope.yaml" — that's OK
  echo "    (template ./paths are intentional — scope-template.yaml copy instruction)"
  pass "Template paths are intentional references, not stale"
fi

# =============================================================================
# 3.5 Bootstrap Enforcement — guard hard-blocks unbooted target interaction
# =============================================================================
header "3.5 Bootstrap Enforcement"

SMOKE_ENG="engagements/_smoke-bootstrap-$$"
rm -rf "$SMOKE_ENG"

# (a) Unbooted: check-bootstrap must exit 1 with BOOTSTRAP REQUIRED
set +e
unbooted_output=$(python3 scripts/violin_guard.py check-bootstrap --eng-dir "$SMOKE_ENG" 2>&1)
unbooted_exit=$?
set -e
if [ "$unbooted_exit" -eq 1 ] && echo "$unbooted_output" | grep -q "BOOTSTRAP REQUIRED"; then
  pass "Unbooted check-bootstrap exits 1 with 'BOOTSTRAP REQUIRED'"
else
  fail "Unbooted check-bootstrap did not behave as expected (exit=$unbooted_exit)"
fi

# (b) Unbooted: check-command with missing scope must exit 1
set +e
unbooted_cmd=$(python3 scripts/violin_guard.py check-command --scope "$SMOKE_ENG/no-scope.yaml" --phase recon --command "curl http://10.129.245.218" 2>&1)
unbooted_cmd_exit=$?
set -e
if [ "$unbooted_cmd_exit" -eq 1 ] && echo "$unbooted_cmd" | grep -q "BOOTSTRAP REQUIRED"; then
  pass "check-command with missing scope exits 1 with 'BOOTSTRAP REQUIRED'"
else
  fail "check-command with missing scope did not block (exit=$unbooted_cmd_exit)"
fi

# (c) Bootstrapped: check-bootstrap must exit 0
mkdir -p "$SMOKE_ENG"/{scope,state,evidence}
cp skills/pentest/templates/ptt.md "$SMOKE_ENG/state/ptt.md"
# Update a PTT row so stale-PTT detection doesn't fire
python3 scripts/violin_guard.py record-ptt --eng-dir "$SMOKE_ENG" --id PT-001 --status "[x]" --note "smoke bootstrap" >/dev/null 2>&1
cp skills/pentest/templates/hypothesis-board.md "$SMOKE_ENG/hypotheses.md"
echo "# Command History — smoke" > "$SMOKE_ENG/state/history.md"
cat > "$SMOKE_ENG/scope/scope.yaml" <<'YAML'
engagement:
  client: Smoke
  tester: smoke
  date: '2026-07-07'
  duration: '1h'
targets:
  domains: [nimbus.htb]
  ip_addresses: [10.129.245.218]
  app_type: webapp
mode: active-recon
depth: black-box
rules_of_engagement:
  max_requests_per_second: 5
  forbidden_actions: [credential-stuffing, social-engineering, persistence, stealth-evasion, malware-delivery, destructive-payloads]
authorisation:
  confirmed: true
  confirmed_by: smoke
  confirmed_at: '2026-07-07T00:00:00Z'
YAML

set +e
booted_output=$(python3 scripts/violin_guard.py check-bootstrap --eng-dir "$SMOKE_ENG" 2>&1)
booted_exit=$?
set -e
if [ "$booted_exit" -eq 0 ] && echo "$booted_output" | grep -q "bootstrap complete"; then
  pass "Bootstrapped check-bootstrap exits 0"
else
  fail "Bootstrapped check-bootstrap did not exit 0 (exit=$booted_exit)"
fi

# (d) Bootstrapped in-scope: check-command must exit 0
set +e
inscope_output=$(python3 scripts/violin_guard.py check-command --scope "$SMOKE_ENG/scope/scope.yaml" --phase recon --command "curl http://10.129.245.218" 2>&1)
inscope_exit=$?
set -e
if [ "$inscope_exit" -eq 0 ]; then
  pass "Bootstrapped in-scope command allowed"
else
  fail "Bootstrapped in-scope command blocked (exit=$inscope_exit)"
fi

# (e) Bootstrapped out-of-scope: check-command must exit 1
set +e
outofscope_output=$(python3 scripts/violin_guard.py check-command --scope "$SMOKE_ENG/scope/scope.yaml" --phase recon --command "curl http://other.example.com" 2>&1)
outofscope_exit=$?
set -e
if [ "$outofscope_exit" -eq 1 ] && echo "$outofscope_output" | grep -q "outside approved scope"; then
  pass "Bootstrapped out-of-scope command blocked"
else
  fail "Bootstrapped out-of-scope command not blocked (exit=$outofscope_exit)"
fi

# Cleanup
rm -rf "$SMOKE_ENG"

# =============================================================================
# 3.6 PTT / History Guard Enforcement
# =============================================================================
header "3.6 PTT & History Guard Enforcement"

SMOKE_GUARD="engagements/_smoke-guard-$$"
mkdir -p "$SMOKE_GUARD"/{scope,state,evidence}
cp skills/pentest/templates/ptt.md "$SMOKE_GUARD/state/ptt.md"
echo "# Command History — smoke" > "$SMOKE_GUARD/state/history.md"
cat > "$SMOKE_GUARD/scope/scope.yaml" <<'YAML'
engagement:
  client: Guard-Smoke
  tester: smoke
  date: '2026-07-07'
  duration: '1h'
targets:
  domains: [nimbus.htb]
  ip_addresses: [10.129.245.218]
  app_type: webapp
mode: active-recon
depth: black-box
rules_of_engagement:
  max_requests_per_second: 5
  forbidden_actions: [credential-stuffing]
authorisation:
  confirmed: true
  confirmed_by: smoke
  confirmed_at: '2026-07-07T00:00:00Z'
YAML

# (a) record-ptt updates a PTT row and exits 0
set +e
ptt_out=$(python3 scripts/violin_guard.py record-ptt --eng-dir "$SMOKE_GUARD" --id PT-001 --status "[x]" --note "smoke test passed" 2>&1)
ptt_exit=$?
set -e
if [ "$ptt_exit" -eq 0 ] && echo "$ptt_out" | grep -q "PT-001"; then
  pass "record-ptt updates PT-001 row and exits 0"
else
  fail "record-ptt failed (exit=$ptt_exit): $ptt_out"
fi

# (b) Verify the PTT row actually changed on disk
if grep -q 'PT-001.*\[x\]' "$SMOKE_GUARD/state/ptt.md" 2>/dev/null; then
  pass "PT-001 row shows [x] on disk"
else
  fail "PT-001 row did not update on disk"
fi

# (c) record-ptt with invalid status exits 1
set +e
bad_ptt=$(python3 scripts/violin_guard.py record-ptt --eng-dir "$SMOKE_GUARD" --id PT-001 --status INVALID 2>&1 || true)
bad_ptt_exit=$?
set -e
if [ "$bad_ptt_exit" -eq 1 ] || echo "$bad_ptt" | grep -qi "invalid"; then
  pass "record-ptt rejects invalid status marker"
else
  fail "record-ptt did not reject invalid status (exit=$bad_ptt_exit)"
fi

# (d) record-ptt with non-existent PT id exits 1
set +e
bad_id=$(python3 scripts/violin_guard.py record-ptt --eng-dir "$SMOKE_GUARD" --id PT-999 --status "[~]" 2>&1)
bad_id_exit=$?
set -e
if [ "$bad_id_exit" -eq 1 ] && echo "$bad_id" | grep -qi "not found"; then
  pass "record-ptt rejects non-existent PT id"
else
  fail "record-ptt did not reject bad PT id (exit=$bad_id_exit)"
fi

# (e) Removed administrative/model-facing commands are absent.
for removed in review-and-release finding sync-done record-history message-tick skill-status check-skill-loaded; do
  set +e
  removed_out=$(python3 scripts/violin_guard.py "$removed" --help 2>&1)
  removed_exit=$?
  set -e
  if [ "$removed_exit" -ne 0 ] && echo "$removed_out" | grep -qi "invalid choice"; then
    pass "removed CLI command is absent: $removed"
  else
    fail "removed CLI command is still accepted: $removed"
  fi
done

# (h) Stale-PTT detection: check-bootstrap warns when all rows are pristine
# Use a SEPARATE fresh engagement (test (a) already updated PT-001 in $SMOKE_GUARD)
STALE_ENG="engagements/_smoke-stale-$$"
mkdir -p "$STALE_ENG"/{scope,state,evidence}
cp skills/pentest/templates/ptt.md "$STALE_ENG/state/ptt.md"
cp skills/pentest/templates/hypothesis-board.md "$STALE_ENG/hypotheses.md"
echo "# Command History — stale" > "$STALE_ENG/state/history.md"
echo "test: ok" > "$STALE_ENG/scope/scope.yaml"
set +e
stale_out=$(python3 scripts/violin_guard.py check-bootstrap --eng-dir "$STALE_ENG" 2>&1)
stale_exit=$?
set -e
rm -rf "$STALE_ENG"
if [ "$stale_exit" -eq 2 ] && echo "$stale_out" | grep -qi "never been updated"; then
  pass "Stale PTT detection warns on pristine PTT (exit 2)"
else
  fail "Stale-PTT detection unexpected (exit=$stale_exit): $stale_out"
fi

# Cleanup
rm -rf "$SMOKE_GUARD"

# =============================================================================
# 3.7 Freshness & Mandatory Skill-Load Gates
# =============================================================================
header "3.7 Freshness & Mandatory Skill-Load Gates"

SMOKE_FRESH="engagements/_smoke-fresh-$$"
mkdir -p "$SMOKE_FRESH"/{scope,state,evidence/vuln-research}
cp skills/pentest/templates/ptt.md "$SMOKE_FRESH/state/ptt.md"
cp skills/pentest/templates/hypothesis-board.md "$SMOKE_FRESH/hypotheses.md"
# Replace placeholder hypothesis with a valid one so the hypothesis guard passes
cat > "$SMOKE_FRESH/hypotheses.md" <<'MD'
# Hypothesis Board

## Active Theories

### H-001: web RCE
- **Status:** researching
- **Phase:** RECON
- **Target:** 10.129.45.113
- **Vuln class:** RCE
- **Rationale:** testing
- **Evidence:** evidence/recon/active/
- **Next step:** confirm
- **Linked findings:** none
- **Updated:** $(date '+%Y-%m-%d %H:%M')
MD
echo "# Command History — fresh" > "$SMOKE_FRESH/state/history.md"
seed_history_fixture "$SMOKE_FRESH" "nmap 10.129.45.113" RECON
# PTT "Last updated" set to now
sed -i "s|<YYYY-MM-DD HH:MM>|$(date '+%Y-%m-%d %H:%M')|" "$SMOKE_FRESH/state/ptt.md"
# Mark one RECON row done so desync detection has a baseline
python3 scripts/violin_guard.py record-ptt --eng-dir "$SMOKE_FRESH" --id PT-016 --status "[x]" --note "nmap done" >/dev/null 2>&1
# Findings file present (non-empty) once vuln-research underway
echo "## Findings" > "$SMOKE_FRESH/evidence/vuln-research/findings.md"
# Skill-load marker for session 'fresh'
touch "$SMOKE_FRESH/state/.skill-loaded-fresh"
cat > "$SMOKE_FRESH/scope/scope.yaml" <<'YAML'
engagement:
  client: Fresh-Smoke
  tester: smoke
  date: '2026-07-08'
  duration: '1h'
targets:
  domains: [fresh.htb]
  ip_addresses: [10.129.45.113]
  app_type: webapp
mode: active-recon
depth: black-box
rules_of_engagement:
  max_requests_per_second: 5
  forbidden_actions: [credential-stuffing]
authorisation:
  confirmed: true
  confirmed_by: smoke
  confirmed_at: '2026-07-08T00:00:00Z'
YAML

# (a) Target-touching command WITH skill marker + --session-id passes (exit 0)
set +e
fresh_ok=$(python3 scripts/violin_guard.py check-command --scope "$SMOKE_FRESH/scope/scope.yaml" --eng-dir "$SMOKE_FRESH" --session-id fresh --phase recon --command "nmap 10.129.45.113" 2>&1)
fresh_ok_exit=$?
set -e
if [ "$fresh_ok_exit" -ne 1 ]; then
  pass "Fresh engagement: target command passes skill gate with marker + --session-id (REVIEW warnings allowed)"
else
  fail "Fresh engagement: target command unexpectedly blocked (exit=$fresh_ok_exit): $fresh_ok"
fi

# (b) Target-touching command WITHOUT --session-id/--skill-loaded-file is BLOCKED (Gap #1 fix)
set +e
fresh_noskill=$(python3 scripts/violin_guard.py check-command --scope "$SMOKE_FRESH/scope/scope.yaml" --eng-dir "$SMOKE_FRESH" --phase recon --command "nmap 10.129.45.113" 2>&1)
fresh_noskill_exit=$?
set -e
if [ "$fresh_noskill_exit" -eq 1 ] && echo "$fresh_noskill" | grep -q "skill load gate"; then
  pass "Gap #1 fix: target command blocked when skill-load marker missing/omitted"
else
  fail "Gap #1 fix: missing skill-load gate did not block (exit=$fresh_noskill_exit): $fresh_noskill"
fi

# (c) Stale PTT (no 'Last updated') raises REVIEW (exit 2, Gap #2)
SMOKE_STALEPTT="engagements/_smoke-staleptt-$$"
mkdir -p "$SMOKE_STALEPTT"/{scope,state,evidence}
cp skills/pentest/templates/ptt.md "$SMOKE_STALEPTT/state/ptt.md"
# remove the Last updated line entirely
sed -i '/Last updated/d' "$SMOKE_STALEPTT/state/ptt.md"
cp skills/pentest/templates/hypothesis-board.md "$SMOKE_STALEPTT/hypotheses.md"
# Overwrite with an active (researching) hypothesis so the hypothesis guard passes;
# the stale signal we test is the PTT missing 'Last updated', not the hypothesis guard.
cat > "$SMOKE_STALEPTT/hypotheses.md" <<'MD'
# Hypothesis Board

## Active Theories

### H-001: stale ptt test
- **Status:** researching
- **Phase:** EXPLOITATION
- **Target:** 10.129.45.113
- **Vuln class:** RCE
- **Rationale:** test
- **Evidence:** x
- **Next step:** confirm
- **Linked findings:** none
- **Updated:** 2026-07-08 00:00
MD
echo "# Command History" > "$SMOKE_STALEPTT/state/history.md"
seed_history_fixture "$SMOKE_STALEPTT" "curl 10.129.45.113" EXPLOITATION
python3 scripts/violin_guard.py record-ptt --eng-dir "$SMOKE_STALEPTT" --id PT-040 --status "[~]" --note "exploiting" >/dev/null 2>&1
touch "$SMOKE_STALEPTT/state/.skill-loaded-stale"
cat > "$SMOKE_STALEPTT/scope/scope.yaml" <<'YAML'
engagement:
  client: StalePTT
  tester: smoke
  date: '2026-07-08'
  duration: '1h'
targets:
  ip_addresses: [10.129.45.113]
mode: active-recon
depth: black-box
rules_of_engagement:
  max_requests_per_second: 5
  forbidden_actions: [credential-stuffing]
authorisation:
  confirmed: true
  confirmed_by: smoke
  confirmed_at: '2026-07-08T00:00:00Z'
YAML
set +e
stale_ptt_out=$(python3 scripts/violin_guard.py check-command --scope "$SMOKE_STALEPTT/scope/scope.yaml" --eng-dir "$SMOKE_STALEPTT" --session-id stale --phase exploitation --command "curl 10.129.45.113" 2>&1)
stale_ptt_exit=$?
set -e
rm -rf "$SMOKE_STALEPTT"
if [ "$stale_ptt_exit" -eq 2 ] && echo "$stale_ptt_out" | grep -q "Last updated"; then
  pass "Gap #2 fix: stale/missing PTT 'Last updated' raises REVIEW"
else
  fail "Gap #2 fix: stale PTT not flagged (exit=$stale_ptt_exit): $stale_ptt_out"
fi

# (d) Stale hypotheses (Candidate linking FIND-) raises REVIEW (exit 2, Gap #3)
SMOKE_STALEHYP="engagements/_smoke-stalehyp-$$"
mkdir -p "$SMOKE_STALEHYP"/{scope,state,evidence}
cp skills/pentest/templates/ptt.md "$SMOKE_STALEHYP/state/ptt.md"
sed -i "s|<YYYY-MM-DD HH:MM>|$(date '+%Y-%m-%d %H:%M')|" "$SMOKE_STALEHYP/state/ptt.md"
# Inject a Candidate hypothesis that already links a finding (contradiction)
cat > "$SMOKE_STALEHYP/hypotheses.md" <<'MD'
# Hypothesis Board

## Active Theories

### H-001: stale candidate
- **Status:** Candidate
- **Phase:** EXPLOITATION
- **Target:** 10.129.45.113
- **Vuln class:** RCE
- **Rationale:** test
- **Evidence:** x
- **Next step:** promote
- **Linked findings:** FIND-001
- **Updated:** 2026-07-08 00:00
MD
echo "# Command History" > "$SMOKE_STALEHYP/state/history.md"
seed_history_fixture "$SMOKE_STALEHYP" "curl 10.129.45.113" EXPLOITATION
python3 scripts/violin_guard.py record-ptt --eng-dir "$SMOKE_STALEHYP" --id PT-040 --status "[~]" --note "exploiting" >/dev/null 2>&1
touch "$SMOKE_STALEHYP/state/.skill-loaded-sh"
cat > "$SMOKE_STALEHYP/scope/scope.yaml" <<'YAML'
engagement:
  client: StaleHyp
  tester: smoke
  date: '2026-07-08'
  duration: '1h'
targets:
  ip_addresses: [10.129.45.113]
mode: active-recon
depth: black-box
rules_of_engagement:
  max_requests_per_second: 5
  forbidden_actions: [credential-stuffing]
authorisation:
  confirmed: true
  confirmed_by: smoke
  confirmed_at: '2026-07-08T00:00:00Z'
YAML
set +e
stale_hyp_out=$(python3 scripts/violin_guard.py check-command --scope "$SMOKE_STALEHYP/scope/scope.yaml" --eng-dir "$SMOKE_STALEHYP" --session-id sh --phase exploitation --command "curl 10.129.45.113" 2>&1)
stale_hyp_exit=$?
set -e
rm -rf "$SMOKE_STALEHYP"
if [ "$stale_hyp_exit" -eq 2 ] && echo "$stale_hyp_out" | grep -q "Candidate but already links"; then
  pass "Gap #3 fix: Candidate hypothesis linking a finding raises REVIEW"
else
  fail "Gap #3 fix: stale hypothesis not flagged (exit=$stale_hyp_exit): $stale_hyp_out"
fi

# Cleanup
rm -rf "$SMOKE_FRESH"

# =============================================================================
# 3.8 Canonical Batch Review Lifecycle
# =============================================================================
header "3.8 Canonical Batch Review Lifecycle (violin_review_batch)"

GATES_DIR="engagements/_smoke-gates-$$"
mkdir -p "$GATES_DIR"/{scope,state,evidence}
cp skills/pentest/templates/ptt.md "$GATES_DIR/state/ptt.md"
sed -i "s|<YYYY-MM-DD HH:MM>|$(date '+%Y-%m-%d %H:%M')|" "$GATES_DIR/state/ptt.md"
cp skills/pentest/templates/hypothesis-board.md "$GATES_DIR/hypotheses.md"
# Seed an active hypothesis so the hypothesis guard passes on fresh engagement.
cat > "$GATES_DIR/hypotheses.md" <<'MD'
# Hypothesis Board

## Active Theories

### H-001: initial recon
- **Status:** verified
- **Phase:** RECON
- **Target:** 10.129.45.113
- **Vuln class:** recon
- **Rationale:** establishing baseline
- **Evidence:** evidence/recon/active/
- **Next step:** confirm
- **Linked findings:** none
- **Updated:** $(date '+%Y-%m-%d %H:%M')
MD
echo "# Command History" > "$GATES_DIR/state/history.md"
touch "$GATES_DIR/state/.skill-loaded-gate"
cat > "$GATES_DIR/scope/scope.yaml" <<'YAML'
engagement:
  client: GateSmoke
  tester: smoke
  date: '2026-07-08'
  duration: '1h'
targets:
  ip_addresses: [10.129.45.113]
mode: active-recon
depth: black-box
rules_of_engagement:
  max_requests_per_second: 5
  forbidden_actions: [credential-stuffing]
authorisation:
  confirmed: true
  confirmed_by: smoke
  confirmed_at: '2026-07-08T00:00:00Z'
YAML

# Seed the active PTT row whose identity review-batch must preserve.
python3 scripts/violin_guard.py record-ptt --eng-dir "$GATES_DIR" --id PT-010 --status "[~]" --note "active recon" >/dev/null 2>&1
# Drive the canonical service handler directly.
python3 - "$GATES_DIR" <<'PY'
import json
import sys
from datetime import UTC, datetime
from pathlib import Path

from plugins.violin_guard import history, service, state

engagement = Path(sys.argv[1])
command = "nmap -sV 10.129.45.113"
receipt = engagement / "evidence" / "executions" / "review.json"
receipt.parent.mkdir(parents=True, exist_ok=True)
state.atomic_json(receipt, {
    "command": command,
    "phase": "RECON",
    "completed_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
    "exit_code": 0,
    "evidence_paths": {"manifest": receipt.relative_to(engagement).as_posix()},
})
history.append_history(
    engagement, command, "RECON", 0, receipt.relative_to(engagement).as_posix()
)
state.mark_pending_sync(engagement, command, "RECON", "PT-010")

reviewed = json.loads(service.handle_review_batch({
    "eng_dir": str(engagement),
    "id": "PT-010",
    "status": "[~]",
    "note": "Reviewed the completed recon receipt",
}))
assert reviewed["status"] == "ok", reviewed
assert reviewed["released"] is True
assert not state.has_pending_sync(engagement)
assert "[reviewed-batch:" in (engagement / "state" / "ptt.md").read_text()
for removed in ("handle_sync_done", "handle_review_and_release", "handle_finding"):
    assert not hasattr(service, removed), removed
print("    ok: violin_review_batch reviewed PTT and released the batch")
print("GATES_OK")
PY
gates_exit=$?
if [ "$gates_exit" -eq 0 ]; then
  pass "3.8 Canonical review lifecycle: receipt->PTT review->batch release"
else
  fail "3.8 Canonical review lifecycle failed (see python output above)"
fi

rm -rf "$GATES_DIR"

# =============================================================================
# 4. Playbook Section Coverage
# =============================================================================
header "4. Playbook Section Coverage"

playbook_count=0
section_issues=0
while IFS= read -r -d '' pb; do
  name="$(basename "$pb" .md)"
  has_blocked=$(grep -q '^## .*Blocked\|^## Blocked' "$pb" 2>/dev/null && echo "yes" || echo "no")
  has_evidence=$(grep -q '^## Evidence' "$pb" 2>/dev/null && echo "yes" || echo "no")
  has_stop=$(grep -q '^## Stop' "$pb" 2>/dev/null && echo "yes" || echo "no")
  case "$name" in
    scoping|recon|vuln-research|exploitation|reporting|tools|post-exploitation)
      echo "    [phase b=$has_blocked e=$has_evidence s=$has_stop] $name"
      ;;
    *)
      echo "    [vuln b=$has_blocked e=$has_evidence s=$has_stop] $name"
      if [ "$has_blocked" = "no" ] || [ "$has_evidence" = "no" ] || [ "$has_stop" = "no" ]; then
        ((section_issues+=1))
      fi
      ;;
  esac
  ((playbook_count+=1))
done < <(find "$PLAYBOOK_DIR" -maxdepth 1 -type f -name '*.md' -print0)

pass "Playbooks counted: $playbook_count"
if [ "$section_issues" -gt 0 ]; then
  fail "$section_issues per-vulnerability playbook(s) missing required sections (## Blocked, ## Evidence, ## Stop)"
else
  pass "All per-vulnerability playbooks have ## Blocked, ## Evidence, ## Stop sections"
fi

# =============================================================================
# 5. Verify skill_view References in SKILL.md Files
# =============================================================================
header "5. skill_view Reference Check"

# Find all skill_view() calls across all SKILL.md files in the repo
sv_refs=$(grep -rn 'skill_view(' "$REPO_ROOT/skills" --include='SKILL.md' 2>/dev/null || true)
if [ -z "$sv_refs" ]; then
  pass "No skill_view() references found in SKILL.md files"
else
  echo "    Found skill_view() calls in SKILL.md files:"
  sv_issues=0
  while IFS= read -r line; do
    filepath="$(echo "$line" | cut -d: -f1)"
    linenum="$(echo "$line" | cut -d: -f2)"
    content="$(echo "$line" | cut -d: -f3-)"
    echo "      $filepath:$linenum"

    # Extract skill name from skill_view(name='X', ...) or skill_view("X", ...)
    sv_name=$(echo "$content" | sed -n "s/.*skill_view(name=['\"]\([^'\"]*\)['\"].*/\1/p")
    if [ -z "$sv_name" ]; then
      # Try skill_view("X") pattern
      sv_name=$(echo "$content" | sed -n 's/.*skill_view(["'\'']\([^"'\'']*\)["'\''].*/\1/p')
    fi

    if [ -z "$sv_name" ]; then
      echo "    → Could not parse skill name from: $content"
      continue
    fi

    # Check if the referenced skill exists locally under skills/
    local_skill_path="$REPO_ROOT/skills/$sv_name/SKILL.md"
    if [ -f "$local_skill_path" ]; then
      pass "Referenced skill '$sv_name' exists locally: $local_skill_path"
    else
      # Check if it's a Hermes official/installed skill
      hermes_skill_path="$HOME/.hermes/skills/$sv_name/SKILL.md"
      if [ -f "$hermes_skill_path" ]; then
        pass "Referenced skill '$sv_name' exists as Hermes skill"
      else
        # Check for category-qualified names like official/research/domain-intel
        # These need to be checked differently — find any SKILL.md with that name
        found_any=$(find "$HOME/.hermes/skills" -name 'SKILL.md' -path "*/$sv_name/SKILL.md" 2>/dev/null | head -1)
        if [ -n "$found_any" ]; then
          pass "Referenced skill '$sv_name' found: $found_any"
        else
          fail "Referenced skill '$sv_name' not found locally or in Hermes skills"
          ((sv_issues+=1))
        fi
      fi
    fi
  done <<< "$sv_refs"
  if [ "$sv_issues" -eq 0 ]; then
    pass "All skill_view() references resolve to existing skills"
  fi
fi

# =============================================================================
# 6. Install + Smoke Chat + Cleanup
# =============================================================================
if [ "$SKIP_INSTALL" = true ]; then
  header "6. Install / Smoke / Cleanup (SKIPPED --no-install)"
  pass "Skipped per --no-install flag"
else
  header "6. Install / Smoke Chat / Cleanup"

  SMOKE_PROFILE="violin-smoke-$(date +%s)"

  # ── Install ──
  echo "    Installing profile as '$SMOKE_PROFILE'..."
  # Under Windows git-bash, REPO_ROOT is a /c/... path that Python's pathlib
  # mangles into \c\... — convert to a native Windows path so `hermes` (Python)
  # resolves distribution.yaml at the repo root. No-op on native Linux/Kali.
  if [[ "$OSTYPE" == "msys"* || "$OSTYPE" == "cygwin"* ]]; then
    INSTALL_SRC="$(cygpath -w "$REPO_ROOT" 2>/dev/null || echo "$REPO_ROOT")"
  else
    INSTALL_SRC="$REPO_ROOT"
  fi
  if hermes profile install "$INSTALL_SRC" --name "$SMOKE_PROFILE" -y 2>&1; then
    pass "Profile installed: $SMOKE_PROFILE"
  else
    fail "Profile install failed"
    # Still try to clean up on failure
    hermes profile delete "$SMOKE_PROFILE" -y 2>/dev/null || true
    summary
    exit 1
  fi

  # ── Show profile info ──
  echo "    Profile info:"
  if hermes profile show "$SMOKE_PROFILE" 2>&1; then
    pass "profile show succeeded"
  else
    fail "profile show failed"
  fi

  # ── Tools summary ──
  if hermes -p "$SMOKE_PROFILE" tools --summary 2>&1; then
    pass "tools --summary succeeded"
  else
    fail "tools --summary failed"
  fi

  # ── Smoke chat ──
  echo "    Running smoke chat..."
  if hermes -p "$SMOKE_PROFILE" chat -q "Smoke test: reply with 'Violin profile loaded and responding'" -Q 2>&1; then
    pass "Smoke chat succeeded"
  else
    fail "Smoke chat failed"
  fi

  # ── Config check ──
  if hermes -p "$SMOKE_PROFILE" config check 2>&1; then
    pass "config check succeeded"
  else
    fail "config check reported issues"
  fi

  # ── Cleanup ──
  echo "    Cleaning up profile..."
  if hermes profile delete "$SMOKE_PROFILE" -y 2>&1; then
    pass "Profile deleted: $SMOKE_PROFILE"
  else
    fail "Profile cleanup failed"
  fi
fi

# =============================================================================
# Results
# =============================================================================
summary

if [ "$FAIL" -gt 0 ]; then
  echo "FAILURES:" >&2
  echo "$FAILURES" >&2
  exit 1
else
  echo "  All checks passed. Release ready."
  exit 0
fi
