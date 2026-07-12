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
  if hermes profile install "$REPO_ROOT" --name "$SMOKE_PROFILE" -y 2>&1; then
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
