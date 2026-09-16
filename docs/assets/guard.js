// Illustrative scenarios. This page never executes target commands.

const scenarioBtns = document.querySelectorAll(".scenario-btn");
const overallStatus = document.getElementById("sim-overall-status");
const simOutput = document.getElementById("sim-output");
const gates = {
  g1: document.getElementById("g1"),
  g2: document.getElementById("g2"),
  g3: document.getElementById("g3"),
  g4: document.getElementById("g4"),
  g5: document.getElementById("g5"),
  g6: document.getElementById("g6"),
  g7: document.getElementById("g7"),
};

const scenarios = {
  recon: {
    statusClass: "pass",
    statusText: "PASSED · SIGNED",
    gates: {
      g1: "PASS",
      g2: "PASS",
      g3: "PASS",
      g4: "PASS",
      g5: "PASS",
      g6: "PASS",
      g7: "PASS",
    },
    output: `// Invocation:
violin_exec(
  phase   = "RECON",
  target  = "app.example.com",
  command = "nmap -sV -sC app.example.com"
)
→ GATES PASSED (7/7)
→ Receipt sealed and signed:
{
  "status": "ok",
  "target": "app.example.com",
  "phase": "RECON",
  "receipt_hmac_sha256": "9f2c41d8...a7",
  "receipt_ed25519": "ed25519:MEUCIQDk3f...",
  "evidence_sha256": ["3b1f8c04...", "c07a2e91..."]
}`,
  },
  scope_deny: {
    statusClass: "fail",
    statusText: "FAIL CLOSED · DENIED",
    gates: {
      g1: "PASS",
      g2: "DENIED",
      g3: "SKIP",
      g4: "SKIP",
      g5: "SKIP",
      g6: "SKIP",
      g7: "SKIP",
    },
    output: `// Invocation:
violin_exec(
  phase   = "RECON",
  target  = "internal.corp",
  command = "curl -i https://internal.corp/admin"
)
→ SCOPE GATE: target resolution failed
→ Target 'internal.corp' not in scope.yaml targets: ['app.example.com']
→ Execution BLOCKED at boundary (fail-closed)
→ Return to an authorized target. Scope changes require renewed written approval.`,
  },
  destructive_deny: {
    statusClass: "fail",
    statusText: "DANGEROUS · BLOCKED",
    gates: {
      g1: "PASS",
      g2: "PASS",
      g3: "PASS",
      g4: "PASS",
      g5: "PASS",
      g6: "PASS",
      g7: "BLOCKED",
    },
    output: `// Invocation:
violin_exec(
  phase   = "EXPLOITATION",
  target  = "app.example.com",
  command = "rm -rf /var/log/*"
)
→ COMMAND GATE: destructive pattern matched
→ Destructive filesystem payload pattern matched: 'rm -rf'
→ Execution blocked in this illustrative scenario.`,
  },
  phase_deny: {
    statusClass: "fail",
    statusText: "PHASE DESYNC · DENIED",
    gates: {
      g1: "PASS",
      g2: "PASS",
      g3: "DENIED",
      g4: "SKIP",
      g5: "SKIP",
      g6: "SKIP",
      g7: "SKIP",
    },
    output: `// Invocation:
violin_exec(
  phase   = "RECON",
  target  = "app.example.com",
  command = "sqlmap -u 'http://app.example.com/item?id=1' --batch"
)
→ PHASE GATE: no active task under that phase
→ Active PTT task is under phase 'RECON', but exploit tool 'sqlmap' requires 'EXPLOITATION'.
→ Denied until an active task under EXPLOITATION is started.`,
  },
};

scenarioBtns.forEach((btn) => {
  btn.setAttribute("aria-pressed", String(btn.classList.contains("active")));
  btn.addEventListener("click", () => {
    scenarioBtns.forEach((b) => {
      b.classList.remove("active");
      b.setAttribute("aria-pressed", "false");
    });
    btn.classList.add("active");
    btn.setAttribute("aria-pressed", "true");
    const scKey = btn.getAttribute("data-scenario");
    const sc = scenarios[scKey];
    if (!sc) return;

    if (overallStatus) {
      overallStatus.className = "sim-status " + sc.statusClass;
      overallStatus.textContent = sc.statusText;
    }

    for (let i = 1; i <= 7; i++) {
      const badge = gates["g" + i];
      const val = sc.gates["g" + i];
      if (badge) {
        badge.textContent = val;
        badge.className =
          "gate-badge " +
          (val === "PASS"
            ? "ok"
            : val === "DENIED" || val === "BLOCKED"
              ? "deny"
              : "skip");
      }
    }

    if (simOutput) simOutput.textContent = sc.output;
  });
});
