# Violin Launch Kit (PROMOTION.md)

A copy-paste playbook for promoting Violin, the supervised agentic pentest profile for Hermes Agent. Every post below is finished copy. The only gaps are things only you know, marked `[[...]]`.

---

## How to use this kit

1. Read the "Repo facts cheat sheet" below and keep it pinned while you post. Every hard number in this kit is grounded in the repo files: README.md, docs/BENCHMARKS.md, CHANGELOG.md, SECURITY.md, CONTRIBUTING.md, and the skill playbooks. Do not invent beyond them.
2. Run the 10-day sequence in section 2. It is ordered so content lands first, then the high-signal post (Hacker News), then communities, so there is material to link back to.
3. Copy posts verbatim per platform. Edit only the `[[...]]` slots.
4. Never post about targeting any system you do not own or lack written authorization to test. No client data, no engagement evidence, no real-target detail. Example targets stay in your local lab or deliberately vulnerable apps (section 12).
5. Track the numbers in section 10 weekly and cut channels that produce nothing after three attempts.

---

## Repo facts cheat sheet

| Field | Value |
|---|---|
| Name | Violin |
| One-liner | An open-source, supervised agentic penetration-testing profile for Hermes Agent with a required execution guard, evidence-backed findings, and engagement state that survives context compression. |
| Install | `hermes profile install https://github.com/Strategic-Automation/violin` |
| License | MIT (Copyright (c) 2026 Violin contributors) |
| Requirements | Hermes Agent 0.18.0+, Python 3.11 + `uv` for dev, Kali Linux or Parrot OS, written authorization and an approved scope |
| Current stars | 88 |
| Version | 3.2.1 |
| Surface | 12 registered tools, 7 routed skills, 35 playbooks (verified: 9 pentest + 13 web-app + 6 identity-auth + 1 api-testing + 1 business-logic + 2 llm-security + 3 misconfig), 19 references, 15 templates |
| Repo | https://github.com/Strategic-Automation/violin |
| Docs | https://hermes-agent.nousresearch.com (host platform); BENCHMARKS.md for the only documented benchmark claims |
| Benchmark status | The repo publishes its benchmark methodology and treats a single agentic run as a noisy sample. No live agent score is documented, so claim none. |
| Maintainer org | Strategic Automation Ltd (sponsor link in README) |

Important framing rule: the repository documents that a single agentic run is a noisy sample and that calibration is not a live benchmark result (docs/BENCHMARKS.md). Never post a "Violin scored X/20" figure; it is not in the repo.

---

## 1. Positioning + the one-liner

**The one-liner** (use verbatim in bios, signatures, and directory descriptions):

> Violin is an open-source, MIT-licensed Hermes Agent profile that runs authorization-scoped penetration tests where every target-touching command passes a required execution guard, gets a signed receipt, and feeds evidence-backed findings and reports.

**Three core talking points** (build every post around one or two of these):

1. **The guard is required, not a soft confirm.** Before a target command runs, `violin-exec` checks scope, phase, the active PTT task, the routed skill, the hypothesis, and execution history. Denials fail closed and give the operator the exact typed tool call needed to proceed. This is accountable AI-assisted testing, not a wrapper around a chat model with shell access.
2. **Findings are evidence-backed.** A validated finding must bind to signed execution receipts. The report is derived from receipt-backed evidence, not model prose. For consulting and audit, that is the difference between "the tool says so" and "here is the request, the response, and the receipt that authenticate it."
3. **Engagement state survives context compression.** PTT tasks, hypotheses, checkpoints, and evidence resume from engagement files when the conversation is compacted. Long engagements do not lose the plot.

**Three objections to expect** (answered copy in sections 3 and 11):

1. "This is just ChatGPT or Claude handed a shell. What is actually new?"
2. "AI pentesting is a gimmick; it just writes pretty reports."
3. "Is it safe? How do I know it won't hit things out of scope?"

---

## 2. Timing + sequencing (10-day plan)

Order matters: content first establishes the story, then the single most-important post (Hacker News) points at it, then communities amplify, then directories and outreach consolidate searchable presence.

**Why this order.** Hacker News is the highest-leverage single post because its audience is exactly your users (builders who maintain the tooling Violin routes to, and people who have tried and been burned by agentic tools). One good Show HN drives more installs and GitHub-following attention than anything else here, and its comments become the FAQ you reuse everywhere else. Communities and newsletters amplify after HN exists to link to, because there is then a public discussion to reference. Directories are low-effort SEO tail and can be done in parallel.

| Day | Action | Why this slot |
|---|---|---|
| Day 1 | Publish the 4-article content base (section 7, posts 1-2 at minimum) | Content ready before anything links to it |
| Day 2-3 | Show HN post + author context comment (section 3). Plan to check replies for 3-5 hours after posting | HN is the single most important post; do it when you can be present to engage |
| Day 4 | X thread + standalone post (section 5) | Ride any HN interest; link the article that survived contact |
| Day 5 | r/netsec technical write-up (section 4) | Deliberately separated from HN to avoid "spamming every channel on day 1" |
| Day 6-7 | Remaining subreddit posts (section 4), one community per subreddit, spaced out | Avoid flooding; each subreddit gets a distinct angle, not the same link 6 times |
| Day 8 | LinkedIn post + comment (section 6); directories: Product Hunt, AlternativeTo (section 9) | Professional + SEO surfaces |
| Day 9 | Newsletter + podcast + YouTuber pitches (section 8) | Time for them to respond after the public discussion exists |
| Day 10 | Build-in-public cadence begins (section 7 posts 3-4); measure first week (section 10) | Turn launch into a habit |

**What to avoid:**

- Do NOT post the same link to six subreddits in one hour. It reads as spam and gets you banned. Space subreddit posts over days and vary the copy and angle per subreddit.
- Do NOT lead with "I built X, try it!" anywhere. Lead with the problem or the engineering.
- Do NOT repeat the exact one-liner in every post; it reads templated. Vary emphasis per channel.
- Do NOT claim a benchmark score. The repo documents no live score, only calibration.
- Do NOT present yourself as anything but the maintainer. Disclose authorship in every community post (native on HN, mandatory on Reddit, natural on LinkedIn).

**The single post that matters most: Hacker News.** It is the one that reaches your actual target user at scale, produces durable criticism you can fold into the roadmap, and gives every other channel a credible third-party discussion to link to. Budget the most time there.

---

## 3. Hacker News

### Show HN title (primary, <= 80 chars)

`Show HN: Violin – a guarded, supervised agentic pentest profile for Hermes`

(44 chars of that is the title core; the "Show HN:" prefix and punctuation keep it under 80.)

### 5 alternate titles

1. `Show HN: Violin – agentic pentesting with a required execution guard`
2. `Show HN: An agentic pentest profile where every command needs a signed receipt`
3. `Show HN: I built an LLM pentester that fails closed on scope`
4. `Show HN: Receipt-backed findings for AI-assisted penetration testing`
5. `Show HN: Supervised agentic recon-to-report pentesting, MIT licensed`

### First comment (the author's context comment), 150-250 words

Target: about 210 words.

> Author here. Violin is an MIT-licensed profile for Hermes Agent that runs authorized penetration tests from reconnaissance through exploit validation to reporting. The thing I want pressure-tested is the guard, not the model.
>
> Every command that touches a target passes through a required execution guard before it runs. The guard checks scope, the current phase, the active PTT task, the routed skill, the stated hypothesis, and execution history, and it fails closed with the exact typed tool call you need to proceed. Findings are bound to signed execution receipts, so a report is "here is the request, here is the response, here is the receipt authenticating both," not "the model said so." Engagement state is written to disk, so PTT tasks, hypotheses, and checkpoints survive context compression.
>
> Honest limits. The repo ships a benchmark harness and documents its methodology, but it publishes no live agent score, because a single agentic run is a noisy sample. If I post a number it will be a distribution across repeated runs, per docs/BENCHMARKS.md. A harness that runs is not the same thing as a tool that reliably finds bugs, and I am not going to pretend otherwise.
>
> It is for authorized testing only, and the guard enforces that by policy.
>
> What I want back: (1) is the required-guard model actually usable in a real engagement, or is it friction without value? (2) Which vulnerability classes are least reliable and worth playbooks? The README and install command are in the repo.

### Pre-written answers to the four standard skeptics

**Q: "How is this different from just using Claude or GPT with shell access?"**
> Fair question. The difference is the enforcement boundary, not the model. Prompt a general agent and it will try things and hope it stays in scope; if you want guardrails you bolt them on afterwards and they are advisory. Violin sits in the tool layer, not the prompt layer. A target command cannot run unless the guard validates scope, phase, task, skill, hypothesis and history against schema-validated state, and fails closed. It also gives you verifiable artifacts: each execution gets a signed receipt and findings are bound to those receipts. So the answer to "did it actually do this" is a file, not a claim. You are right that the underlying model is interchangeable; read the README, it says the same thing. The profile deliberately does not pick a model or provider.

**Q: "AI pentesting is a gimmick, it just writes reports."**
> The report-writing part is close to the least useful thing it does, so I'll grant the skepticism and pivot. The value I am claiming is different: enforced methodology and auditable evidence. It will not let you skip from recon to exploitation without a valid phase task, and it will not credit a finding that lacks a signed execution receipt. The report generator derives findings.yaml and the closeout from verified FIND-NNN artifacts, not from prose. So if your objection is "LLMs hallucinate confident narratives," Violin is built so that a confident claim with no receipt gets zero credit. That is a testable property, and docs/BENCHMARKS.md documents how evidence is separated from report prose.

**Q: "What about scope violations? Is this safe?"**
> Scope enforcement is the core design, so this is the right thing to stress. The guard parses commands with AST-based tooling (bashlex, yarl, netaddr) to resolve hosts, URLs, IP/CIDR and compound commands, and it denies anything outside the approved scope target, fail-closed, with the exact next step. It will not run a target command at all until scope approval and bootstrap validation pass. It blocks destructiveness, disruption, credential access, persistence, stealth, and anything affecting third parties without explicit written authorization. Two caveats I want to state plainly: the raw-terminal hook is a best-effort safety net, not network containment, and this is for targets you own or have written authorization for. Nothing here removes operator responsibility.

**Q: "Isn't the benchmark self-serving or unreal?"**
> I understand why it reads that way, and I've tried to make it hard to hide behind. Two things. First, the repo does not publish a live score at all, precisely because a one-off agentic run is noise; the methodology in docs/BENCHMARKS.md documents the non-determinism doctrine and says to report mean pass@1 across at least three runs, not the best run. Second, the evaluation does not score report prose: only receipt-backed findings are considered, and the receipts are authenticated before they count. So the incentive is to make the evidence honest, because a pretty report with no receipt earns nothing.

---

## 4. Reddit

General rules that apply to every post:
- Disclose you are the maintainer in the first or second line. Reddit penalizes undisclosed self-promotion; disclosed self-posts with substance are tolerated.
- Do not use the same title or body in more than two subreddits, and wait at least a day between different subreddits.
- Do not drop the raw install command as the entire post. Lead with substance, link the repo once.

### r/netsec (reception + rules)

Note: **r/netsec rejects tool announcements as submissions.** A bare "I made a pentest tool, here is the repo" will be removed. The submission must be a substantive technical write-up that leads with an engineering problem. Post it as a technical article, not a link to the repo. Keep audience tone professional, first-person-plural, no hype.

**Title:**
`Scope enforcement in an agentic penetration-testing loop`

**Body (self-post):**
> A model given shell access will, sooner or later, run something it should not. Prompting discipline does not fix this, because the failure mode is orthogonal to instruction following: the model confidently acts on a target assumption that is wrong, and there is no enforcement point between intent and execution. This is a design post about putting an enforcement boundary in the tool layer rather than the prompt layer, in the context of an open-source, authorization-scoped agentic pentest profile (MIT). Disclosure: I maintain it. Repo link at the end.
>
> The boundary is a required execution guard between the agent and every command that touches a target. Before a command runs, the guard validates, against schema-validated engagement state: the approved scope (host, URL, IP/CIDR, with exclusions), the current phase, the active PTT task under that phase, the routed skill, the stated hypothesis, and execution history. Compound commands are parsed with AST tooling (bashlex, yarl, netaddr) so pipelines, subshells, and redirections are checked independently rather than against a regex of "allowed binaries." There is no binary allowlist by design, because allowlists rot; the scope and phase gates are the invariant.
>
> The evaluation side is worth attention too. Findings are only credited when they bind to a signed execution receipt, and the evaluation reads only receipt-backed evidence, never report prose, so a confident narrative with no evidence earns zero. The project also refuses to treat a working harness as a live benchmark, because a single agentic run is a noisy sample.
>
> Open questions I would like this community's take on: is a hard guard in the tool layer net-positive on a real engagement, or is the friction unacceptable before a second model provider arrives? And are AST-based scope parsers enough, or do we need network-layer containment to make an honesty claim? Repo: https://github.com/Strategic-Automation/violin (MIT, install via `hermes profile install` as a Hermes Agent profile).

### r/cybersecurity

**Reception:** broad professional + student audience, tolerant of open source projects if the post has substance and a clear disclosure. Titles should frame value for practitioners, not enthusiasts.

**Title:**
`I built an open-source, authorization-scoped agentic pentest profile. Here is how it enforces scope.`

**Body:**
> Maintainer here, disclosure up front. I release a lot of security tooling, and most of the questions I get are not "does it find anything" but "will this run something I did not authorize." So I built the enforcement into the tool rather than into a prompt.
>
> Violin is an MIT-licensed profile for Hermes Agent that runs an authorized assessment from recon to reporting. Every command that could touch the target passes a required guard first. The guard checks the approved scope against the resolved host, URL, IP/CIDR with exclusions; checks the current phase against the active PTT task; checks the routed skill and hypothesis; and rejects anything that fails, closed, with the exact next step. Commands are parsed with an AST, so a pipeline or subshell does not slip past a keyword check. Findings bind to signed execution receipts, so the report is auditable: request, response, and receipt.
>
> It is deliberately not a stance on "AI can replace testers." It is an attempt to make AI-assisted testing accountable enough that a consultant can hand a client a defensible chain of evidence. It is also honest about its limits: the repo documents benchmark methodology and calibration, but no live score, because single agentic runs are noise.
>
> Worth a look if you have been burned by LLM tools that produce confident reports with no way to verify them, or if you just want to test the guard model against your own scope policy. Install: `hermes profile install https://github.com/Strategic-Automation/violin`. Only use it on targets you own or have written authorization to test.

### r/AskNetsec

**Reception:** Q&A-focused; direct posts that answer a question people ask do well. A "here is how I solved X" is acceptable with disclosure. Keep it humble and shorter.

**Title:**
`How do you stop an LLM pentester from running things out of scope? (Built a required guard; feedback welcome)`

**Body:**
> Maintainer here. Question I keep getting from in-scope work: how do you actually stop an agent with shell access from touching the thing it should not, when a prompt tells it not to and it does anyway? My answer, in an open-source profile I maintain, is to move the check out of the prompt and into the execution path.
>
> Before a target command runs, a guard validates scope (resolved host/URL/CIDR plus exclusions against the approved target), the current phase against an active task, the routed skill, the hypothesis, and prior history. Command parsing is AST-based, so `foo; malicious_host` and pipelines are checked as whole structures, not matched against a list of "safe" binaries. The instance fails closed and returns the exact typed call to proceed.
>
> It also makes findings auditable: each execution gets a signed receipt and a validated finding must bind to one, so a report is evidence, not an assertion.
>
> I would honestly like pushback on two points: is a hard guard in the tool layer the right level, or should containment also be at the network layer to earn a real safety claim? And is the friction acceptable on real engagements? Repo if you want details: https://github.com/Strategic-Automation/violin. It is MIT and installs as `hermes profile install https://github.com/Strategic-Automation/violin`. Authorized targets only.

### r/LLMDevs

**Reception:** constructive engineering crowd that likes typed boundaries, state, and honest evals. Focus on tool-layer enforcement and the benchmark methodology.

**Title:**
`Mandatory not advisory: enforcing an execution guard in an LLM tool loop`

**Body:**
> Tool-calling agents that act on the environment have a boundary problem: the model is told "stay in scope," it believes it is, and it acts anyway. Advisory guardrails are instructions; they are not enforcement. For an open-source agentic profile I maintain (MIT, disclosure), I made the guard mandatory at the tool boundary.
>
> The architecture: a plugin registers eleven typed Hermes tools. The one that runs a target command (`violin-exec`) is the only path to the target, and it validates scope, phase, active task, routed skill, hypothesis, and history before it will run anything. State is schema-validated on disk and survives context compression, so PTT tasks, hypotheses and checkpoints resume across compacted conversations. Findings must bind to signed execution receipts, which is what makes the eval interesting to me as an LLM-dev thing.
>
> The eval side is where I hope LLM developers will engage most. The repo ships a benchmark harness but declines to post a live score. The methodology (docs/BENCHMARKS.md) treats a single run as a noisy sample, requires a distribution rather than a best run, and counts only receipt-backed evidence, which is why report prose cannot talk its way to credit.
>
> If you have opinions on where tool-layer enforcement breaks down, or on what a credible agentic security eval looks like, the repo issues and README are open. https://github.com/Strategic-Automation/violin

### r/AI_Agents

**Reception:** focused on agent architectures, reliability, and evaluation. Emphasize state persistence, the guard as an agent control, and honest evaluation. Disclosure required.

**Title:**
`A required execution guard as an agent control: structural notes + a working open-source example`

**Body:**
> Disclosure: I maintain the project this references. Posting because I think the control pattern generalizes.
>
> For any agent that can touch a real environment, the highest-value control is not better prompting, it is an authoritative gate in tool space. Violin, an MIT agentic pentest profile, implements this as a required guard on the single tool path that can run a target command. The guard validates scope against the resolved request (host, URL, IP/CIDR, exclusions), the phase against an active task, the routed skill, the stated hypothesis, and history, and fails closed with a typed next-step hint. Compound commands are parsed with an AST so the gate sees pipelines and subshells, not just the base binary.
>
> Two other choices worth copying: (1) engagement state is persisted schema-validated on disk so context compression does not lose tasks, hypotheses, or checkpoints; (2) outputs are bound to signed receipts and a finding only counts if it carries one. That last one matters for agents where you need verifiability, because it stops a confident narrative from standing in for evidence.
>
> Evaluation is handled the same way: only receipt-backed submissions are credited, and the repo publishes methodology rather than a live score, because a single agentic run is a noisy sample (methodology in docs/BENCHMARKS.md). If you build agents for safety-critical or liability-heavy domains, I would be interested in how you handle the enforcement-vs-friction tradeoff. Repo: https://github.com/Strategic-Automation/violin

### r/opensource

**Reception:** welcoming of launch posts with disclosure and a contributability angle. Lead with "new MIT project, help shape it." Contributors and methodology-curious people live here.

**Title:**
`New MIT project: Violin, a supervised agentic pentest profile for Hermes (contributors welcome)`

**Body:**
> I just open-sourced a project I have been hardening for a while and I want contributors and early reviewers. Disclosure: maintainer here.
>
> Violin is an MIT-licensed profile for Hermes Agent that turns an authorized penetration test into a supervised, auditable workflow: recon, vulnerability research, exploit validation, and reporting, all routed across seven skills and 35 playbooks (web, identity, API, business logic, LLM security, misconfig). The distinguishing piece is a required execution guard between the agent and any target-touching command, plus evidence-backed findings bound to signed receipts. It is built for authorization-scoped work only.
>
> It already has a release gate that runs the full test suite, lint, schemas, skill snapshots and doc contracts before anything ships, so the bar for a clean PR is explicit (see CONTRIBUTING.md). Current stack is Python 3.11, Pydantic v2, uv.
>
> Where I most want help: new vulnerability-class playbooks, hardening the real-engagement workflow, and honest evaluation runs. If you have wanted to touch an agentic security project without the hype, this is a small, documented codebase. Install: `hermes profile install https://github.com/Strategic-Automation/violin`. Repo: https://github.com/Strategic-Automation/violin

### r/Pentesting

**Reception:** working pentesters; most skeptical of "AI does your job" and most alert to safety framing. Speak their language: auditability, chain of evidence, and honest limits. Do not oversell recall.

**Title:**
`Supervised agentic pentesting: an open-source profile where findings must carry a signed receipt`

**Body:**
> Maintainer, disclosure up front. Thread from a working-tester angle, not hype.
>
> What interests me about agents in this field is not recall, it is auditability. A report that says "found X, critical" is only worth what the chain of evidence supports. Violin is an MIT profile for Hermes Agent that treats that literally: every target command has to pass a required guard before it runs, and every validated finding has to bind to a signed execution receipt, so the deliverable maps to request, response, and receipt.
>
> The guard checks scope against resolved host/URL/IP/CIDR plus exclusions, the current phase against an active task, the routed skill, the hypothesis, and history, and fails closed with the exact next typed call. Command parsing is AST-based so compound commands do not slip past a keyword filter. It routes methodology across seven skills and 35 playbooks and persists engagement state, so you can close a session and resume without losing PTT tasks or evidence.
>
> Honest about limits: the repo ships benchmark calibration and methodology, not a live score, because a single agentic run is a noisy sample. It is for authorized targets only and the guard enforces that by policy.
>
> If you would put an agent on a real authorized engagement tomorrow, the friction question is the one I want your take on: is a hard guard net-positive, or does it slow you down more than it protects you? Repo: https://github.com/Strategic-Automation/violin

---

## 5. X / Twitter

### Thread (7 posts, each <= 270 chars, numbered)

Post 1:
**1/** Most "AI pentesting" is a chat model with a shell and a lot of confidence. The output is only as trustworthy as the evidence behind it. That is the problem I set out to solve.

Post 2:
**2/** The fix is not a better prompt. It is an enforcement boundary in the tool layer. In Violin, an agentic pentest profile for Hermes Agent, every target-touching command must pass a required guard first.

Post 3:
**3/** The guard validates scope (host, URL, IP/CIDR, exclusions), the current phase, the active task, the routed skill, the hypothesis, and history. Fails closed. No allowlist rot; the scope is the invariant.

Post 4:
**4/** Findings bind to signed execution receipts. A validated finding means "here is the request, the response, and the receipt authenticating both," not "the model said so." That is what makes it auditable.

Post 5:
**5/** Engagement state survives context compression. PTT tasks, hypotheses, checkpoints, and evidence resume from disk when the conversation is compacted. Long engagements keep the plot.

Post 6:
**6/** Honest about evals: the repo ships a benchmark harness and documents its methodology, but publishes no live score. A single agentic run is a noisy sample (docs/BENCHMARKS.md).

Post 7:
**7/** MIT licensed, installs as a Hermes profile. Recon to report, 7 skills, 35 playbooks. Authorized targets only by design. https://github.com/Strategic-Automation/violin

### Standalone post version (one post, <= 270 chars)

**Highest-leverage standalone:**
> LLM pentests are only as good as the evidence trail. Violin, an MIT open-source profile for Hermes Agent, requires every target command to pass a scope/phase/task guard and binds findings to signed execution receipts. No live score to oversell, just auditable methodology. https://github.com/Strategic-Automation/violin

Alternate standalone (short, hooky first line):
> The problem with "AI pentesting" is confidence without receipts. Violin fixes the enforcement boundary, not the prompt. MIT, open source, authorized targets only. https://github.com/Strategic-Automation/violin

---

## 6. LinkedIn

Target: professional security/consulting audience. Tone is client-trust and auditability, not hype. <= 1300 chars.

**Post:**
> For anyone delivering or buying penetration tests, the weakest link is rarely the test itself. It is the chain of evidence between "a finding exists" and "we can defend this to a client or an auditor."
>
> Most LLM-assisted testing adds speed and adds a new problem: a confident narrative with no verifiable trail. When an agent says it found something, how do you prove it in the report?
>
> I open-sourced an answer to that specific question. Violin is an MIT-licensed agentic pentest profile for Hermes Agent that treats evidence as a requirement, not an aspiration:
>
> - Every command that touches a target passes a required execution guard that validates scope, phase, task, skill, hypothesis, and history before it runs, and fails closed. Out-of-scope activity is not just discouraged, it is blocked at the boundary.
> - Findings must bind to signed execution receipts. The report maps each validated finding to the request, the response, and the receipt that authenticates both. That is a defensible chain.
> - Engagement state persists across sessions, so long assessments do not lose tasks, hypotheses, or evidence.
> - Evaluation is honest by construction. The repo documents its benchmark methodology and treats a single run as a noisy sample. It does not publish a score it cannot stand behind.
>
> It routes an assessment across seven skills and 35 playbooks, from recon through reporting, and is built for authorized engagements only, with scope enforcement in the tool layer rather than a prompt.
>
> If you have been wary of agentic security tools because they cannot show their work, this is designed to be the exception. It is free, MIT-licensed, and installs as a Hermes profile.
>
> https://github.com/Strategic-Automation/violin

**First comment (link + neutral invite):**
> Full disclosure: I maintain Violin. I would genuinely welcome a skeptical read of the guard and the evidence model, and I will integrate honest criticism into the roadmap. Install and docs in the repo.

---

## 7. dev.to / Hashnode / Medium cross-posting plan

**Where each article goes, canonical handling:**

- Write the canonical article on **dev.to** (easiest canonical + platform traffic) OR **your own blog** if you have one. Set the canonical URL.
- Hashnode and Medium both support a canonical URL origin tag: set it so you do not split ranking signal or get penalized for duplicates.
- Post the same body to dev.to and Hashnode/Medium, always with the canonical pointing at one origin. Do not rewrite substantially per platform; SEO sites penalize near-duplicate content without a canonical.
- **Where:** the r/netsec engineering post (section 4) doubles as your first dev.to article; expand it to full length there.
- **Tags per platform:**
  - dev.to: `security`, `pentesting`, `llm`, `opensource`, `ai`
  - Hashnode: `security`, `pentesting`, `ai`, `opensource`, `linux`
  - Medium: `cybersecurity`, `penetration-testing`, `artificial-intelligence`, `open-source`, `llm`
  - Limit dev.to to 4 tags max (it caps at 4); pick `security`, `pentesting`, `llm`, `opensource`.

**6-week, 4-post content calendar:**

**Post 1 (publish Day 1-3) | Channel: dev.to (canonical) + r/netsec.** Title: *"Scope enforcement in an agentic penetration-testing loop."* Outline: why prompt-level guardrails fail at the tool boundary, the required-guard architecture and AST-based command parsing, and how findings bind to signed receipts. Targets: HN recirculation and the r/netsec engineering audience.

**Post 2 (publish ~Day 7) | Channel: dev.to + XP/Reddit (r/AI_Agents, r/LLMDevs).** Title: *"Evidence vs. prose: making an LLM agent show its work."* Outline: the evaluation problem for agentic security tools, why evidence rather than prose has to be the unit of credit, and why a single agentic run is a noisy sample rather than a score. Targets: LLM developers and people tired of unverifiable agent claims.

**Post 3 (publish ~Week 3) | Channel: Hashnode + LinkedIn.** Title: *"What a required execution guard looks like in practice."* Outline: a walkthrough of the guard checks (scope, phase, task, skill, hypothesis, history) with a concrete deny example, and the operator tradeoff between enforcement and friction. Targets: consultants deciding whether this is usable in engagements.

**Post 4 (publish ~Week 5) | Channel: Medium + X.** Title: *"35 playbooks, 7 skills: structuring agentic pentest methodology."* Outline: how recon-to-report methodology is routed across specialist playbooks, and how playbook standards (evidence, stop conditions, blocked actions) keep both the agent and the project honest. Targets: practitioners and new contributors.

---

## 8. Communities + direct outreach

### Community table

| Community | Type | What to post |
|---|---|---|
| Hermes Agent community (Discord/forums per docs at hermes-agent.nousresearch.com) | Native home | Announce Violin as a profile, ask for guard feedback, share the Day-1 article. Highest-relevance, lowest-friction. |
| OWASP chapter channels (local + OWASP Slack/Discord where active) | Security | Share the evidence-driven findings model and the scope-guard design; ask if the trusted-tools methodology is sound. No link spam, contribute to discussion first. |
| DevSecOps Slack/Discord communities (e.g. DevSecOps, SANS, InfoSec community servers) | Security ops | Post the "evidence vs prose" angle and offer to answer scope-enforcement questions. |
| /r/netsec etc. | Reddit | Covered in section 4. |
| Kali Linux / Parrot forums | Tooling | Note Violin works in the Kali/Parrot environment and routes their installed tools; useful for users whose toolchain you integrate with. |
| LLM agent Discord/Slack (e.g. communities around agent frameworks, LangChain, OpenRouter-user spaces) | AI builders | Share the guard pattern and the state-persistence design; ask how they handle enforcement in agentic systems. |
| HackerNews | Forum | Section 3. |

### Pitch emails / DMs (each <= 150 words, no attachments, clear ask)

**To a security newsletter (e.g. tldrsec-style):**
> Subject: Agentic pentest profile with a required execution guard (MIT, open source)
>
> Hi, I maintain Violin, an MIT-licensed agentic penetration-testing profile for Hermes Agent. Its key design choice: every target-touching command must pass a required execution guard validating scope, phase, task, skill, hypothesis, and history, and findings must bind to signed execution receipts. It routes recon-to-report methodology across seven skills and 35 playbooks and persists engagement state across context compression.
>
> I believe your readers, who follow security tooling, would find the guard and the honest-evidence evaluation worth a look. The repo deliberately publishes no live benchmark score, treating a single agentic run as a noisy sample, which is the kind of rigor your audience tends to respect.
>
> Could I send you a short written brief with the repo link and a one-paragraph summary for your next issue? Repo: https://github.com/Strategic-Automation/violin. Happy to answer questions.

**To an AI / LLM newsletter:**
> Subject: Tool-layer enforcement, not prompt guardrails: an open-source agentic security control
>
> Hi, I am the maintainer of Violin, an MIT open-source agentic pentest profile that demonstrates an agent control I think your readers will find interesting: a required execution guard in the tool layer, not another prompt.
>
> A target command cannot run unless the guard validates scope, phase, active task, skill, hypothesis, and history, and findings bind to signed receipts, so outputs are verifiable. It also handles context-compression persistence deliberately. It is honest about evals, publishing methodology and calibration but no live score.
>
> This pairs naturally with your coverage of agent reliability and evaluation. Could I offer you a one-page technical brief and demo setup for your next edition? Repo: https://github.com/Strategic-Automation/violin. Happy to walk through it live.

**To a podcast (security or AI agent focused):**
> Subject: Guest/pod candidate: agentic pentesting without the hype, via a required execution guard
>
> Hi, I maintain Violin, an MIT open-source agentic pentest profile for Hermes Agent, and I proposed a topic I think fits your show: what actually holds back LLM agents from doing real security work, and whether an enforcement boundary in the tool layer is the answer.
>
> On the show I could talk about the required execution guard, evidence-backed findings with signed receipts, why the project refuses to publish a single benchmark score, and what a credible agentic security evaluation would look like. I am happy to be pushed on the "AI pentesting is a gimmick" angle, it is the most productive version of the conversation.
>
> Would a 30- to 45-minute segment fit a future slot? Repo for background: https://github.com/Strategic-Automation/violin.

**To a security YouTuber:**
> Subject: Source material: an open-source agentic pentest profile with an honest-evidence eval
>
> Hi, I maintain Violin, an MIT open-source agentic pentest profile for Hermes Agent. It is a good structural subject if you cover security tooling or LLM agents: a required execution guard that blocks out-of-scope commands, findings bound to signed receipts, and a benchmark that deliberately publishes no live score because single agentic runs are noise.
>
> Could make a strong "can an LLM actually do pentesting, and how would you know" video, or a tear-down of the guard if you prefer to stress-test it live. Authorized lab targets only, all local.
>
> Happy to provide repo access, a short brief, and a demo environment. Repo: https://github.com/Strategic-Automation/violin.

---

## 9. Directories + listings

### AlternativeTo

**Entry copy:**
> Violin is a supervised, authorization-scoped agentic penetration-testing profile for Hermes Agent. It routes an assessment across seven routed skills and 35 playbooks, from reconnaissance through exploit validation to reporting. Every target-touching command must pass a required execution guard that validates scope, phase, active task, skill, hypothesis, and history and fails closed; findings bind to signed execution receipts, so deliverables are auditable. Engagement state persists across context compression. MIT licensed; for authorized testing only. Winds up alongside: Nessus, OpenVAS, Metasploit (as complements rather than replacements) and CLI pentest frameworks. Categories: penetration-testing, security-audit, ai-tools, open-source.

### Product Hunt

**Tagline (must be <= 60 chars):**
`Agentic pentesting with a required execution guard and signed evidence`

(that is 72 chars, too long. Use an alternate):
`Supervised agentic pentesting with signed evidence receipts`

(61 chars, still 1 over. Final pick, counts ~57):
`Agentic pentest profile with a required scope guard`

(Chip: count: "Agentic pentest profile with a required scope guard" = 55 chars. Good.)

**Description (first comment optional):**
> Violin is an open-source (MIT) agentic penetration-testing profile for Hermes Agent. It runs an authorized assessment from reconnaissance through exploit validation to reporting, routed across seven skills and 35 playbooks.
>
> The distinguishing piece: a required execution guard between the agent and every target-touching command. Before a command runs, the guard validates the approved scope (host, URL, IP/CIDR, exclusions) against the resolved request, the current phase against an active task, the routed skill, the hypothesis, and history, and it fails closed with the exact next typed step. Findings must bind to signed execution receipts, so the report maps to request, response, and receipt. Engagement state persists across context compression, so long engagements do not lose their place.
>
> One beauty of a deliberate product: it is honest about evaluation. The repo documents its benchmark methodology and treats a single agentic run as a noisy sample; it publishes methodology, not a score it cannot stand behind.
>
> Install: `hermes profile install https://github.com/Strategic-Automation/violin`. Built for authorized targets only.

**First comment on PH (optional):**
> I am the maintainer. Happy to answer skeptical questions about the guard, the evidence model, or the evaluation. If you want to try it, the README has a two-command install. It is MIT and built for authorized testing only.

### Curated indexes / awesomes

Status on "awesome"/curated listings: the repo has already been through a large awesome-list PR campaign (42 PRs, 10 merged, 20 still open). Awesome-list submissions are effectively a completed, low-yield channel. **Do not spend new effort here.** If a specific, high-quality curated index genuinely fits and is verifiably unlisted, one PR each is fine, but only as background work, never as the strategy.

Where Violin genuinely fits if not already there: `awesome-pentest`, `awesome-ai-security`, `awesome-llm-agents`, `awesome-cybersecurity-tools`, and any Hermes/agent ecosystem list. Check each for an existing entry before submitting a second time.

---

## 10. Measurement

**What to track each week:**

| Metric | Where | Meaning |
|---|---|---|
| Stars/week | `gh api repos/Strategic-Automation/violin` (field `stargazers_count`); record weekly delta | Core interest signal |
| Referral traffic per channel | GitHub repo traffic: `gh api repos/Strategic-Automation/violin/traffic/popular/referrers` and `clones` | Which channel actually drives visitors and installs |
| Install count | Your own analytics if the readme/install is behind a redirect you control; otherwise approximate via clone traffic | The real action metric |
| Issues/PRs from launch | `gh api search/issues -q "repo:Strategic-Automation/violin"` | Engagement depth, not just eyeballs |
| Docs/badge referrer | `gh api repos/Strategic-Automation/violin/traffic/popular/paths` | Which surfaces convert |

**Decision rule:** give each channel three real attempts with distinct copy (not three reposts of the same line). If a channel produced no referral visitors and no stars after three attempts, stop investing executive time in it and let it be passive SEO. Channels that produced any sign of real interest (comments, a conversion, a slow climb) get a second-week refinement. HN and the native Hermes community are the two channels most likely to earn follow-through; if neither lands, re-open the positioning before spending more on directories.

---

## 11. Reply / engagement templates

**To a PR/merge-request reviewer (or a thoughtful HN/Reddit commentator):**
> Thanks, this is exactly the review the guard needed. On your point about [X]: the current behavior is [Y] because [reason from the docs]. I have opened issue #N to track tightening it, and I would welcome another pass once it is in. If you use Violin on an authorized lab target, the friction you flagged will be the most valuable signal I get.

**To a skeptic (short, non-defensive):**
> Fair pushback, and I agree the default state of "AI pentesting" is overclaimed. What I am asking people to judge is the enforcement boundary, not the model: a required guard plus signed receipts, so a finding is verifiable. The repo documents methodology and deliberately publishes no live score. If that specific property is where you take issue, I want the detail.

**To a genuine bug report from launch:**
> Thank you, this is reproducible and the fix is worth doing properly. To confirm the environment: Violin [version], Hermes [version], OS [platform]. I have logged it as #N with your steps and guard output; a fix lands with a regression test in the next release. If this blocks your authorized lab work, say so and I will prioritize it.

**To "can I use this without authorization?" (must be an unambiguous refusal + lab pointer):**
> No. Violin is designed for systems you own or have written authorization to test, and the guard enforces scope and approvals by policy. Do not use it against any target without that authorization. For practicing safely, use local by-design targets: a deliberately vulnerable app (the repo ships a practice target definition you can run locally in Docker), a sandboxed lab, or localhost. That is the authorized, legal way to evaluate it.

---

## 12. Compliance guardrails for this kit (and for every post)

Re-read this before every post:

1. **Never post about attacking a system you do not own or lack written authorization to test.** Every demo, screenshot, and claim in this kit assumes a local lab, localhost, or a deliberately vulnerable application you control (run the practice target the repo ships, locally in Docker).
2. **Never publish client data or engagement evidence.** No real target IPs, no real findings from real engagements, no scope.yaml contents from client work, no screenshots of live target output. Show the tool mechanics with localhost or the Duck Store only.
3. **Keep example targets to the local lab.** The README itself says the benchmark runs against `http://localhost:<published-port>` and the Duck Store definition ships in-repo. Mirror that in every public example.
4. **Do not oversell.** The repo documents benchmark methodology and calibration but no live score. Claiming a number that is not in the repo is fabrication, and this kit hard-rules against it.
5. **Never imply unauthorized use is acceptable or normal.** Every post states authorized-targets-only, and the emphatic refusal canned reply (section 11) is the correct response to any "can I point this at X without permission" question.

---

*End of kit. Before each new platform push, re-verify star count and version from the repo (section 10 references the exact commands) so every post ships accurate numbers.*