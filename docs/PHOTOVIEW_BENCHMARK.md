# Photoview comparison benchmark

This benchmark is independent of Duck Store. It reproduces the documented input
conditions of Shannon's Photoview comparison: Photoview 2.4.0, MariaDB, standalone
password authentication, two seeded accounts, read-only target source, and only
the admin credentials supplied to the assessment agent.

## Implementation and verification requirements

- Pin Photoview source to `f79d379e38241c687c55e9f899e30661fd9f115a`
  (upstream tag `v2.4.0`); record both target and database image identities.
- Deploy a disposable local fixture with synthetic media and independent admin
  and ordinary-user data. Publish only the app port on loopback; keep the database
  and agent on a dedicated Docker network. Reset storage between independent runs.
- Mount only the pinned application source read-only into the agent. Do not mount
  evaluator cases, patched source, upstream reports, review decisions or host secrets.
- Initialize a normal Violin engagement without Duck Store credentials, obligations,
  OpenAPI assumptions, target-specific proof rules or its 15/20 release gate.
- Execute through registered Guard tools with all scope, approval and signed-receipt
  requirements intact. Preserve runner completion, source/runtime identity, model,
  provider, elapsed time, usage/cost provenance and every failed run.
- Review every reported finding against saved evidence. Record reviewer identity,
  true/false-positive or unresolved verdict, rationale, independently assigned
  severity and any match to a published patched vulnerability. A signature proves
  authenticity, not the vulnerability. Unreviewed findings cannot receive credit.
- Report findings, true/false positives, precision, unresolved reviews, exact
  severity agreement, partial patched-case recall, cost and wall time separately.
  The seven published patched cases form a partial reference set, not all bugs.
- Aggregate compatible independent runs without mixing target versions, models,
  source revisions, runtime images or review protocols. Include failures and spread.
- Export a human-readable summary and SARIF. Preserve the distinction between
  agent-reported severity and reviewer severity; do not invent CVSS vectors.
- Add deterministic regression coverage and run the repository's required checks.
  Complete actual isolated deployment, seeding, source visibility and guarded Hermes
  execution before claiming the implementation works. Calibration/dry runs are not
  live evidence. Apply the repository's baseline/candidate comparison requirements.

The publication does not fully specify the original media dataset, database image,
target image digest, all deployment settings or reviewer rubric. Record these
differences explicitly; local reproduction must not claim exact experimental parity
or comparable commercial pricing. Model token cost and commercial scan price are
different accounting measures. The benchmark adds no automatic claim that a tool is
better than Shannon, Aikido or XBOW.

Source: [Shannon comparison](https://github.com/KeygraphHQ/shannon/blob/main/docs/shannon-xbow-aikido-benchmark.md).

## Run locally

Run from the repository root with Docker available. Set the provider credential
in your process environment (for OpenRouter, `OPENROUTER_API_KEY`); never put it
in arguments, checked-in files or review artifacts. There is no benchmark spend
cap. Hermes accounting exports tokens, provider cost when available, and estimates
separately to `run/usage.json`. Missing actual costs stay unknown.

```text
docker build -t violin:photoview .
uv run python -m benchmark.photoview.fixture setup --directory .benchmark-live/pv-01 --port 4800
uv run python -m benchmark.photoview.fixture run --directory .benchmark-live/pv-01 --output .benchmark-live/pv-output-01 --runtime-image violin:photoview --provider openrouter --model "<model-id>"
uv run python -m benchmark.photoview.fixture down --directory .benchmark-live/pv-01
```

Setup verifies the source commit and target image revision, initializes both
accounts, and requires indexed media for both principals. Each live attempt
consumes its fixture, including failed attempts. Create a new directory and
fixture for each independent run. `--dry-run` initializes an engagement without
contacting a model and does not consume the fixture.

Keep review files and evaluation outputs outside the agent engagement. Create
an unresolved review template, then independently inspect every finding and its
saved evidence before changing verdicts. Reviewer severity and any patched-case
mapping must reflect that inspection. An automated evaluator cannot supply the
required human review.

```text
uv run python -m benchmark.photoview.evaluate --eng-dir .benchmark-live/pv-output-01/run --review-file .benchmark-live/pv-review-01.json --create-review "<reviewer>"
uv run python -m benchmark.photoview.evaluate --eng-dir .benchmark-live/pv-output-01/run --review-file .benchmark-live/pv-review-01.json --output-dir .benchmark-live/pv-results-01
uv run python -m benchmark.photoview.aggregate --glob ".benchmark-live/pv-results-*/results.json" --output .benchmark-live/pv-summary.json
```

The evaluator exits unsuccessfully while the runner or reviews are incomplete.
Review templates bind decisions to exact manifest and findings hashes. The
aggregate rejects mixed models, images, source revisions and reused fixtures;
use a separate explicit glob for each model and revision. Preserve failed runs
in the same group. Do not publish private evidence, credentials or raw logs.
