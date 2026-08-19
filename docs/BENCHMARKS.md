# Benchmark methodology

Violin's benchmark harness evaluates whether an engagement produces
reproducible technical proof and canonical reporting artifacts. It does not
grade narrative confidence or award credit for an unsupported claim.

## Included target

`benchmark/targets/duck-store/` defines the Escape Duck Store evaluation:

- `challenges.json`: challenge inventory used by the scorer
- `scope.yaml`: benchmark scope
- `engage.md`: engagement prompt
- `report.md`: closeout prompt
- `calibration/known-good/`: evidence expected to receive credit
- `calibration/known-bad/`: evidence expected to receive no credit

The target contains 20 challenge definitions spanning authentication,
authorization, business logic, injection, SSRF, redirect, and information
disclosure behavior.

## Metrics

| Measure | Meaning |
|---|---|
| Technical-proof recall | Challenges supported by decisive target evidence |
| Formally validated recall | Proven challenges also represented by canonical state and finding artifacts |
| Formalization rate | Proven challenges that were recorded correctly |
| Guard compliance | Whether target work followed the guarded workflow |

A calibration pass checks scorer behavior only. It does not prove that a live
agent can discover the same findings, complete the workflow, or produce a
client-ready report.

## Proof requirements

Credit requires challenge-specific evidence. For HTTP behavior, this normally
includes the request context, HTTP status, relevant headers, and decisive body
content. A status code, route name, hypothesis title, or model assertion alone
is insufficient.

Evidence must be reproducible from the saved artifact set. Secrets or values
known only to the scoring fixture must not be inferred from filenames or
challenge metadata.

Formal validation additionally requires the expected hypothesis, PTT, and
`FIND-NNN.md` links. Technical proof and formalization are reported separately
so incomplete closeout cannot receive full workflow credit.

## Commands

```bash
# Known-good fixtures must receive their expected credit.
uv run python benchmark/score.py --calibrate known-good

# Known-bad fixtures must remain at zero false credit.
uv run python benchmark/score.py --calibrate known-bad

# Run a live benchmark.
uv run python -m benchmark.run --target https://duck-store.escape.tech

# Score an existing engagement.
uv run python benchmark/score.py engagements/benchmark-run-YYYYMMDD_HHMMSS
```

## Publishing a result

Do not publish a headline score from calibration output or an incomplete run.
A publishable result needs:

1. The exact model and provider configuration.
2. The target revision and scope used by the run.
3. A completed engagement artifact directory.
4. Reproducible proof for each credited challenge.
5. Known-good and known-bad calibration results from the same scorer revision.
6. Both technical-proof and formally validated metrics.
7. Run duration, termination reason, and any manual intervention.

Cross-tool rankings are not included because different models, target
revisions, prompts, time limits, and validation rules are not controlled by
this repository.

## Harness files

| File | Responsibility |
|---|---|
| `benchmark/run.py` | Create and run the benchmark engagement |
| `benchmark/indexer.py` | Collect bounded engagement artifacts |
| `benchmark/proof.py` | Evaluate decisive proof signals |
| `benchmark/score.py` | Calculate benchmark metrics and calibration |
| `benchmark/ai_judge.py` | Produce the optional heuristic audit |

The deterministic scorer and saved evidence are authoritative. The heuristic
audit is supporting context and must not override missing proof.
