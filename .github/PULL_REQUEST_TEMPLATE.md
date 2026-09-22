Fixes #

## Summary

<!-- What changed, and why? 1-3 sentences: who benefits and what problem this solves. Keep the `Fixes #` line above only when this PR closes an issue; otherwise delete it.

Release PRs (`dev` → `master`) must additionally list every issue the shipped PRs claim, for example `Closes #83, #84`: only a merge into the default branch triggers GitHub's own closing, so the release PR is where those keywords take effect. The `release-issues` check fails the release when one is missing. See CONTRIBUTING.md. -->

## Verification

<!-- Required. Tick what you ran, or list the checks that cover this change. -->

- [ ] `uv run pytest`
- [ ] `uv run ruff check .`
- [ ] `uv run ruff format --check .`
- [ ] `uv run python scripts/violin_guard.py check-release`
- [ ] Manual verification: <!-- how did you confirm the change works? -->

## Documentation and release surfaces

<!-- Delete this section only for PRs that touch no user-facing surface. -->

- [ ] User-facing behavior and examples match the current code.
- [ ] New playbooks include Evidence, Stop Conditions, and Blocked Actions.
- [ ] `distribution.yaml`, versions, and skill snapshots are updated when required.
- [ ] No target data, credentials, engagement evidence, or generated artifacts are included.
