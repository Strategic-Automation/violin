## Summary

<!-- What changed, and why? -->

## Verification

- [ ] `uv run pytest`
- [ ] `uv run ruff check .`
- [ ] `uv run ruff format --check .`
- [ ] `uv run python scripts/violin_guard.py check-release`

## Documentation and release surfaces

- [ ] User-facing behavior and examples match the current code.
- [ ] New playbooks include Evidence, Stop Conditions, and Blocked Actions.
- [ ] `distribution.yaml`, versions, and skill snapshots are updated when required.
- [ ] No target data, credentials, engagement evidence, or generated artifacts are included.
