# Issue standards

Violin uses GitHub-native metadata wherever possible. Issue bodies describe the work;
they do not duplicate project state.

## Titles

Use a short, imperative, descriptive title.

Good:
- `Resolve one skill consistently across PTT tools`
- `Add confidence gates for zero-finding scanner results`

Do not add priority/order prefixes such as `P0-01:`, type prefixes such as
`[Bug]`, or status text such as `Blocked:`. Priority, type, status,
parent/child relationships, dependencies, milestones and project ordering belong in
GitHub metadata.

## Before creating an issue

1. Search open and closed issues for duplicates and overlapping scope.
2. Check open pull requests for work already implementing the change.
3. Keep one independently reviewable concern per issue.
4. For larger outcomes, use a parent issue and GitHub sub-issues.
5. Use GitHub issue dependencies for real blocking relationships.

Do not create a second issue merely to express a different implementation approach.

## Canonical agent-authored body

Use these headings in this order. Omit only sections that genuinely do not apply.

```markdown
## Summary

What is wrong or what should change, in concrete terms.

## Why this matters

User, safety, correctness, maintainability, performance, context/cost, or reviewer impact.

## Reproduction

For defects: minimal deterministic steps, expected behaviour, and actual behaviour.

## Proposed implementation

The intended boundary and important constraints.

## Implementation area

Likely files/components and tests affected.

## Acceptance criteria

- [ ] Observable, testable outcome.
- [ ] Regression/safety requirement where relevant.
- [ ] Documentation or compatibility requirement where relevant.

## Dependencies / related work

Native GitHub dependencies/sub-issues are the source of truth. Add links here only when a
short explanation helps a reader understand the relationship.

## References

Standards, upstream documentation, benchmarks, or research used to justify the work.
```

For small tasks, `Summary`, `Proposed implementation`, `Implementation area`, and
`Acceptance criteria` are sufficient. Bugs should include `Reproduction` whenever the
failure is reproducible.

## Metadata

Prefer GitHub-native metadata:

- **Type:** Bug, Feature, or Task.
- **Priority:** project/organization Priority field, not the title or body.
- **Status/order:** GitHub Project fields/views, not issue prose.
- **Dependencies:** GitHub blocked-by/blocking relationships.
- **Hierarchy:** GitHub parent/sub-issue relationships.
- **Milestone:** use for a real release or delivery target, not priority.
- **Labels:** stable cross-cutting areas such as `guard`, `playbooks`,
  `benchmark`, `docs`, `ci`, `tests`, and `packaging`.

If the API/tool cannot set a native field, do not invent a duplicate text field. Set the
parts the API supports and leave the native field for triage. Legacy `bug` or
`enhancement` labels may be used only as a fallback when issue type cannot be set.

## Agent rules

When an agent creates or edits an issue:

- search for duplicates first;
- preserve existing evidence, reproduction detail, decisions and acceptance criteria;
- do not overwrite a well-formed issue merely to restyle prose;
- do not create branches until the issue scope is clear;
- keep one concern per issue;
- use checkable acceptance criteria;
- link a PR with `Fixes #<issue>` when it fully closes the issue;
- never put credentials, target data, customer evidence or other sensitive engagement data
  in a public issue.

Security vulnerabilities in Violin itself must follow `SECURITY.md`, not public issues.
