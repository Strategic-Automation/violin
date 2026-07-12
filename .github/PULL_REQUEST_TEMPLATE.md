---
name: Pull Request
description: Submit a pull request for Violin
title: "[PR]: "
body:
  - type: markdown
    attributes:
      value: |
        Thanks for contributing to Violin!
  - type: input
    id: summary
    attributes:
      label: Summary
      description: What does this PR change?
    validations:
      required: true
  - type: dropdown
    id: type
    attributes:
      label: Change type
      options:
        - New playbook
        - Playbook improvement
        - Bug fix
        - Documentation
        - CI / workflow
        - Infrastructure
    validations:
      required: true
  - type: textarea
    id: changes
    attributes:
      label: Changes
      description: List the key files changed and what was modified
    validations:
      required: true
  - type: textarea
    id: verification
    attributes:
      label: Verification
      description: Did you run `python scripts/violin_guard.py check-release`?
      placeholder: "Yes — all checks pass"
    validations:
      required: true
  - type: checkboxes
    id: checklist
    attributes:
      label: Checklist
      options:
        - label: I ran the guard release check
          required: true
        - label: I followed the playbook standards (Evidence, Stop, Blocked sections)
        - label: I updated distribution.yaml if adding new files