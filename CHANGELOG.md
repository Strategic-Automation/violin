# Changelog

## 1.3.1

- Enforced scope authorisation, exclusions, phase-aligned PTT tasks, and relevant hypotheses at the execution boundary.
- Made synchronization credits apply to all target-touching commands and bound reviewed batches to their captured PTT task.
- Serialized guard state transitions, fixed isolated plugin imports, and made release and PowerShell smoke checks fail reliably.

## 1.3.0

- Consolidated Violin Guard into a Hermes-native plugin.
- Made command history executor-owned and PTT review explicit.
