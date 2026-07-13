# Changelog

## Unreleased

- Replaced regex-based target parsing with Python standard-library shell, URL, IP/CIDR, and MIME parsers; this keeps scope enforcement dependency-free while reducing parser ambiguity.
- Moved target parsing and target-scope enforcement into `core/targets.py`, leaving the command guard focused on policy orchestration.
- Allowed `violin_record_ptt` to start one untouched phase-bound task, removing the initial active-task deadlock while retaining fail-closed batch reviews.
- Made hypothesis parsing field-order independent and fixed template rewrites so recorded hypotheses are never written inside the template comment.
- Clarified typed nmap all-port input: use `ports: "1-65535"`, not the `-p-` flag form.
- Bootstrap engagement-local `exploits/` and phase evidence directories, and direct local scripts and output away from `/tmp` while preserving explicitly labelled remote-target `/tmp` payloads.
- Fixed target extraction so local dotted output/script names are not treated as hosts, and Bash `/dev/tcp` or `/dev/udp` endpoints retain their full host and port boundary.
- Canonicalized hypothesis IDs supplied as `H-001`, removed malformed duplicate headings on rewrite, and compare scoped hypothesis targets correctly when they include a URL or port.
- Kept review binding fail-closed while removing the need to manually copy an opaque pending batch ID into every PTT note.

## 1.3.1

- Enforced scope authorisation, exclusions, phase-aligned PTT tasks, and relevant hypotheses at the execution boundary.
- Made synchronization credits apply to all target-touching commands and bound reviewed batches to their captured PTT task.
- Serialized guard state transitions, fixed isolated plugin imports, and made release and PowerShell smoke checks fail reliably.

## 1.3.0

- Consolidated Violin Guard into a Hermes-native plugin.
- Made command history executor-owned and PTT review explicit.
