# File Processing and Derived-Artifact Authorization

Use this playbook for an in-scope upload or file-processing flow when a
disposable synthetic principal and inert fixture are available. Follow the
object through upload, parse/convert/thumbnail/export, storage, retrieval and
deletion. An accepted extension, MIME type, or upload response is not proof of
unsafe processing or cross-user access.

## Lifecycle and authorization checks

Create one harmless marker file owned by test principal A. If authorized, use a
second synthetic principal B as the negative control. Record the identifier and
owner at each stage; distinguish upload accepted, processing completed, and
retrieval authorized.

| Stage | Check | Control |
|---|---|---|
| Upload | Owner, normalized name, declared and detected type | A's own inert file |
| Processing | Parser/converter job identity and completion state | Same content with a benign unsupported feature |
| Derived objects | Thumbnail/export ownership and identifier binding | B requests A's generated artifact |
| Retrieval | Original and derivative access checks, path/object selection | B requests only the known synthetic ID |
| Temporary links | Scope, owner, expiry and post-expiry behavior | Reuse after documented expiry |
| Deletion | Original and derivative cleanup | Confirm only the test object is removed |

Use bounded, non-executable files and small archives. For asynchronous jobs,
wait for the documented ready state before comparing access. Treat a signed
download URL as a bearer capability: do not share it, extend it, or test it
against another tenant without explicit approval. Route parser-specific issues
to input validation, traversal, XSS, or deserialization guidance rather than
duplicating their payload catalogs.

## Evidence

Save the exact authorized requests, synthetic ownership labels, processing
state, and decisive returned bytes under `$ENG_DIR/evidence/exploitation/`.
Use `evidence_outputs` for saved responses and cite files only with the receipt
that sealed them. Redact link tokens and user data.

## Stop Conditions

- Stop before uploading an active file, large archive, or fixture that can
  consume material resources.
- Stop when ownership, cleanup, or test-account reset cannot be confirmed.
- Stop on access to any non-test user's object.

## Blocked Actions

No webshells, credential files, decompression exhaustion, malware, remote
callbacks, traversal outside a disposable fixture, or unapproved cross-tenant
reads.

## References

- [OWASP File Upload Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html)
