# AWS IAM and Storage Policy Review

This reference covers supplied AWS policy and storage configuration. It does
not authorize account discovery or cloud API calls. Record the supplied
partition, account, principal/session, resource ARN, action, conditions, and
policy version. A URL in web scope does not grant account-wide AWS authority.

## Review the effective request

For one synthetic request, trace principal and session -> requested action ->
resource -> applicable controls -> possible protected effect. Review identity
policies, resource policies, role trust, conditions, session policies,
permissions boundaries, organization SCP/RCP, endpoint policies, and storage
ownership/ACL settings where supplied. An `Allow` statement in isolation does
not prove effective access: explicit denies and policy-type interactions
matter, cross-account access requires relevant permissions on both sides, and
service-specific behavior can differ.

Example: a role policy allows `s3:GetObject` on `arn:aws:s3:::demo-private/*`,
but the supplied record lacks the bucket policy and organization controls.
Classify access as unresolved until those inputs or a permitted synthetic
request establish the effective principal, object, and returned canary. Do not
infer a real data exposure from a policy fragment.

## Evidence

Keep supplied files and provenance under `$ENG_DIR/evidence/recon/`. Record
missing policy layers and the exact principal/resource/action tuple. If a live
synthetic check is explicitly authorized and supported, use registered guarded
tools and authenticated receipts; redact account identifiers and credentials
from user-facing reports.

## Stop Conditions

- Stop when account, principal, resource, action, or requested cloud API is not
  explicitly authorized.
- Treat absent trust, boundary, organization, or resource context as a
  limitation, not an inferred allow.
- Stop before any write, role assumption, or real object read.

## Blocked Actions

No credential discovery, metadata credential harvesting, role assumption,
cloud-client installation, infrastructure mutation, or real customer-data
access.

## References

- [AWS IAM policy evaluation logic](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic.html)
- [AWS IAM policy types](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies.html)
