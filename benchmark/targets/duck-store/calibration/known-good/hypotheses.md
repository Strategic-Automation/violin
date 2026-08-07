# Hypothesis Board — Calibration Known-Good Engagement

## Observations

Initial reconnaissance and vulnerability assessment of duck-store.escape.tech API.

## Active Hypotheses

### H-001: Default Admin Credentials
**Status:** Validated
**Linked challenges:** weak-admin-creds

The login endpoint accepts admin/password as valid credentials.

### H-002: JWT Algorithm None Attack
**Status:** Validated
**Linked challenges:** jwt-alg-none

The API accepts JWTs with alg set to none, bypassing signature verification.

### H-003: TOTP 2FA Bypass
**Status:** Validated
**Linked challenges:** totp-bypass

The TOTP verification endpoint can be bypassed by submitting an empty or null TOTPSecret.

### H-004: IDOR on User Profiles
**Status:** Validated
**Linked challenges:** idor-user-profiles

User profile endpoints at /api/v1/users/{uuid} do not enforce ownership checks.

### H-005: Mass Assignment on User Role
**Status:** Validated
**Linked challenges:** mass-assign-role

The PUT /api/v1/users/me/profile endpoint accepts a role field in the UserUpdate schema, allowing privilege escalation.

### H-006: 100% Discount Coupon
**Status:** Validated
**Linked challenges:** coupon-100-discount

The checkout endpoint accepts coupon codes that apply a 100% discount.

### H-007: Referral Credit Abuse
**Status:** Validated
**Linked challenges:** referral-abuse

The registration endpoint accepts self-referral via the referrer field in RegisterRequest, generating unlimited credit.

### H-008: SQL Injection in Color Filter
**Status:** Validated
**Linked challenges:** sqli-color-filter

The /api/v1/products/filter/by-color endpoint is vulnerable to SQL injection via the ProductColor parameter.

### H-009: Stored XSS in Testimonials
**Status:** Validated
**Linked challenges:** xss-testimonials

The POST /api/v1/testimonials/ endpoint does not sanitize the guest_avatar_url field, allowing stored XSS via script injection.

### H-010: SSRF via Image Import
**Status:** Validated
**Linked challenges:** ssrf-image-import

The POST /api/v1/uploads/import-from-url endpoint follows arbitrary URLs server-side (ImageImport SSRF).

### H-011: SSRF via Fetch URL
**Status:** Validated
**Linked challenges:** ssrf-fetch-url

The GET /api/v1/uploads/fetch-url endpoint acts as an open proxy (FetchUrl link-preview SSRF).

### H-012: Unauthenticated Testimonial Modification
**Status:** Validated
**Linked challenges:** unauth-testimonial-mod

PUT /api/v1/testimonials/{id} does not require authentication, allowing unauth TestimonialUpdate.

### H-013: IDOR on Order Details
**Status:** Validated
**Linked challenges:** idor-order-details

GET /api/v1/orders/{id} returns OrderDetail for any order_id without ownership verification.

### H-014: Broken Access Control on Admin Users List
**Status:** Validated
**Linked challenges:** bac-admin-users

GET /api/v1/admin/users returns the full UserList to non-admin authenticated users.

## Decoy Trail

None identified during this engagement.

## Research Log

All hypotheses tested against duck-store.escape.tech per approved scope.

## Resolved Theories

All 14 hypotheses above have been validated with HTTP evidence.
