# Hypothesis Board — Calibration Known-Good Engagement

## Observations

Initial reconnaissance and vulnerability assessment of duck-store.escape.tech API.

## Active Hypotheses

### H-001: Default Admin Credentials
**Status:** Validated
**Linked challenges:** weak-admin-creds
**Linked findings:** FIND-001

The login endpoint accepts admin/password as valid credentials.

### H-002: JWT Algorithm None Attack
**Status:** Validated
**Linked challenges:** jwt-alg-none
**Linked findings:** FIND-002

The API accepts JWTs with alg set to none, bypassing signature verification.

### H-003: TOTP 2FA Bypass
**Status:** Validated
**Linked challenges:** totp-bypass
**Linked findings:** FIND-003

The TOTP verification endpoint can be bypassed by submitting an empty or null TOTPSecret.

### H-004: IDOR on User Profiles
**Status:** Validated
**Linked challenges:** idor-user-profiles
**Linked findings:** FIND-004

User profile endpoints at /api/v1/users/{uuid} do not enforce ownership checks.

### H-005: Mass Assignment on User Role
**Status:** Validated
**Linked challenges:** mass-assign-role
**Linked findings:** FIND-005

The PUT /api/v1/users/me/profile endpoint accepts a role field in the UserUpdate schema, allowing privilege escalation.

### H-006: 100% Discount Coupon
**Status:** Validated
**Linked challenges:** coupon-100-discount
**Linked findings:** FIND-006

The checkout endpoint accepts coupon codes that apply a 100% discount.

### H-007: Referral Credit Abuse
**Status:** Validated
**Linked challenges:** referral-abuse
**Linked findings:** FIND-007

The registration endpoint accepts self-referral via the referrer field in RegisterRequest, generating unlimited credit.

### H-008: SQL Injection in Color Filter
**Status:** Validated
**Linked challenges:** sqli-color-filter
**Linked findings:** FIND-008

The /api/v1/products/filter/by-color endpoint is vulnerable to SQL injection via the ProductColor parameter.

### H-009: Stored XSS in Testimonials
**Status:** Validated
**Linked challenges:** xss-testimonials
**Linked findings:** FIND-009

The POST /api/v1/testimonials/ endpoint does not sanitize the guest_avatar_url field, allowing stored XSS via script injection.

### H-010: SSRF via Image Import
**Status:** Validated
**Linked challenges:** ssrf-image-import
**Linked findings:** FIND-010

The POST /api/v1/uploads/import-from-url endpoint follows arbitrary URLs server-side (ImageImport SSRF).

### H-011: SSRF via Fetch URL
**Status:** Validated
**Linked challenges:** ssrf-fetch-url
**Linked findings:** FIND-011

The GET /api/v1/uploads/fetch-url endpoint acts as an open proxy (FetchUrl link-preview SSRF).

### H-012: Unauthenticated Testimonial Modification
**Status:** Validated
**Linked challenges:** unauth-testimonial-mod
**Linked findings:** FIND-012

PUT /api/v1/testimonials/{id} does not require authentication, allowing unauth TestimonialUpdate.

### H-013: IDOR on Order Details
**Status:** Validated
**Linked challenges:** idor-order-details
**Linked findings:** FIND-013

GET /api/v1/orders/{id} returns OrderDetail for any order_id without ownership verification.

### H-014: Broken Access Control on Admin Users List
**Status:** Validated
**Linked challenges:** bac-admin-users
**Linked findings:** FIND-014

GET /api/v1/admin/users returns the full UserList to non-admin authenticated users.

### H-015: Negative Cart Quantity
**Status:** Validated
**Linked challenges:** neg-quantity-cart
**Linked findings:** FIND-015

PUT /api/v1/cart/items/{id} accepts a negative quantity and creates an invalid CartItem total.

### H-016: Shipping Charge Bypass
**Status:** Validated
**Linked challenges:** shipping-bypass
**Linked findings:** FIND-016

POST /api/v1/orders/checkout accepts manipulated ShippingInfo and bypasses the shipping cost.

### H-017: Coupon Information Disclosure
**Status:** Validated
**Linked challenges:** coupon-info-disclosure
**Linked findings:** FIND-017

GET /api/v1/orders/coupons discloses the complete CouponList without appropriate authorization.

### H-018: Login Has No Rate Limiting
**Status:** Validated
**Linked challenges:** no-rate-limiting
**Linked findings:** FIND-018

POST /api/v1/auth/login permits repeated brute-force attempts without throttling or HTTP 429 responses.

### H-019: Open Redirect
**Status:** Validated
**Linked challenges:** open-redirect
**Linked findings:** FIND-019

The redirect parameter accepts an external URL and returns a Location header to that origin.

### H-020: User Enumeration
**Status:** Validated
**Linked challenges:** user-enumeration
**Linked findings:** FIND-020

GET /api/v1/users/ exposes usernames and permits unauthenticated user enumeration.

## Decoy Trail

None identified during this engagement.

## Research Log

All hypotheses tested against duck-store.escape.tech per approved scope.

## Resolved Theories

All 20 hypotheses above have been validated with correlated HTTP request/response evidence.
