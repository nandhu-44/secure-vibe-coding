# OWASP API Security Top 10 (2023): checklist for API code

Risk IDs and names are from the [OWASP API Security Top 10 2023](https://owasp.org/API-Security/editions/2023/en/0x11-t10/) (CC BY-SA 4.0). The rules column is Secure Vibe Coding's own guidance.

| ID | Risk | Rule to apply when generating an endpoint |
|---|---|---|
| API1 | Broken Object Level Authorization | Every `/{id}` query is scoped by owner/tenant; 404 on mismatch |
| API2 | Broken Authentication | Use a vetted auth library; rate-limit credential endpoints; short-lived tokens; verify JWT alg/exp/aud |
| API3 | Broken Object Property Level Authorization | Input DTO allowlists writable fields; output DTO omits sensitive/internal fields |
| API4 | Unrestricted Resource Consumption | Rate limits, body size limits, pagination max, timeouts, per-user quotas on costly operations |
| API5 | Broken Function Level Authorization | Admin/management routes check role server-side; separate router with an admin guard |
| API6 | Unrestricted Access to Sensitive Business Flows | Protect purchase/signup/referral/booking flows from automation (limits, CAPTCHA, device checks) |
| API7 | Server Side Request Forgery | URL allowlist, block private IPs, connect to resolved IP, no blind redirects |
| API8 | Security Misconfiguration | CORS allowlist, security headers, no debug, TLS only, disable unused HTTP methods |
| API9 | Improper Inventory Management | Version APIs; remove old/test endpoints; no undocumented debug routes in prod |
| API10 | Unsafe Consumption of APIs | Validate third-party responses with schemas; timeouts; TLS verify; don't follow redirects blindly |

GraphQL extras: depth and complexity limits, alias/batch caps, authz in every resolver (not just the top query), persisted queries for public clients.
