# Post-write self-review (one pass)

This follows the "Recursive Criticism and Improvement" loop (Kim et al., 2023, [arXiv:2303.17491](https://arxiv.org/abs/2303.17491)) recommended by the [OpenSSF guide for AI code assistant instructions](https://best.openssf.org/Security-Focused-Guide-for-AI-Code-Assistant-Instructions), **limited to one pass** so it never blocks delivery. Re-read your diff and tick each line that applies. Fix what fails, then stop.

## Universal
- [ ] No secrets, keys, or passwords in code, tests, configs, Dockerfiles, or front-end env. Missing secrets fail fast.
- [ ] All external URLs are `https://`. TLS verification is not disabled anywhere.
- [ ] All queries are parameterized. No input reaches a shell, `eval`, a template engine as a template, or a deserializer.
- [ ] Every input has validation: type, length/size, range, format, allowlist where possible.
- [ ] Error responses are generic. Debug mode is off by default. No secrets in logs.
- [ ] New dependencies are real, well-known, and pinned. Lockfile updated.

## If it is a server/API
- [ ] Every new route has authentication (or is deliberately public, with a comment saying so).
- [ ] Every object access checks ownership/tenant server-side (IDOR).
- [ ] Role/price/owner/status fields are never taken from the client. Writable fields are allowlisted.
- [ ] Rate limits are on auth, OTP, reset, signup, and costly endpoints. Body size limits and pagination caps are set.
- [ ] Multi-step flows validate state transitions. Money/inventory changes are transactional and idempotent.
- [ ] Cookies are `HttpOnly`/`Secure`/`SameSite`. CSRF is handled. CORS is an explicit allowlist. Security headers are set.
- [ ] Uploads have size/type checks, random names, and storage outside the web root.

## If it is C/C++/unsafe
- [ ] Every copy and index is bounds-checked against the destination size. No banned functions.
- [ ] Integer arithmetic for sizes is overflow-checked before `malloc`/`memcpy`.
- [ ] Each allocation has exactly one owner and one free. Pointers are NULLed after free. Every error path frees.
- [ ] Format strings are literals. Secrets are wiped with `explicit_bzero`/`memset_s`.
- [ ] Return values of `read`, `malloc`, `snprintf`, etc. are checked.

## If it calls an LLM or exposes tools
- [ ] LLM output is treated as untrusted (encoded, validated, never `eval`'d or executed raw).
- [ ] Tools take identity and tenant from the session, not from model arguments. Destructive tools need confirmation.
- [ ] Token/cost/rate limits and timeouts are set.

## Then
Run the scanner (`scripts/secscan.py`) on changed files. Tell the user, in 1–3 lines, which protections you added and what they must configure.
