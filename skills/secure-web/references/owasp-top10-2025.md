# OWASP Top 10:2025 → where this pack covers it

Category IDs and names are from the [OWASP Top 10:2025](https://owasp.org/Top10/) (OWASP Foundation, CC BY-SA 4.0). The other columns are SecureVibe's own mapping.

| # | Category | Typical AI-code failure | Pack coverage |
|---|---|---|---|
| A01 | Broken Access Control (incl. SSRF) | Routes without auth, IDOR, client-sent `role`, open CORS, user-URL fetch | secure-web §1, §8; scanner SV-INJ-006/007, SV-WEB-005/006 |
| A02 | Security Misconfiguration | `DEBUG=True`, default creds, verbose errors, missing headers, public buckets | secure-web §4, §9; secure-supply-chain-infra; SV-WEB-001/002, SV-IAC-* |
| A03 | Software Supply Chain Failures | Hallucinated/typosquatted packages, unpinned deps/actions, `curl \| sh` | secure-supply-chain-infra; SV-CI-*, SV-INF-001/004 |
| A04 | Cryptographic Failures | MD5 passwords, `Math.random` tokens, ECB, `verify=False`, `http://`, hardcoded keys | core crypto.md, secrets-config.md; SV-CRY-*, SV-NET-*, SV-SEC-* |
| A05 | Injection | f-string SQL, `shell=True`, `eval`, `innerHTML`, SSTI, NoSQL operators | core card; secure-web §3, §4; SV-INJ-* |
| A06 | Insecure Design | No rate limits, no state machine, trusting client totals, race conditions | business-logic.md, rate-limiting.md, threat-model-lite.md |
| A07 | Authentication Failures | Hand-rolled sessions, no lockout, JWT `none`, reset token reuse | secure-web §2; SV-CRY-005, SV-WEB-003 |
| A08 | Software or Data Integrity Failures | `pickle`/`yaml.load`, unsigned webhooks, unverified updates | SV-INJ-005; business-logic.md (webhooks) |
| A09 | Security Logging & Alerting Failures | No audit logs, or logging passwords/tokens | core logging-errors.md |
| A10 | Mishandling of Exceptional Conditions | Fail-open on errors, stack traces to users, unchecked return values | core logging-errors.md; secure-lowlevel |

The ASVS 5.0 chapters map the same way: V1 Encoding/Sanitization → §3–4, V6 Authentication → §2, V7 Session Mgmt → §2, V8 Authorization → §1, V11 Cryptography → core crypto.md, V12 Secure Communication → core card, V14 Data Protection → secrets/logging, V5 File Handling → §7.
