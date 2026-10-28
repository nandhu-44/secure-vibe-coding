# Errors, logging & monitoring

## Errors returned to clients
- Return **generic messages and a correlation ID**. Never return stack traces, SQL errors, file paths, internal hostnames, or library versions. [CWE-209]
- Use the **same response for "user not found" and "wrong password"**, and for "email exists" on signup/reset, to prevent account enumeration. Keep timing similar too, e.g. hash a dummy password when the user is missing. [CWE-204]
- Fail **closed**: if an authz check, signature verification, or payment lookup throws, deny. [CWE-636]
- Turn off debug in production: Flask `debug=False`, Django `DEBUG=False`, Express `NODE_ENV=production`, Spring `server.error.include-stacktrace=never`, and no `app.UseDeveloperExceptionPage()` outside Development.

```python
# FastAPI example
@app.exception_handler(Exception)
async def unhandled(request, exc):
    error_id = uuid.uuid4().hex
    logger.exception("unhandled error id=%s path=%s", error_id, request.url.path)
    return JSONResponse({"error": "internal_error", "id": error_id}, status_code=500)
```

## What to log (security events)
Login success/failure, MFA changes, password reset requests, permission denials, admin actions, payment and state changes, rate-limit triggers, and input validation failures on sensitive endpoints. Include: timestamp (UTC), actor/user ID, source IP, action, target object ID, outcome.

## What never to log [CWE-532]
Passwords (including failed attempts), session IDs, access/refresh tokens, API keys, `Authorization` headers, cookies, full card numbers/CVV, government IDs, health data, and private keys. Redact by field name (`password`, `token`, `secret`, `authorization`, `cookie`, `api_key`) in structured loggers.

## Log injection [CWE-117]
Use structured (JSON) logging, or strip CR/LF from user-supplied values before logging.

## Monitoring hooks
Alert on spikes of 401/403/429, many failed logins per account or IP, and unusual admin activity. Logs must be append-only and stored off-host. Do not depend on them for authz decisions.
