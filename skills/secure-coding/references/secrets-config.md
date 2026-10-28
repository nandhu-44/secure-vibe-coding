# Secrets & configuration

Hardcoded credentials are the most common flaw in AI-generated code (CWE-798). Bots scan public commits within minutes of a push.

## Rules
1. Secrets come from the **environment or a secret manager**, never from source, tests, Dockerfiles, CI YAML, or front-end bundles.
2. **Fail fast** when a required secret is missing. Never fall back to a hardcoded default such as `os.getenv("KEY", "sk-test-123")`.
3. Commit a `.env.example` with placeholder values, and add `.env*` (except `.env.example`) to `.gitignore`.
4. **Client-side code has no secrets.** Anything shipped to a browser or mobile app is public: `NEXT_PUBLIC_*`, `VITE_*`, `REACT_APP_*`, `EXPO_PUBLIC_*`. Put keys behind a server route.
5. Use different credentials per environment, scoped to least privilege (read-only DB user, restricted API key scopes).
6. If a secret was ever committed, tell the user to **rotate it**. Deleting it from git history is not enough.
7. Default config must be secure: `DEBUG=false`, HTTPS URLs, auth enabled. Insecure options must be opt-in and named loudly (`ALLOW_INSECURE_DEV_HTTP=1`).
8. Generated sample tokens and passwords in docs/tests must be obviously fake (`example-not-a-real-key`). Never use real-looking high-entropy strings.

## Patterns

**Python**
```python
import os

def require_env(name: str) -> str:
    value = os.environ.get(name)
    if not value:
        raise RuntimeError(f"Missing required environment variable: {name}")
    return value

DATABASE_URL = require_env("DATABASE_URL")
STRIPE_SECRET_KEY = require_env("STRIPE_SECRET_KEY")
```
For typed settings, use `pydantic-settings` (`BaseSettings` with `SecretStr`), which also masks the value in reprs.

**Node / TypeScript**
```ts
function requireEnv(name: string): string {
  const v = process.env[name];
  if (!v) throw new Error(`Missing required environment variable: ${name}`);
  return v;
}
export const config = { dbUrl: requireEnv("DATABASE_URL"), jwtSecret: requireEnv("JWT_SECRET") };
```
Validate config at startup with `zod` or `envalid`. Use `dotenv` only in development.

**Go**
```go
func mustEnv(k string) string {
    v, ok := os.LookupEnv(k)
    if !ok || v == "" { log.Fatalf("missing required env var %s", k) }
    return v
}
```

**Docker / Compose**: pass secrets at runtime (`env_file`, Docker/K8s secrets, BuildKit `--mount=type=secret`). Never use `ENV API_KEY=...` or `ARG` for secrets, because both persist in image layers.

**GitHub Actions**: `${{ secrets.NAME }}`. Prefer OIDC federation to cloud providers (`id-token: write`) over long-lived keys.

## Secret managers
AWS Secrets Manager / SSM Parameter Store, GCP Secret Manager, Azure Key Vault, HashiCorp Vault, Doppler, 1Password Connect, Kubernetes Secrets (enable encryption at rest; prefer External Secrets Operator).

## `.gitignore` baseline
```
.env
.env.*
!.env.example
*.pem
*.key
*.p12
id_rsa*
credentials.json
service-account*.json
terraform.tfstate*
```

## Recognizable secret formats (the scanner flags these)
AWS `AKIA…`/`ASIA…`, GitHub `ghp_`/`gho_`/`ghs_`/`github_pat_`, Slack `xox[abpr]-`, Stripe `sk_live_`/`rk_live_`, OpenAI `sk-…`/`sk-proj-`, Anthropic `sk-ant-`, Google `AIza…`, private key blocks `-----BEGIN … PRIVATE KEY-----`, JWTs `eyJ…`, and DB URLs with inline passwords `postgres://user:pass@`.
