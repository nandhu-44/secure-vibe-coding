# Rate limiting & resource limits, per framework

Defaults: login/OTP 5 per 15 min per IP+account · signup/reset/email-send 3–5 per hour · general API 100/min per user · public API 60/min per IP. Use Redis-backed storage when running more than one instance. Respond `429` with `Retry-After`.

**Behind a proxy or CDN**, configure the trusted proxy hop count. Otherwise every request appears to come from the proxy IP, or an attacker spoofs `X-Forwarded-For`.

## Express / Node
```ts
import rateLimit from "express-rate-limit";
import { RedisStore } from "rate-limit-redis";
app.set("trust proxy", 1); // exactly the number of proxies in front of you
app.use(express.json({ limit: "100kb" }));
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, limit: 5, standardHeaders: "draft-7", legacyHeaders: false,
  keyGenerator: (req) => `${req.ip}:${String(req.body?.email ?? "").toLowerCase()}`,
  store: new RedisStore({ sendCommand: (...args) => redis.sendCommand(args) }),
});
app.post("/auth/login", loginLimiter, loginHandler);
app.use("/api", rateLimit({ windowMs: 60_000, limit: 100 }));
```
Alternatives: `rate-limiter-flexible` (also supports per-account lockout), and `@fastify/rate-limit` for Fastify.

## Next.js
Route Handlers and Server Actions don't have built-in limits. Use `@upstash/ratelimit` (edge-compatible) inside the handler or middleware:
```ts
import { Ratelimit } from "@upstash/ratelimit";
import { Redis } from "@upstash/redis";
const ratelimit = new Ratelimit({ redis: Redis.fromEnv(), limiter: Ratelimit.slidingWindow(5, "15 m") });
export async function POST(req: Request) {
  const ip = (req.headers.get("x-forwarded-for") ?? "").split(",")[0].trim() || "unknown"; // trust only your platform's header
  const { success } = await ratelimit.limit(`login:${ip}`);
  if (!success) return new Response("Too many requests", { status: 429 });
  // ...
}
```

## FastAPI / Starlette
```python
from slowapi import Limiter
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded
from slowapi import _rate_limit_exceeded_handler
limiter = Limiter(key_func=get_remote_address, storage_uri=os.environ.get("REDIS_URL", "memory://"))
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

@app.post("/auth/login")
@limiter.limit("5/15minutes")
async def login(request: Request, body: LoginIn): ...
```
Cap body size at the proxy (nginx `client_max_body_size`) or with middleware. Run uvicorn with `--proxy-headers --forwarded-allow-ips=<proxy ip>`.

## Flask
```python
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
limiter = Limiter(get_remote_address, app=app, storage_uri=os.environ.get("REDIS_URL", "memory://"), default_limits=["100/minute"])
@app.post("/login")
@limiter.limit("5 per 15 minutes")
def login(): ...
app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024
```

## Django / DRF
```python
REST_FRAMEWORK = {
  "DEFAULT_THROTTLE_CLASSES": ["rest_framework.throttling.AnonRateThrottle", "rest_framework.throttling.UserRateThrottle", "rest_framework.throttling.ScopedRateThrottle"],
  "DEFAULT_THROTTLE_RATES": {"anon": "60/min", "user": "1000/hour", "login": "20/hour"},  # DRF periods are s/m/h/d; pair with django-axes for per-account lockout
}
class LoginView(APIView):
    throttle_scope = "login"
```
For login lockout use `django-axes`. Set `DATA_UPLOAD_MAX_MEMORY_SIZE` and `FILE_UPLOAD_MAX_MEMORY_SIZE`.

## Spring Boot
Use Bucket4j (with Redis/JCache) in a `OncePerRequestFilter` or `HandlerInterceptor`, keyed by user or IP. Alternatives are Resilience4j `RateLimiter` for outbound calls, and the gateway (Spring Cloud Gateway `RequestRateLimiter`). Set `spring.servlet.multipart.max-file-size` and `server.tomcat.max-swallow-size`.

## Go
```go
import "golang.org/x/time/rate"
// per-key limiters in a sync.Map with eviction, or use github.com/ulule/limiter / httprate (chi)
r.Use(httprate.LimitByIP(100, time.Minute))
r.With(httprate.Limit(5, 15*time.Minute, httprate.WithKeyFuncs(httprate.KeyByIP, keyByEmail))).Post("/login", login)
srv := &http.Server{ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second}
handler = http.MaxBytesHandler(handler, 1<<20)
```

## Laravel
```php
RateLimiter::for('login', fn (Request $r) => [Limit::perMinutes(15, 5)->by($r->ip().'|'.Str::lower($r->input('email')))]);
Route::post('/login', LoginController::class)->middleware('throttle:login');
```

## Edge / infrastructure
Cloudflare rate-limiting rules or WAF, AWS WAF rate-based rules, API Gateway usage plans, nginx `limit_req_zone`. These are good as an extra layer but don't replace per-account limits in the app, because the edge doesn't know the user.

## LLM / cost endpoints
Apply per-user token or request budgets (daily/monthly), a concurrency cap of 1–3 in-flight requests per user, `max_tokens` on every call, and provider-side spend limits. See `secure-ai-features`.
