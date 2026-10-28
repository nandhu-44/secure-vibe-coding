# Express / Node.js secure baseline

```ts
import express from "express";
import helmet from "helmet";
import cors from "cors";
import rateLimit from "express-rate-limit";
import session from "express-session";
import { z } from "zod";

const app = express();
app.disable("x-powered-by");
app.set("trust proxy", 1);                       // match your real proxy count
app.use(helmet());                               // CSP, HSTS, nosniff, frameguard...
app.use(express.json({ limit: "100kb" }));
app.use(cors({ origin: process.env.ALLOWED_ORIGINS!.split(","), credentials: true }));
app.use("/api", rateLimit({ windowMs: 60_000, limit: 100 }));
app.use(session({
  secret: requireEnv("SESSION_SECRET"),
  resave: false, saveUninitialized: false, name: "__Host-sid",
  cookie: { httpOnly: true, secure: true, sameSite: "lax", maxAge: 8 * 3600_000 },
  store: redisStore,                              // never MemoryStore in prod
}));

const requireAuth: express.RequestHandler = (req, res, next) =>
  req.session.userId ? next() : res.status(401).json({ error: "unauthorized" });

const UpdateProfile = z.object({ displayName: z.string().min(1).max(80), bio: z.string().max(500).optional() }).strict();

app.patch("/api/profile", requireAuth, async (req, res) => {
  const parsed = UpdateProfile.safeParse(req.body);
  if (!parsed.success) return res.status(400).json({ error: "invalid_input" });
  await db.query("UPDATE users SET display_name = $1, bio = $2 WHERE id = $3",
                 [parsed.data.displayName, parsed.data.bio ?? null, req.session.userId]);
  res.status(204).end();
});

app.get("/api/notes/:id", requireAuth, async (req, res) => {
  const { rows } = await db.query("SELECT id, title, body FROM notes WHERE id = $1 AND owner_id = $2",
                                  [req.params.id, req.session.userId]);
  if (!rows[0]) return res.status(404).end();
  res.json(rows[0]);
});

app.use((err, req, res, _next) => {            // generic error handler last
  logger.error({ err, path: req.path }, "unhandled");
  res.status(500).json({ error: "internal_error" });
});
```

## Node pitfalls
- Never `child_process.exec` with interpolation. Use `execFile`/`spawn` with an args array (no `shell: true`).
- Prototype pollution: don't deep-merge user JSON into objects (`lodash.merge`, `Object.assign` with nested user data). Validate with zod `.strict()`. Use `Object.create(null)` for maps.
- `jsonwebtoken`: use `jwt.verify(token, key, { algorithms: ["HS256"], audience, issuer })`. Never `jwt.decode` for auth.
- Regex DoS: avoid nested quantifiers on user input. Prefer `re2` for user-supplied patterns.
- Paths: `const p = path.resolve(BASE, name); if (!p.startsWith(BASE + path.sep)) return 400`.
- Mongo/Mongoose: `mongoose.set("sanitizeFilter", true)` and cast types. Never pass `req.body` as a filter.
- `npm ci` in CI with a committed lockfile. Use `npm audit` / `osv-scanner`.
