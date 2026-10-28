# Laravel / PHP secure baseline

- `.env` holds `APP_KEY`, DB creds, etc. `APP_DEBUG=false` and `APP_ENV=production` in prod (the Ignition debug page has led to RCE).
- **Mass assignment**: define `$fillable` (never `$guarded = []`). Use `$request->validated()` from a FormRequest, not `$request->all()`.
- **AuthZ**: Policies plus `$this->authorize('update', $post)` or `Gate`. Scope queries: `$request->user()->posts()->findOrFail($id)`.
- **SQL**: Eloquent/Query Builder bindings. `DB::raw`, `whereRaw`, and `orderByRaw` only with bound `?` params. Allowlist column names.
- **XSS**: Blade `{{ }}` escapes. `{!! !!}` only for sanitized HTML (HTMLPurifier).
- **CSRF**: `@csrf` in forms (`VerifyCsrfToken` middleware). Keep the exclusions list empty except for signed webhooks.
- **Rate limiting**: `RateLimiter::for(...)` plus `throttle:` middleware (see rate-limiting.md).
- **Passwords**: `Hash::make` (bcrypt/argon2id via `config/hashing.php`). Use Breeze/Fortify/Jetstream for auth flows.
- **Uploads**: `$request->validate(['file' => 'required|file|mimes:png,jpg,pdf|max:2048'])`, store via `Storage::disk('private')->putFile()` (random names).
- **Plain PHP**: PDO with `ATTR_EMULATE_PREPARES=false` and prepared statements. `htmlspecialchars($s, ENT_QUOTES, 'UTF-8')`. `password_hash($p, PASSWORD_ARGON2ID)`. Never `unserialize()` user data (use `json_decode`). Never `include $_GET[...]`. Turn off `display_errors`.
