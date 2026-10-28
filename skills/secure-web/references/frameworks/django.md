# Django / DRF secure baseline

## settings.py (production)
```python
DEBUG = env.bool("DJANGO_DEBUG", default=False)
SECRET_KEY = env("DJANGO_SECRET_KEY")                  # no default
ALLOWED_HOSTS = env.list("DJANGO_ALLOWED_HOSTS")
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")  # only behind a trusted proxy
SECURE_SSL_REDIRECT = True
SECURE_HSTS_SECONDS = 63072000; SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SESSION_COOKIE_SECURE = CSRF_COOKIE_SECURE = True
SESSION_COOKIE_HTTPONLY = True
SESSION_COOKIE_SAMESITE = "Lax"
X_FRAME_OPTIONS = "DENY"
SECURE_CONTENT_TYPE_NOSNIFF = True
PASSWORD_HASHERS = ["django.contrib.auth.hashers.Argon2PasswordHasher", "django.contrib.auth.hashers.PBKDF2PasswordHasher"]
DATA_UPLOAD_MAX_MEMORY_SIZE = 2_621_440
```
Run `python manage.py check --deploy` and fix every warning.

## Views & ORM
- Scope querysets: `Invoice.objects.filter(account=request.user.account).get(pk=pk)`. In DRF, override `get_queryset()` to filter by user. Don't rely on `queryset = Model.objects.all()` + permissions alone.
- DRF serializers: explicit `fields = [...]` (never `"__all__"`), `read_only_fields` for owner/role/status. Set the owner in `perform_create(serializer.save(owner=self.request.user))`.
- `DEFAULT_PERMISSION_CLASSES = ["rest_framework.permissions.IsAuthenticated"]` (deny by default). Use object permissions for per-object checks.
- Never use `raw()`/`extra()`/`cursor.execute()` with formatting. Use params: `cursor.execute("... %s", [x])`.
- Templates auto-escape. Avoid `|safe`, `mark_safe`, `{% autoescape off %}` on user data.
- Avoid `@csrf_exempt`. For APIs with token auth use DRF's authentication classes. With `SessionAuthentication`, DRF enforces CSRF.
- Throttling: DRF throttles plus `django-axes` for login lockout.
