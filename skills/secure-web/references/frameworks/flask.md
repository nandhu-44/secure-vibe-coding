# Flask secure baseline

```python
import os
from flask import Flask, abort, g, jsonify, request
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_talisman import Talisman          # security headers + HTTPS
from flask_wtf.csrf import CSRFProtect       # for cookie-session form apps

app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ["FLASK_SECRET_KEY"],
    SESSION_COOKIE_SECURE=True, SESSION_COOKIE_HTTPONLY=True, SESSION_COOKIE_SAMESITE="Lax",
    MAX_CONTENT_LENGTH=2 * 1024 * 1024,
)
Talisman(app, content_security_policy={"default-src": "'self'"}, force_https=True)
CSRFProtect(app)
limiter = Limiter(get_remote_address, app=app, storage_uri=os.environ.get("REDIS_URL", "memory://"), default_limits=["100/minute"])

@app.get("/notes/<int:note_id>")
@login_required
def get_note(note_id):
    note = db.session.execute(db.select(Note).filter_by(id=note_id, owner_id=g.user.id)).scalar_one_or_none()
    if note is None:
        abort(404)
    return jsonify(id=note.id, title=note.title)

if __name__ == "__main__":
    app.run(host="127.0.0.1", debug=os.environ.get("FLASK_DEBUG") == "1")  # never debug=True in prod (Werkzeug console = RCE)
```

## Pitfalls
- `render_template_string(user_input)` is SSTI and leads to RCE. Use static templates.
- `send_file(user_path)`: use `send_from_directory(BASE, filename)` with `werkzeug.utils.secure_filename`.
- Default Flask sessions are signed client-side cookies, not encrypted. Don't store secrets in `session`. Use server-side sessions (Flask-Session) for sensitive state.
- Use flask-login / Flask-Security with argon2 hashing. Never store plaintext passwords.
