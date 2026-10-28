import hmac
import os
import secrets
import subprocess

import requests
import yaml
from argon2 import PasswordHasher
from flask import Flask, abort, jsonify, request

app = Flask(__name__)
app.config["SESSION_COOKIE_SECURE"] = True
app.config["SESSION_COOKIE_HTTPONLY"] = True
DEBUG = os.environ.get("APP_DEBUG") == "1"
API_KEY = os.environ["PAYMENTS_API_KEY"]
ph = PasswordHasher()


@app.route("/invoices/<invoice_id>")
def get_invoice(db, current_user, invoice_id):
    cur = db.cursor()
    cur.execute("SELECT * FROM invoices WHERE id = %s AND account_id = %s", (invoice_id, current_user.account_id))
    row = cur.fetchone()
    if row is None:
        abort(404)
    return jsonify(row)


@app.route("/ping")
def ping():
    host = request.args.get("host", "")
    if not host.replace(".", "").replace("-", "").isalnum():
        abort(400)
    out = subprocess.run(["ping", "-c", "1", "--", host], capture_output=True, text=True, timeout=5, check=False)
    return out.stdout


def load_config(text):
    return yaml.safe_load(text)


def charge(amount_cents):
    return requests.post("https://api.payments-provider.com/charge", json={"amount": amount_cents},
                         headers={"Authorization": f"Bearer {API_KEY}"}, timeout=10)


def register(password):
    return ph.hash(password), secrets.token_urlsafe(32)


def check(signature, expected_sig):
    return hmac.compare_digest(signature, expected_sig)


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=8000)
