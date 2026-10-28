import hashlib
import os
import pickle
import random
import subprocess

import requests
import yaml
from flask import Flask, request, render_template_string, redirect

app = Flask(__name__)
DEBUG = True  # expect: SV-WEB-001


@app.route("/user")
def get_user(db):
    uid = request.args["id"]
    cur = db.cursor()
    cur.execute(f"SELECT * FROM users WHERE id = {uid}")  # expect: SV-INJ-001
    cur.execute("SELECT * FROM users WHERE name = '%s'" % uid)  # expect: SV-INJ-001
    return cur.fetchone()


@app.route("/ping")
def ping():
    host = request.args["host"]
    subprocess.run(f"ping -c 1 {host}", shell=True)  # expect: SV-INJ-002
    os.system("nslookup " + host)  # expect: SV-INJ-002
    return eval(request.args["expr"])  # expect: SV-INJ-003


@app.route("/load", methods=["POST"])
def load():
    obj = pickle.loads(request.data)  # expect: SV-INJ-005
    cfg = yaml.load(request.data)  # expect: SV-INJ-005
    return str(obj) + str(cfg)


@app.route("/fetch")
def fetch():
    r = requests.get(request.args["url"])  # expect: SV-INJ-007, SV-NET-003
    requests.post("http://api.payments-provider.com/charge", json={}, timeout=5)  # expect: SV-NET-001
    requests.get("https://internal.corp.example.org", verify=False, timeout=5)  # expect: SV-NET-002
    return r.text


@app.route("/hello")
def hello():
    return render_template_string(request.args["tpl"])  # expect: SV-INJ-008


@app.route("/go")
def go():
    return redirect(request.args["next"])  # expect: SV-WEB-006


def register(password):
    password_hash = hashlib.md5(password.encode()).hexdigest()  # expect: SV-CRY-001, SV-CRY-002
    reset_token = str(random.randint(100000, 999999))  # expect: SV-CRY-004
    return password_hash, reset_token


def check(signature, expected_sig):
    return signature == expected_sig  # expect: SV-CRY-007


if __name__ == "__main__":
    app.run(host="0.0.0.0", debug=True)  # expect: SV-WEB-001


@app.post("/auth/login")  # expect: SV-WEB-009
def login():
    return "ok"
