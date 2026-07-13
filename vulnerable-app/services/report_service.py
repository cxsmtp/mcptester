"""Deliberately vulnerable Python service (Flask) for Checkmarx SAST multi-language coverage.
OWASP Top 10 2021. DO NOT DEPLOY."""

import os
import pickle
import subprocess
import sqlite3
import hashlib
import yaml
import requests
from flask import Flask, request, redirect, make_response

app = Flask(__name__)
app.secret_key = "hardcoded-flask-secret-key"  # A02: hardcoded secret

DB_PASSWORD = "Sup3rS3cr3tR00tP@ss!"            # A02: hardcoded credential


@app.route("/user")
def user():
    uid = request.args.get("id")
    conn = sqlite3.connect("app.db")
    # A03: SQL injection via string formatting
    row = conn.execute("SELECT * FROM users WHERE id = '%s'" % uid).fetchall()
    return str(row)


@app.route("/ping")
def ping():
    host = request.args.get("host")
    # A03: OS command injection (shell=True + concatenation)
    out = subprocess.check_output("ping -c 1 " + host, shell=True)
    return out


@app.route("/run")
def run():
    # A03: os.system command injection
    os.system("echo " + request.args.get("msg"))
    return "ok"


@app.route("/load", methods=["POST"])
def load():
    # A08: insecure deserialization -> RCE
    obj = pickle.loads(request.data)
    return str(obj)


@app.route("/yaml", methods=["POST"])
def parse_yaml():
    # A08: unsafe YAML load
    return str(yaml.load(request.data, Loader=yaml.Loader))


@app.route("/hash")
def hash_pw():
    # A02: weak hashing, no salt
    return hashlib.md5(request.args.get("pw").encode()).hexdigest()


@app.route("/fetch")
def fetch():
    # A10: SSRF + TLS verification disabled
    return requests.get(request.args.get("url"), verify=False).text


@app.route("/go")
def go():
    # A01: open redirect
    return redirect(request.args.get("next"))


@app.route("/template")
def template():
    # A03: server-side template injection via format on user input
    name = request.args.get("name")
    return ("Hello %s" % name).format(config=app.config)


@app.route("/eval")
def do_eval():
    # A03: code injection
    return str(eval(request.args.get("expr")))


@app.route("/read")
def read():
    # A01: path traversal
    with open(request.args.get("path")) as f:
        return f.read()


if __name__ == "__main__":
    # A05: debug mode on, binds all interfaces
    app.run(host="0.0.0.0", port=5000, debug=True)
