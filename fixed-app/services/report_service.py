"""Remediated Python service (Flask). OWASP Top 10 issues fixed. AFTER state."""

import os
import re
import json
import hashlib
import ipaddress
import socket
from urllib.parse import urlparse

import bcrypt
import yaml
import requests
from flask import Flask, request, redirect, abort

app = Flask(__name__)
app.secret_key = os.environ["FLASK_SECRET_KEY"]        # from environment, not hardcoded

DB_PATH = os.environ.get("DB_PATH", "app.db")
ALLOWED_HOSTS = set(filter(None, os.environ.get("ALLOWED_FETCH_HOSTS", "").split(",")))
ALLOWED_REDIRECTS = {"/", "/dashboard", "/profile"}


@app.route("/user")
def user():
    import sqlite3
    uid = request.args.get("id", "")
    conn = sqlite3.connect(DB_PATH)
    # Parameterized query — no string formatting.
    rows = conn.execute("SELECT id, username FROM users WHERE id = ?", (uid,)).fetchall()
    return json.dumps(rows)


@app.route("/ping")
def ping():
    host = request.args.get("host", "")
    if not re.fullmatch(r"[A-Za-z0-9.-]+", host):
        abort(400)
    # Fixed argv, no shell. (subprocess with a list and shell=False.)
    import subprocess
    try:
        out = subprocess.run(["ping", "-c", "1", "--", host], capture_output=True, timeout=3)
        return out.stdout
    except subprocess.SubprocessError:
        abort(504)


@app.route("/load", methods=["POST"])
def load():
    # JSON instead of pickle — no code execution on deserialize.
    try:
        return json.dumps(json.loads(request.data or b"{}"))
    except ValueError:
        abort(400)


@app.route("/yaml", methods=["POST"])
def parse_yaml():
    # safe_load rejects arbitrary Python object construction.
    try:
        return json.dumps(yaml.safe_load(request.data or b""))
    except yaml.YAMLError:
        abort(400)


@app.route("/hash")
def hash_pw():
    # bcrypt instead of unsalted MD5.
    pw = request.args.get("pw", "").encode()
    return bcrypt.hashpw(pw, bcrypt.gensalt(12)).decode()


def _is_public(host: str) -> bool:
    try:
        addr = ipaddress.ip_address(socket.gethostbyname(host))
        return not (addr.is_private or addr.is_loopback or addr.is_link_local or addr.is_reserved)
    except (socket.gaierror, ValueError):
        return False


@app.route("/fetch")
def fetch():
    url = urlparse(request.args.get("url", ""))
    if url.scheme != "https" or url.hostname not in ALLOWED_HOSTS or not _is_public(url.hostname):
        abort(400)
    # TLS verification stays on (verify defaults to True).
    return requests.get(url.geturl(), timeout=5, allow_redirects=False).text


@app.route("/go")
def go():
    nxt = request.args.get("next", "/")
    return redirect(nxt if nxt in ALLOWED_REDIRECTS else "/")


@app.route("/read")
def read():
    # Contain reads within a base directory.
    base = os.path.realpath("/var/www/files")
    target = os.path.realpath(os.path.join(base, request.args.get("path", "")))
    if not target.startswith(base + os.sep):
        abort(400)
    with open(target) as f:
        return f.read()


if __name__ == "__main__":
    # debug off; bind loopback by default.
    app.run(host="127.0.0.1", port=5000, debug=False)
