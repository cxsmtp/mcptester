import os
import ast
import json
import shlex
import ipaddress
import secrets
import hashlib
import base64
import logging
import subprocess
from urllib.parse import urlparse, urljoin

from flask import (
    Flask,
    request,
    redirect,
    render_template_string,
    make_response,
    send_from_directory,
    abort,
)
import requests
import yaml
from markupsafe import escape
from flask_talisman import Talisman

app = Flask(__name__)

# FIX (Use_Of_Hardcoded_Password / secrets): load all secrets from the environment.
# Generate an ephemeral key only as a last resort so the app still boots in dev.
app.config["SECRET_KEY"] = os.environ.get("SECRET_KEY") or secrets.token_hex(32)

# FIX (Missing_HSTS_Header / Missing_Content_Security_Policy): apply security
# headers globally via flask-talisman. This enforces HSTS and a locked-down
# Content-Security-Policy on every response from the application object itself.
CSP = {
    "default-src": "'self'",
    "script-src": "'self'",
    "object-src": "'none'",
    "frame-ancestors": "'none'",
}
Talisman(
    app,
    force_https=False,  # TLS is terminated upstream; HSTS is still emitted.
    strict_transport_security=True,
    strict_transport_security_max_age=31536000,
    strict_transport_security_include_subdomains=True,
    content_security_policy=CSP,
    frame_options="DENY",
    session_cookie_secure=True,
    session_cookie_http_only=True,
)

# FIX: credentials are read from the environment, never hardcoded.
DB_USER = os.environ.get("DB_USER", "")
DB_PASSWORD = os.environ.get("DB_PASSWORD", "")

# Base directories used to constrain file access.
DATA_DIR = os.path.realpath(os.environ.get("DATA_DIR", "/var/data"))

# Outbound fetch allow-list (SSRF defense).
ALLOWED_FETCH_HOSTS = {
    h.strip()
    for h in os.environ.get("ALLOWED_FETCH_HOSTS", "example.com,api.example.com").split(",")
    if h.strip()
}

# Allow-list of safe local redirect targets / trusted hosts.
ALLOWED_REDIRECT_HOSTS = {
    h.strip()
    for h in os.environ.get("ALLOWED_REDIRECT_HOSTS", "").split(",")
    if h.strip()
}

logging.basicConfig(level=logging.INFO)


def get_db():
    import sqlite3

    conn = sqlite3.connect("users.db")
    return conn


@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "")
    password = request.form.get("password", "")
    conn = get_db()
    cur = conn.cursor()
    # FIX (SQL Injection): parameterized query with bound parameters.
    cur.execute(
        "SELECT * FROM users WHERE username = ? AND password = ?",
        (username, password),
    )
    row = cur.fetchone()
    if row:
        # FIX (XSS): escape user input before reflecting it.
        return "Welcome " + escape(username)
    return "Invalid credentials"


@app.route("/search")
def search():
    term = request.args.get("q", "")
    conn = get_db()
    cur = conn.cursor()
    # FIX (SQL Injection): bound parameter; build the LIKE wildcard safely.
    cur.execute("SELECT name FROM products WHERE name LIKE ?", ("%" + term + "%",))
    results = cur.fetchall()
    # FIX (Reflected/Stored XSS): escape() neutralizes any HTML/script in the
    # reflected term. Avoid render_template_string entirely, which Checkmarx
    # treats as an injection sink regardless of binding.
    return "<h1>Results for " + escape(term) + "</h1><p>" + str(len(results)) + " matches</p>"


def _validate_host(host):
    """Allow only hostnames/IPs made of a safe character set."""
    if not host or len(host) > 255:
        return False
    allowed = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-")
    return all(c in allowed for c in host)


@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    # FIX (Command Injection): validate input and invoke without a shell,
    # passing arguments as a list so user input can never be interpreted.
    if not _validate_host(host):
        abort(400, "invalid host")
    output = subprocess.check_output(
        ["ping", "-c", "1", "--", host], shell=False, timeout=5
    )
    # FIX (Reflected XSS): escape command output before returning it as a page.
    return escape(output.decode("utf-8", "replace"))


@app.route("/exec")
def execute():
    code = request.args.get("code", "")
    # FIX (Code Injection): no eval(). Only parse literals safely.
    try:
        result = ast.literal_eval(code)
    except (ValueError, SyntaxError):
        abort(400, "only literal expressions are allowed")
    # FIX (Reflected XSS): escape the reflected value.
    return escape(str(result))


@app.route("/run")
def run_cmd():
    name = request.args.get("cmd", "")
    # FIX (Command Injection): branch on the validated name and invoke a hardcoded
    # literal argument list, so no user-derived value ever reaches subprocess.
    if name == "uptime":
        subprocess.run(["uptime"], shell=False, timeout=5, check=False)
    elif name == "date":
        subprocess.run(["date"], shell=False, timeout=5, check=False)
    else:
        abort(400, "unknown command")
    return "done"


@app.route("/download")
def download():
    filename = request.args.get("file", "")
    # FIX (Path Traversal): send_from_directory rejects traversal and keeps the
    # resolved path inside DATA_DIR.
    try:
        return send_from_directory(DATA_DIR, filename, as_attachment=True)
    except (NotADirectoryError, FileNotFoundError):
        abort(404)


@app.route("/read")
def read_file():
    name = request.args.get("path", "")
    # FIX (Path Traversal): canonicalize and confirm the result stays under DATA_DIR.
    candidate = os.path.realpath(os.path.join(DATA_DIR, name))
    if not (candidate == DATA_DIR or candidate.startswith(DATA_DIR + os.sep)):
        abort(400, "invalid path")
    if not os.path.isfile(candidate):
        abort(404)
    with open(candidate, "r", encoding="utf-8") as f:
        # FIX (Stored XSS): escape file contents before returning them as a page.
        return escape(f.read())


@app.route("/load", methods=["POST"])
def load_obj():
    data = request.get_data()
    # FIX (Insecure Deserialization): use JSON instead of pickle.
    try:
        obj = json.loads(data.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        abort(400, "invalid JSON")
    # FIX (Stored XSS): escape deserialized content before reflecting it.
    return escape(str(obj))


@app.route("/parse", methods=["POST"])
def parse_yaml():
    data = request.get_data()
    # FIX (Unsafe YAML): safe_load cannot instantiate arbitrary Python objects.
    try:
        obj = yaml.safe_load(data)
    except yaml.YAMLError:
        abort(400, "invalid YAML")
    return str(obj)


def _is_safe_fetch_url(url):
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        return False
    host = parsed.hostname
    if not host or host not in ALLOWED_FETCH_HOSTS:
        return False
    # Reject hosts that resolve to private / loopback / link-local ranges.
    try:
        ip = ipaddress.ip_address(host)
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved:
            return False
    except ValueError:
        pass  # not a literal IP; the allow-list above is the control.
    return True


@app.route("/fetch")
def fetch_url():
    url = request.args.get("url", "")
    # FIX (SSRF): only allow vetted hosts and schemes, with a timeout and no redirects.
    if not _is_safe_fetch_url(url):
        abort(400, "url not allowed")
    resp = requests.get(url, timeout=5, allow_redirects=False)
    # FIX (Stored XSS): escape fetched remote content before returning it.
    return escape(resp.text)


@app.route("/redirect")
def do_redirect():
    target = request.args.get("next", "/")
    # FIX (Open Redirect): only redirect to same-origin or allow-listed hosts.
    host_url = request.host_url
    absolute = urljoin(host_url, target)
    parsed = urlparse(absolute)
    same_origin = parsed.netloc == urlparse(host_url).netloc
    if not (same_origin or parsed.netloc in ALLOWED_REDIRECT_HOSTS):
        abort(400, "invalid redirect target")
    return redirect(absolute)


@app.route("/hash")
def hash_pw():
    pw = request.args.get("pw", "")
    # FIX (Broken Crypto): salted PBKDF2-HMAC-SHA256 instead of MD5.
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", pw.encode(), salt, 200_000)
    return salt.hex() + "$" + digest.hex()


@app.route("/token")
def gen_token():
    # FIX (Insecure Randomness): use a cryptographically secure generator.
    return secrets.token_urlsafe(32)


@app.route("/template")
def template():
    name = request.args.get("name", "World")
    # FIX (SSTI/XSS): user input passed as an auto-escaped variable, not concatenated
    # into the template source.
    return render_template_string("Hello {{ name }}", name=name)


@app.route("/cookie")
def set_cookie():
    resp = make_response("ok")
    # FIX (Insecure Cookie): HttpOnly + Secure + SameSite set.
    resp.set_cookie(
        "session",
        secrets.token_urlsafe(16),
        httponly=True,
        secure=True,
        samesite="Lax",
    )
    return resp


@app.route("/decode")
def decode():
    data = request.args.get("d", "")
    # FIX (Code Injection): decode and return as escaped text only — never eval.
    try:
        decoded = base64.b64decode(data, validate=True)
        text = decoded.decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        abort(400, "invalid base64")
    return str(escape(text))


@app.after_request
def cors_headers(resp):
    # FIX (CORS): restrict to a single trusted origin instead of "*" with credentials.
    # Security headers (HSTS, CSP, X-Frame-Options, nosniff) are applied by Talisman.
    allowed_origin = os.environ.get("CORS_ALLOWED_ORIGIN")
    origin = request.headers.get("Origin")
    if allowed_origin and origin == allowed_origin:
        resp.headers["Access-Control-Allow-Origin"] = allowed_origin
        resp.headers["Access-Control-Allow-Credentials"] = "true"
        resp.headers["Vary"] = "Origin"
    return resp


if __name__ == "__main__":
    # FIX (Debug_Enabled): never run with the debugger in production; bind address
    # and debug flag come from the environment and default to safe values.
    host = os.environ.get("BIND_HOST", "127.0.0.1")
    debug = os.environ.get("FLASK_DEBUG", "false").lower() == "true"
    app.run(host=host, port=5000, debug=debug)
