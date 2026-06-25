import os
import ssl
import hashlib
import secrets
import ftplib

import jwt

# FIX (Hardcoded secrets): all secrets come from the environment.
JWT_SECRET = os.environ.get("JWT_SECRET")
GITHUB_TOKEN = os.environ.get("GITHUB_TOKEN")

JWT_ALGORITHM = "HS256"


def _require_secret():
    if not JWT_SECRET:
        raise RuntimeError("JWT_SECRET is not configured")
    return JWT_SECRET


def make_jwt(user, is_admin=False):
    # FIX: privilege is passed in explicitly rather than always granting admin.
    return jwt.encode(
        {"user": user, "admin": bool(is_admin)},
        _require_secret(),
        algorithm=JWT_ALGORITHM,
    )


def verify_jwt(token):
    # FIX (JWT signature bypass): always verify the signature with the configured
    # algorithm; reject 'none' and unsigned tokens.
    return jwt.decode(
        token,
        _require_secret(),
        algorithms=[JWT_ALGORITHM],
        options={"verify_signature": True},
    )


def hash_password(password, salt=None):
    # FIX (Broken Crypto): salted PBKDF2-HMAC-SHA256 instead of unsalted SHA1.
    if salt is None:
        salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 200_000)
    return salt.hex() + "$" + digest.hex()


def get_ssl_context():
    # FIX (Disabled cert verification): use a verifying default context.
    ctx = ssl.create_default_context()
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    return ctx


def upload(host, user, password, path):
    # FIX (Cleartext FTP): use FTPS (TLS) and protect the data channel.
    ftps = ftplib.FTP_TLS(host, context=get_ssl_context())
    ftps.login(user, password)
    ftps.prot_p()
    with open(path, "rb") as fh:
        ftps.storbinary("STOR file", fh)
    ftps.quit()
