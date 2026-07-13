# owasp-juice-lab — deliberately vulnerable app for Checkmarx testing

> ⚠️ **WARNING: This application is intentionally insecure.**
> It exists only to exercise SAST/SCA/IaC/Secrets scanners (Checkmarx One).
> **Do not deploy it, expose it to a network, or run it against real data.**
> Every "bug" here is on purpose.

## Purpose

A crafted target that produces **hundreds of findings** across the OWASP Top 10
(2021) and across every Checkmarx One engine:

| Checkmarx engine        | Source of findings                                             |
|-------------------------|---------------------------------------------------------------|
| SAST                    | `src/**` (Node), `services/*.py` (Python), `public/*.html` (JS) |
| SCA                     | `package.json` — pinned to known-vulnerable versions          |
| IaC (KICS)              | `Dockerfile`, `docker-compose.yml`, `deploy/terraform`, `deploy/k8s` |
| Secret Detection        | `.env`, `config/secrets.js`, IaC files, client HTML           |
| API Security            | `openapi.yaml` + the Express routes                           |
| Containers              | `Dockerfile` base image + installed OS/npm packages           |

## OWASP Top 10 (2021) coverage

- **A01 Broken Access Control** — IDOR, path traversal, missing authz, open redirect (`routes/access.js`)
- **A02 Cryptographic Failures** — MD5/SHA1, DES/ECB, static IV, `Math.random` tokens, hardcoded keys (`routes/crypto.js`, `config/secrets.js`)
- **A03 Injection** — SQLi, NoSQLi, command injection, `eval`/`Function`, XSS, SSTI (`routes/injection.js`, `routes/xss.js`)
- **A04 Insecure Design** — trust-client-price checkout, mass assignment (`routes/misc.js`)
- **A05 Security Misconfiguration** — XXE, verbose errors, wildcard CORS, debug endpoints (`routes/xxe.js`, `routes/misc.js`, `app.js`)
- **A06 Vulnerable & Outdated Components** — old npm deps, CDN jQuery without SRI (`package.json`, `public/dashboard.html`)
- **A07 Auth Failures** — weak JWT (`alg:none`), hardcoded creds, no rate limiting, insecure cookies (`routes/auth.js`)
- **A08 Software & Data Integrity Failures** — insecure deserialization, prototype pollution, zip slip (`routes/deserialize.js`)
- **A09 Logging & Monitoring Failures** — logging card/CVV, leaking stack traces (`routes/misc.js`, `app.js`)
- **A10 SSRF** — fetch arbitrary URLs, webhook port scan (`routes/ssrf.js`)

## How to scan (Checkmarx One)

CI: `.github/workflows/checkmarx.yml` runs all engines and uploads SARIF.

CLI:

```bash
cx scan create \
  --project-name owasp-juice-lab \
  --sources . \
  --scan-types sast,sca,kics,secret-detection,api-security,containers \
  --branch main
```

See `SECURITY-FINDINGS.md` for the before/after triage and remediation notes.
