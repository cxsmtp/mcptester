# Checkmarx One — Findings, Remediation & Triage (Before / After)

This document tracks the security posture of the sample app across a **before**
(`vulnerable-app/`) and **after** (`fixed-app/`) state, mapped to OWASP Top 10 (2021)
and to the Checkmarx One engines (SAST, SCA, IaC/KICS, Secret Detection, API Security,
Containers).

> **Scan status — LIVE RESULTS RECORDED.** Both scans were run against the public repo
> via Checkmarx One (project `owasp-juice-lab`, `deu.ast.checkmarx.net`). Engines
> **KICS, SCA, and Secret Detection completed**; **SAST failed on both scans** with
> `engine failed: (65) One or more queries violated the query security policy` — a
> tenant-level SAST query-policy restriction, not a code or scan-config issue (a
> Checkmarx tenant admin must adjust the SAST query policy / preset to enable it).
> The numbers below are the real 3-engine results.
>
> | Scan | Commit | Scan ID | Total |
> |------|--------|---------|------:|
> | BEFORE (`vulnerable-app` isolated) | `ef59b26` | `31404b3d-4df3-4753-b202-89cda54c5761` | **367** |
> | AFTER (`fixed-app` isolated) | `e145603` | `b0b1dcd6-4cdc-4a3e-bb66-f689ec8e4999` | **55** |
> | (reference) both apps together | `6c25e5e` | `0b0ab0cb-a9cf-4530-8d01-2b11102ea075` | 412 |

---

## 1. Expected findings inventory (BEFORE — `vulnerable-app/`)

Counts are the *crafted* vulnerability sinks. Checkmarx typically reports **one result
per data-flow path**, so SAST result counts are usually higher than the sink count
(multiple sources reach the same sink). Treat these as the lower bound.

### SAST (source code)

| OWASP | Category | Where | Crafted sinks |
|-------|----------|-------|--------------:|
| A03 | SQL Injection | `routes/injection.js`, `services/report_service.py` | 6 |
| A03 | NoSQL Injection | `routes/injection.js` | 2 |
| A03 | OS Command Injection | `routes/injection.js`, `report_service.py` | 6 |
| A03 | Code Injection (eval/Function/vm/pickle) | `routes/injection.js`, `report_service.py` | 6 |
| A03 | Reflected/Stored XSS | `routes/xss.js` | 6 |
| A03 | DOM XSS | `public/dashboard.html` | 5 |
| A03 | Server-Side Template Injection | `report_service.py`, `routes/xss.js` | 3 |
| A01 | Path Traversal | `routes/access.js`, `report_service.py` | 4 |
| A01 | IDOR / Missing Authorization | `routes/access.js` | 4 |
| A01 | Open Redirect | `routes/access.js`, `routes/xss.js`, `report_service.py` | 4 |
| A02 | Weak Hash (MD5/SHA1) | `routes/crypto.js`, `report_service.py` | 3 |
| A02 | Weak Cipher / Static IV / ECB | `routes/crypto.js` | 3 |
| A02 | Insecure Randomness | `routes/crypto.js` | 2 |
| A02 | Disabled TLS Verification | `routes/crypto.js`, `report_service.py` | 3 |
| A05 | XXE | `routes/xxe.js` | 3 |
| A07 | Weak/None JWT, hardcoded creds | `routes/auth.js` | 6 |
| A08 | Insecure Deserialization | `routes/deserialize.js`, `report_service.py` | 3 |
| A08 | Prototype Pollution | `routes/deserialize.js` | 2 |
| A08 | Zip Slip | `routes/deserialize.js` | 1 |
| A10 | SSRF | `routes/ssrf.js`, `report_service.py` | 5 |
| A04 | Mass Assignment / trust-client price | `routes/misc.js` | 2 |
| A09 | Sensitive data in logs / verbose errors | `routes/misc.js`, `app.js` | 3 |
| — | ReDoS | `routes/misc.js` | 1 |
| A05 | Wildcard CORS + credentials, debug endpoint | `routes/misc.js`, `app.js` | 3 |
| **SAST total (sinks)** | | | **≈ 90** |

### SCA (dependencies)
`package.json` pins **26** knowingly-outdated packages (e.g. `lodash 4.17.4`,
`node-serialize 0.0.4`, `handlebars 4.0.11`, `marked 0.3.6`, `jquery 3.2.1`,
`js-yaml 3.10.0`, `axios 0.18.0`, `request 2.81.0`, `adm-zip 0.4.7`). These map to
dozens of CVEs (prototype pollution, ReDoS, RCE, XSS). **Expected: 80–150 SCA findings.**

### IaC / KICS
| File | Sample misconfigurations | Expected |
|------|--------------------------|---------:|
| `Dockerfile` | outdated base, root user, secret in ENV, `curl \| bash`, no HEALTHCHECK | ~6 |
| `docker-compose.yml` | privileged, host network, docker.sock mount, host-root volume, `cap_add: ALL` | ~10 |
| `deploy/terraform/main.tf` | public S3, SG `0.0.0.0/0`, public+unencrypted RDS, `*:*` IAM | ~12 |
| `deploy/k8s/deployment.yaml` | privileged, runAsRoot, host PID/network, hostPath `/`, no limits/probes | ~12 |
| **KICS total** | | **~40** |

### Secret Detection
`.env`, `config/secrets.js`, IaC files, `openapi.yaml`, and `public/dashboard.html`
contain AWS keys, a Stripe live key, GitHub/SendGrid tokens, DB passwords, a JWT
secret, and an embedded private key. **Expected: ~30 secret findings.**

### API Security
`openapi.yaml` documents no global auth, a BOLA endpoint, a debug/env dump, an
example credential, and an API key embedded in the spec. **Expected: ~6 findings.**

**BEFORE grand total (order of magnitude): ~300+ findings across all engines.**

---

## 2. Remediation mapping (AFTER — `fixed-app/`)

| OWASP | Vulnerability (before) | Fix (after) |
|-------|------------------------|-------------|
| A03 | String-concatenated SQL | `mysql2` **parameterized** `execute(sql, params)`; `ORDER BY` column **allowlisted** (`src/db.js`, `routes/injection.js`) |
| A03 | `exec`/`execSync` with shell | `execFile('ping', ['-c','1','--',host])`, input regex-validated, no shell |
| A03 | `eval`/`Function`/`vm` | removed; arithmetic via a **recursive-descent parser** over `[0-9+-*/()]` only |
| A03 | Reflected/stored XSS | `escape-html` on all output; `res.type('html')` with encoded values |
| A03 | Markdown XSS | `marked` output run through **DOMPurify** |
| A03 | DOM XSS | `textContent` instead of `innerHTML`/`document.write`; CSP header; external script |
| A01 | IDOR / missing authz | `requireUser` + ownership check + `requireRole('admin')` |
| A01 | Path traversal | `path.resolve` within a base dir + containment check (`startsWith(root + sep)`) |
| A01 | Open redirect | redirect **allowlist** (`/`, `/dashboard`, `/profile`) |
| A02 | MD5/SHA1 password hash | **bcrypt** (cost 12) |
| A02 | DES/ECB, static IV | **AES-256-GCM**, key from env, `crypto.randomBytes(12)` IV, auth tag |
| A02 | `Math.random` tokens | `crypto.randomBytes` / `crypto.randomInt` |
| A02 | `rejectUnauthorized:false`, `NODE_TLS_REJECT_UNAUTHORIZED=0` | removed; TLS verification on; https-only |
| A05 | XXE | `fast-xml-parser` (no external entities); DOCTYPE/ENTITY rejected |
| A07 | JWT `alg:none`, `decode()` w/o verify, hardcoded creds | `jwt.verify(..., {algorithms:['HS256']})`, `expiresIn:'15m'`, bcrypt login, no backdoor |
| A07 | Insecure cookies, session fixation | `httpOnly + secure + sameSite:'strict'`; server-generated session id; rate limiting |
| A08 | `node-serialize.unserialize`, `pickle.loads` | `JSON.parse` / `json.loads` only |
| A08 | `lodash.merge` prototype pollution | `safeMerge` blocking `__proto__`/`constructor`/`prototype` |
| A08 | Zip slip | per-entry `path.resolve` containment check |
| A10 | SSRF | https-only + **host allowlist** + DNS resolution + private-range block + `maxRedirects:0` |
| A04 | Mass assignment | explicit field allowlist; server-side price table |
| A09 | Logging PAN/CVV, stack traces to client | masked `last4` only; generic 500, details server-side |
| A05 | Wildcard CORS, missing headers, debug endpoint | `helmet()`, origin allowlist, debug endpoints removed |
| A02/Secrets | Hardcoded secrets & `.env` in repo | env-only via `required()`; `.env.example` template; `.gitignore` + `.dockerignore` exclude secrets |
| A06/SCA | 26 outdated deps | upgraded to current majors; `node-serialize`/`request`/`xmldom`/`libxmljs` removed |
| IaC | Docker/Compose/TF/K8s misconfig | non-root, read-only fs, dropped caps, no host ns, encryption, private networking, least-privilege IAM, pinned images, probes/limits |

---

## 3. Triage — reported items that are NOT findings (or expected residue)

When you run the real scan, expect a portion of results to be non-actionable. Pre-classified:

| # | Likely reported (AFTER or BEFORE) | Verdict | Rationale |
|---|-----------------------------------|---------|-----------|
| T1 | `fixed-app`: `execFile('ping', ...)` flagged as *Command Injection* | **Not exploitable** | Fixed binary + argv array, `shell:false`, and host is `^[a-z0-9.-]+$`-validated. No shell metacharacter reaches an interpreter. |
| T2 | `fixed-app/routes/injection.js` `ORDER BY ${col}` flagged as *SQL Injection* | **False positive** | `col` is constrained to a static `SORTABLE` allowlist; `dir` is a boolean choice. Not attacker-controlled. |
| T3 | `vulnerable-app` intentionally-vulnerable files re-reported after fix | **By design / out of scope** | `vulnerable-app/` is the permanent BEFORE target and is meant to stay vulnerable; only `fixed-app/` is remediated. Exclude `vulnerable-app/**` from the AFTER scan (see `cx-exclusions`). |
| T4 | SCA transitive advisory with no reachable path (e.g. dev-only) | **Not exploitable (needs review)** | Confirm with Checkmarx SCA *exploitable path* — mark as *Proposed Not Exploitable* if the vulnerable API isn't called. |
| T5 | `Dockerfile` digest placeholder `sha256:000…` flagged as invalid pin | **Cosmetic** | Placeholder for the demo; replace with the real digest of `node:20-slim` at build time. |
| T6 | `fixed-app` `safeArithmetic` recursion flagged as *ReDoS/complexity* | **Not exploitable** | Operates on an input already restricted to `[0-9+-*/(). ]`; linear in input length. |
| T7 | K8s/TF placeholder digests / example ARNs flagged | **Cosmetic** | Demo placeholders; substitute real values in a real deployment. |

> How to record triage in Checkmarx One: set each result's state to
> **Not Exploitable** / **Proposed Not Exploitable** with a comment referencing the
> row above, or encode T1–T2 as accepted queries in the project's
> *predicates*, and exclude `vulnerable-app/**` from the AFTER project.

---

## 4. Before / After snapshot — ACTUAL Checkmarx One results

Live results from Checkmarx One (KICS + SCA + Secret Detection; SAST blocked by tenant
query policy on both scans, so code-level findings are **not** included in these totals).

### By severity

| Severity | BEFORE (`vulnerable-app`) | AFTER (`fixed-app`) | Reduction |
|----------|--------------------------:|--------------------:|----------:|
| Critical | 33 | 3 | −91% |
| High | 197 | 12 | −94% |
| Medium | 107 | 16 | −85% |
| Low | 19 | 15 | −21% |
| Info | 11 | 9 | −18% |
| **Total** | **367** | **55** | **−85%** |

### What drove the reduction

- **SCA** — `vulnerable-app` pinned 26 outdated packages (dozens of critical/high CVEs:
  lodash, handlebars, marked, js-yaml, node-serialize, adm-zip, xmldom, etc.). `fixed-app`
  upgraded/removed them, eliminating essentially all SCA findings except one **newly
  disclosed** transitive CVE (see triage T8).
- **Secret Detection** — the hardcoded AWS/DB/JWT/API keys in `vulnerable-app/.env` and
  `config/secrets.js` are gone from the `fixed-app` tree (env-only). The 2 residual
  secret criticals are **historical** (see T9).
- **KICS** — the insecure Dockerfile/Compose/Terraform/K8s dropped from many
  critical/high misconfigs to a handful on the hardened manifests (mostly placeholder
  digests) plus the constant root `.github/workflows/checkmarx.yml`.

### Residual AFTER findings — triage (added from real results)

| # | Finding | Verdict | Action |
|---|---------|---------|--------|
| T8 | **SCA CRITICAL** `tar@6.2.1` → CVE-2026-59873 (node-tar gzip-bomb, CWE-770, disclosed 2026-07-08, transitive via bcrypt/jsdom) | **Real but low-risk** (DoS in an extraction path the app never invokes) | **Fixed** — added `overrides: { "tar": ">=7.5.19" }` to `fixed-app/package.json`. |
| T9 | **2× Secret CRITICAL** `Generic-Api-Key` pointing at `/vulnerable-app/config/secrets.js:30` | **Not in current tree** | The AFTER tree has no `vulnerable-app/`; Secret Detection (`slsaStep: Source`) scans **git history**, so it still sees the secret in older commits. Real remediation = purge history (git-filter-repo/BFG) **and rotate** the exposed values. Not a `fixed-app` code defect. |
| T10 | Residual KICS on `fixed-app` hardened IaC + root workflow | **Mostly cosmetic** | Placeholder image digests (`sha256:000…`, `sha256:111…`) and the CI workflow file. Replace digests at build time; scope/annotate the rest. |

Reproduce: scan `vulnerable-app/` and `fixed-app/` as isolated trees (or use the two
scan IDs above). The combined-repo scan (412) is provided only as a whole-repo reference —
per-directory isolation is required for a clean comparison because the CxMCP finding list
does not expose file paths for aggregate filtering.
