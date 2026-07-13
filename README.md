# mcptester

Security-testing sandbox that exercises the full **Checkmarx One** loop —
generate → scan (all engines) → fix → triage → rescan — against a crafted
OWASP Top 10 (2021) target.

## Layout

| Path | State | Purpose |
|------|-------|---------|
| `vulnerable-app/` | **BEFORE** | Deliberately vulnerable Node/Python/JS app. 72 endpoints, 26 outdated deps, insecure Docker/Compose/Terraform/K8s, committed secrets. Meant to stay vulnerable as the permanent scan baseline. |
| `fixed-app/` | **AFTER** | Fully remediated version of the same app. |
| `SECURITY-FINDINGS.md` | — | Expected findings inventory, before→after remediation mapping, triage of non-findings, and the before/after snapshot table. |
| `.github/workflows/checkmarx.yml` | — | CI that runs Checkmarx One with **all engines** and uploads SARIF. |
| `cx-exclusions.txt` | — | File filters for the AFTER scan (excludes the intentionally-vulnerable baseline). |

## Running the scan

The Checkmarx MCP connector (`CxMCP`) must be authorized first. Then either:

- **CI:** push the branch — `.github/workflows/checkmarx.yml` runs automatically, or
- **CLI:**
  ```bash
  # BEFORE
  cx scan create --project-name owasp-juice-lab-before \
    --sources vulnerable-app \
    --scan-types sast,sca,kics,secret-detection,api-security,containers --branch main
  # AFTER
  cx scan create --project-name owasp-juice-lab-after \
    --sources fixed-app \
    --scan-types sast,sca,kics,secret-detection,api-security,containers --branch main
  ```

See **`SECURITY-FINDINGS.md`** for the mapping and the before/after snapshot to fill in
with real scan numbers.

> ⚠️ `vulnerable-app/` is intentionally insecure. Never deploy it or point it at real data.
