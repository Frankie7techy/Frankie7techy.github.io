# GitHub / OSINT Security Sweep 2026-09-22
**Scope:** Publicly disclosed vulnerabilities from NVD published 2026-09-19, with GitHub Security Advisory references where available.
**Purpose:** Defensive triage and responsible disclosure preparation. No exploitation attempts.

## Summary
Sweep of NVD batch published 2026-09-19 yielded 100+ entries. 12 items matched high-impact patterns: RCE, auth bypass, privilege escalation, SQLi, file upload. 7 of these are WordPress plugin supply-chain defects with clear GitHub repository provenance, suitable for vendor reporting.

## Valid Candidates for Reporting

### 1. WP Photo Album Plus – Remote Code Execution via ImageMagick
- **CVE:** CVE-2026-87909
- **Published:** 2026-09-19T03:17:15.853
- **Vector:** wppa_image_magick() sanitizes multipart filename insufficiently before concatenation into ImageMagick command executed via exec()
- **Impact:** Unauthenticated RCE
- **Evidence:** NVD description confirms insufficient sanitization of multipart upload filename.
- **Reporting notes:** Contact plugin author via WordPress.org Security contact. Provide PoC request with crafted filename containing shell metacharacters. Recommend using escapeshellarg and allow-listed commands.

### 2. Botiga Pro WordPress – Unauthenticated REST privilege escalation
- **CVE:** CVE-2026-86591
- **Published:** 2026-09-19T07:16:33.063
- **Vector:** REST route lacks authorization check, allows unauthenticated update of arbitrary WordPress options
- **Impact:** Site takeover / privilege escalation
- **Reporting notes:** GitHub repo likely botigathemes/botiga-pro. Provide request example for /wp-json/botiga/v1/... route.

### 3. Gravity Forms – Arbitrary File Upload
- **CVE:** CVE-2026-84434
- **Published:** 2026-09-19T03:17:15.573
- **Vector:** upload_file function bypass via hidden file upload fields; validation pipeline mismatch
- **Impact:** Remote file write → RCE
- **Reporting notes:** Vendor: Gravity Forms. Reference field validation pipeline discrepancy.

### 4. Ultra Addons for Contact Form 7 – Arbitrary File Upload
- **CVE:** CVE-2026-84750
- **Published:** 2026-09-19T07:16:32.753
- **Vector:** No type/extension validation, predictable public path
- **Impact:** Unauthenticated arbitrary file upload
- **Reporting notes:** Report to plugin author via WordPress.org.

### 5. Create plugin – SQL Injection via order_by
- **CVE:** CVE-2026-13191
- **Published:** 2026-09-19T08:16:52.050
- **Vector:** Insufficient escaping on user supplied 'order_by' parameter
- **Impact:** Authenticated SQLi
- **Reporting notes:** Provide parameterized query fix.

### 6. Create plugin – SQL Injection via order
- **CVE:** CVE-2026-13200
- **Published:** 2026-09-19T08:16:52.200
- **Vector:** Same class, 'order' parameter
- **Impact:** Authenticated SQLi

### 7. The Welcomizer – RCE via eval
- **CVE:** CVE-2026-4327
- **Published:** 2026-09-19T08:16:53.887
- **Vector:** twiz_ajax_callback 'savesection' handler missing auth, uses eval() on user-supplied custom logic
- **Impact:** Unauthenticated RCE
- **Reporting notes:** Recommend removal of eval, capability check.

## GitHub Security Advisory Cross-Reference
Where available, advisories reference GitHub repositories:
- BerriAI LiteLLM CVE-2026-59822 – GHSA-7488-6r32-c95q
- Kludex Starlette CVE-2026-48710 – GHSA-86qp-5c8j-p5mr
- Kestra OSS CVE-2026-49869 – GHSA-5vc5-wxxq-3fjx

These demonstrate the pattern of supply-chain issues in open source libraries. For reporting, verify repository owner, check existing issues, and follow coordinated disclosure.

## Responsible Disclosure Checklist
- Confirm vulnerability is not already patched
- Reproduce with minimal test case in isolated lab
- Collect timestamps, request/response logs, no production data
- Contact vendor via security.txt or official channel
- Allow 90 days for remediation before public disclosure

## Next Steps
- Prioritize CVE-2026-87909 and CVE-2026-86591 for immediate reporting due to unauthenticated RCE / takeover potential
- Prepare PoC scripts in isolated WordPress testbed
- Track vendor responses in tracker

---
Generated: 2026-09-22
Ethical use only.
