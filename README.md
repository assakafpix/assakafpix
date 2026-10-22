<div align="center">

# Adel Assakaf

Security researcher at [Escape](https://escape.tech) (YC W23).<br>
Vulnerability research on self-hosted open source, coordinated disclosure.

</div>

## Published advisories

<!-- ADVISORIES:START -->
| Advisory | Project | CVSS | Class |
|:---|:---|:---|:---|
| [CVE-2026-52848](https://assakaf.com/articles/glpi-mfa-bypass-request-uri/) | `glpi` | ![9.2 Critical](https://img.shields.io/badge/9.2-Critical-8b1a1a?style=flat-square) | MFA bypass (CWE-287) |
| [GHSA-r4cx-rg3p-25g7](https://github.com/docmost/docmost/security/advisories/GHSA-r4cx-rg3p-25g7) | `docmost` | ![8.1 High](https://img.shields.io/badge/8.1-High-cf222e?style=flat-square) | Path traversal to arbitrary file read (CWE-22) |
| [GHSA-g293-vf99-xv36](https://github.com/directus/directus/security/advisories/GHSA-g293-vf99-xv36) | `directus` | ![7.5 High](https://img.shields.io/badge/7.5-High-cf222e?style=flat-square) | Anonymous DoS via alias amplification (CWE-770) |
| [GHSA-59xh-5vwx-4c4q](https://assakaf.com/articles/paperless-ngx-privesc/) | `paperless-ngx` | ![7.1 High](https://img.shields.io/badge/7.1-High-cf222e?style=flat-square) | Privilege escalation to superuser (CWE-697) |
| [CVE-2026-59206](https://assakaf.com/articles/n8n-prototype-pollution-auth-bypass/) | `n8n` | ![7.1 High](https://img.shields.io/badge/7.1-High-cf222e?style=flat-square) | Prototype pollution to data disclosure (CWE-1321) |
| [CVE-2026-103288](https://www.cve.org/CVERecord?id=CVE-2026-103288) | `Ghost` | ![7.1 High](https://img.shields.io/badge/7.1-High-cf222e?style=flat-square) | Authorization bypass in comment likes (CWE-639) |
| [GHSA-vp6f-78w7-v422](https://github.com/docmost/docmost/security/advisories/GHSA-vp6f-78w7-v422) | `docmost` | ![6.8 Medium](https://img.shields.io/badge/6.8-Medium-d4a72c?style=flat-square) | MFA secret overwrite (CWE-287) |
| [GHSA-233r-fpgw-fx8x](https://github.com/n8n-io/n8n/security/advisories/GHSA-233r-fpgw-fx8x) | `n8n` | ![6.0 Medium](https://img.shields.io/badge/6.0-Medium-d4a72c?style=flat-square) | Node parameter injection to blind SSRF (CWE-918) |
| [GHSA-vqrf-cjv6-rf89](https://github.com/docmost/docmost/security/advisories/GHSA-vqrf-cjv6-rf89) | `docmost` | ![5.3 Medium](https://img.shields.io/badge/5.3-Medium-d4a72c?style=flat-square) | Unauthenticated cross-tenant disclosure (CWE-285) |
<!-- ADVISORIES:END -->

<sub>Rows link to the write-up when one is published, otherwise to the CVE record or the advisory. Verify independently in the [GitHub Advisory Database](https://github.com/advisories?query=credit%3Aassakafpix). Reports in triage are not listed until the maintainer publishes.</sub>

## Open source contributions

| Project | Contribution |
|:---|:---|
| [`projectdiscovery/httpx`](https://github.com/projectdiscovery/httpx) | [Graceful shutdown on interrupt](https://assakaf.com/articles/httpx-graceful-shutdown/), [PR #2393](https://github.com/projectdiscovery/httpx/pull/2393), merged February 2026. The resume index was written from dispatched targets rather than completed ones, so a resumed scan silently skipped hosts; shutdown now drains in-flight work first. |
| [`turbot/steampipe-plugin-googleworkspace`](https://github.com/turbot/steampipe-plugin-googleworkspace) | [Admin Reports table](https://assakaf.com/articles/steampipe-googleworkspace-reports/), [PR #88](https://github.com/turbot/steampipe-plugin-googleworkspace/pull/88), merged. Google Workspace audit logs (logins, admin actions, OAuth tokens, Drive, mobile) queryable as SQL for detection and compliance. |
