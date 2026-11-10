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
| [GHSA-5rq2-4mjm-m7q2](https://github.com/Budibase/budibase/security/advisories/GHSA-5rq2-4mjm-m7q2) | `budibase` | ![9.1 Critical](https://img.shields.io/badge/9.1-Critical-8b1a1a?style=flat-square) | Unauthenticated automation execution via User-Agent trust (CWE-807) |
| [CVE-2026-117635](https://github.com/go-gitea/gitea/security/advisories/GHSA-37xv-m4w7-j2fh) | `gitea` | ![8.1 High](https://img.shields.io/badge/8.1-High-cf222e?style=flat-square) | Token scope bypass on the admin API (CWE-284) |
| [GHSA-r4cx-rg3p-25g7](https://github.com/docmost/docmost/security/advisories/GHSA-r4cx-rg3p-25g7) | `docmost` | ![8.1 High](https://img.shields.io/badge/8.1-High-cf222e?style=flat-square) | Path traversal to arbitrary file read (CWE-22) |
| [GHSA-whp2-qr7v-7cf3](https://github.com/seaweedfs/seaweedfs/security/advisories/GHSA-whp2-qr7v-7cf3) | `seaweedfs` | ![8.1 High](https://img.shields.io/badge/8.1-High-cf222e?style=flat-square) | Object Lock bypass on bucket deletion (CWE-863) |
| [GHSA-g293-vf99-xv36](https://github.com/directus/directus/security/advisories/GHSA-g293-vf99-xv36) | `directus` | ![7.5 High](https://img.shields.io/badge/7.5-High-cf222e?style=flat-square) | Anonymous DoS via alias amplification (CWE-770) |
| [CVE-2026-110932](https://access.redhat.com/security/cve/cve-2026-110932) | `keycloak` | ![7.5 High](https://img.shields.io/badge/7.5-High-cf222e?style=flat-square) | Unauthenticated disk exhaustion via theme gzip cache (CWE-400) |
| [GHSA-59xh-5vwx-4c4q](https://assakaf.com/articles/paperless-ngx-privesc/) | `paperless-ngx` | ![7.1 High](https://img.shields.io/badge/7.1-High-cf222e?style=flat-square) | Privilege escalation to superuser (CWE-697) |
| [CVE-2026-59206](https://assakaf.com/articles/n8n-prototype-pollution-auth-bypass/) | `n8n` | ![7.1 High](https://img.shields.io/badge/7.1-High-cf222e?style=flat-square) | Prototype pollution to data disclosure (CWE-1321) |
| [CVE-2026-103288](https://www.cve.org/CVERecord?id=CVE-2026-103288) | `Ghost` | ![7.1 High](https://img.shields.io/badge/7.1-High-cf222e?style=flat-square) | Authorization bypass in comment likes (CWE-639) |
| [GHSA-vp6f-78w7-v422](https://github.com/docmost/docmost/security/advisories/GHSA-vp6f-78w7-v422) | `docmost` | ![6.8 Medium](https://img.shields.io/badge/6.8-Medium-d4a72c?style=flat-square) | MFA secret overwrite (CWE-287) |
| [CVE-2026-125652](https://access.redhat.com/security/cve/cve-2026-125652) | `keycloak` | ![6.8 Medium](https://img.shields.io/badge/6.8-Medium-d4a72c?style=flat-square) | Mandatory PKCE bypass via the password reset flow (CWE-862) |
| [CVE-2026-121885](https://github.com/podman-container-tools/podman/security/advisories/GHSA-55rm-rwr7-q2wr) | `podman` | ![6.5 Medium](https://img.shields.io/badge/6.5-Medium-d4a72c?style=flat-square) | Arbitrary systemd unit restart via image auto-update labels (CWE-807) |
| [CVE-2026-77074](https://github.com/n8n-io/n8n/security/advisories/GHSA-233r-fpgw-fx8x) | `n8n` | ![6.0 Medium](https://img.shields.io/badge/6.0-Medium-d4a72c?style=flat-square) | Node parameter injection to blind SSRF (CWE-918) |
| [CVE-2026-121746](https://github.com/nvm-sh/nvm/security/advisories/GHSA-8qjx-8r8m-mpqh) | `nvm` | ![5.5 Medium](https://img.shields.io/badge/5.5-Medium-d4a72c?style=flat-square) | Symlink following to arbitrary file overwrite (CWE-59) |
| [GHSA-vqrf-cjv6-rf89](https://github.com/docmost/docmost/security/advisories/GHSA-vqrf-cjv6-rf89) | `docmost` | ![5.3 Medium](https://img.shields.io/badge/5.3-Medium-d4a72c?style=flat-square) | Unauthenticated cross-tenant disclosure (CWE-285) |
| [CVE-2026-111361](https://github.com/podman-container-tools/container-libs/security/advisories/GHSA-pggw-qqjf-6cxw) | `container-libs` | ![4.6 Medium](https://img.shields.io/badge/4.6-Medium-d4a72c?style=flat-square) | Image digest and signature validation bypass (CWE-345) |
| [CVE-2026-121751](https://github.com/nvm-sh/nvm/security/advisories/GHSA-7prg-rw9c-82h7) | `nvm` | ![3.1 Low](https://img.shields.io/badge/3.1-Low-6e7781?style=flat-square) | Mirror-supplied version string to shell arithmetic evaluation (CWE-78) |
<!-- ADVISORIES:END -->

<sub>Rows link to the write-up when one is published, otherwise to the CVE record or the advisory. Verify independently in the [GitHub Advisory Database](https://github.com/advisories?query=credit%3Aassakafpix). Reports in triage are not listed until the maintainer publishes.</sub>

## Open source contributions

| Project | Contribution |
|:---|:---|
| [`projectdiscovery/httpx`](https://github.com/projectdiscovery/httpx) | [Graceful shutdown on interrupt](https://assakaf.com/articles/httpx-graceful-shutdown/), [PR #2393](https://github.com/projectdiscovery/httpx/pull/2393), merged February 2026. The resume index was written from dispatched targets rather than completed ones, so a resumed scan silently skipped hosts; shutdown now drains in-flight work first. |
| [`turbot/steampipe-plugin-googleworkspace`](https://github.com/turbot/steampipe-plugin-googleworkspace) | [Admin Reports table](https://assakaf.com/articles/steampipe-googleworkspace-reports/), [PR #88](https://github.com/turbot/steampipe-plugin-googleworkspace/pull/88), merged. Google Workspace audit logs (logins, admin actions, OAuth tokens, Drive, mobile) queryable as SQL for detection and compliance. |
