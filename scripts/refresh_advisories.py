#!/usr/bin/env python3
"""Regenerate the advisories table and the counters in README.md.

Source of truth is GitHub itself: every published advisory that credits HANDLE, read from the
repositories listed in REPOS plus the global advisory database. Nothing is hand-maintained
except that list, and advisories.json for a short class label, a write-up link, or a CVSS
score when GitHub publishes none.

Each row links, in this order of preference:
  1. the write-up on the blog, when advisories.json has one for that advisory,
  2. the CVE record, when the advisory carries a CVE,
  3. the GitHub advisory page.
The identifier shown is the CVE when there is one, otherwise the GHSA id. The CVSS column
takes the 4.0 score GitHub publishes, then the 3.x one, then the override.

The script only rewrites what sits between the markers, so the rest of the README is safe:

    <!-- ADVISORIES:START -->  ... table ...  <!-- ADVISORIES:END -->
    <!-- COUNTERS:START -->    ... line  ...  <!-- COUNTERS:END -->

Usage:  GITHUB_TOKEN=... python3 scripts/refresh_advisories.py [--check] [--force]
        --check exits 1 when the README would change, for CI.
        Without a token the API allows 60 requests an hour and the collection comes back
        incomplete; the script then refuses to shrink the table unless --force is given.
"""
import json, os, pathlib, re, sys, urllib.error, urllib.request

HANDLE = "assakafpix"
RACINE = pathlib.Path(__file__).resolve().parent.parent
README = RACINE / "README.md"
NOTES = pathlib.Path(__file__).resolve().parent / "advisories.json"

# Projects this handle has reported to. Add a line when a new report is accepted; an entry
# that never credits the handle costs one request and nothing else.
REPOS = [
    "n8n-io/n8n", "glpi-project/glpi", "directus/directus", "docmost/docmost",
    "Cacti/cacti", "xwiki/xwiki-platform", "appwrite/appwrite", "keycloak/keycloak",
    "grafana/grafana", "podman-container-tools/podman", "mastodon/mastodon",
    "coollabsio/coolify", "immich-app/immich", "metabase/metabase", "strapi/strapi",
    "TryGhost/Ghost", "paperless-ngx/paperless-ngx", "vuejs/core", "nuxt/nuxt", "ceph/ceph",
    "apache/httpd",
]

RANG = {"critical": 0, "high": 1, "moderate": 2, "medium": 2, "low": 3}
COULEUR = {"critical": "8b1a1a", "high": "cf222e", "moderate": "d4a72c", "medium": "d4a72c",
           "low": "2da44e"}
CWE_COURT = {
    "CWE-22": "Path traversal", "CWE-74": "Injection", "CWE-77": "Command injection",
    "CWE-78": "OS command injection", "CWE-79": "Cross-site scripting",
    "CWE-94": "Code injection", "CWE-200": "Information disclosure",
    "CWE-269": "Privilege escalation", "CWE-285": "Improper authorization",
    "CWE-287": "Improper authentication", "CWE-306": "Missing authentication",
    "CWE-352": "Cross-site request forgery", "CWE-502": "Deserialization",
    "CWE-522": "Insufficiently protected credentials", "CWE-601": "Open redirect",
    "CWE-639": "Authorization bypass through user-controlled key",
    "CWE-645": "Overly restrictive account lockout", "CWE-770": "Allocation without limits",
    "CWE-799": "Improper control of interaction frequency", "CWE-862": "Missing authorization",
    "CWE-863": "Incorrect authorization", "CWE-918": "Server-side request forgery",
    "CWE-1321": "Prototype pollution",
}
# REPOS=owner/repo,owner/repo dans l environnement restreint la passe, pour un essai rapide.
if os.environ.get("REPOS"):
    REPOS = [r.strip() for r in os.environ["REPOS"].split(",") if r.strip()]

INCOMPLET = []   # depots dont la lecture a echoue pendant cette passe


def get(url):
    req = urllib.request.Request(url, headers={
        "Accept": "application/vnd.github+json", "User-Agent": "refresh-advisories"})
    tok = os.environ.get("GITHUB_TOKEN")
    if tok:
        req.add_header("Authorization", "Bearer " + tok)
    with urllib.request.urlopen(req, timeout=40) as r:
        return json.load(r)


def credite(adv):
    return HANDLE.lower() in json.dumps(adv.get("credits") or []).lower()


def depuis_depots():
    for repo in REPOS:
        page = 1
        while True:
            url = ("https://api.github.com/repos/%s/security-advisories"
                   "?per_page=100&state=published&page=%d" % (repo, page))
            try:
                lot = get(url)
            except urllib.error.HTTPError as e:
                print("  %s: HTTP %s, collecte incomplete" % (repo, e.code), file=sys.stderr)
                INCOMPLET.append("%s (HTTP %s)" % (repo, e.code))
                break
            if not isinstance(lot, list) or not lot:
                break
            for a in lot:
                if credite(a):
                    yield repo.split("/")[-1], a
            if len(lot) < 100:
                break
            page += 1


def depuis_base_globale():
    """Filet de securite: un advisory d un depot absent de REPOS mais present dans la base."""
    url = "https://github.com/advisories?query=credit%%3A%s" % HANDLE
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    try:
        with urllib.request.urlopen(req, timeout=40) as r:
            html = r.read().decode("utf-8", "replace")
    except Exception as e:
        print("  base globale injoignable (%s), on continue" % e, file=sys.stderr)
        return
    for g in sorted(set(re.findall(r"GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}", html))):
        try:
            a = get("https://api.github.com/advisories/" + g)
        except Exception:
            continue
        pkgs = [v["package"]["name"] for v in (a.get("vulnerabilities") or []) if v.get("package")]
        yield (pkgs[0] if pkgs else "?"), a


def notes_de(a, notes):
    return notes.get(a["ghsa_id"]) or notes.get(a.get("cve_id") or "") or {}


def classe(a, notes):
    n = notes_de(a, notes)
    if n.get("class"):
        return n["class"]
    cwes = a.get("cwes") or []
    if not cwes:
        return "Undisclosed class"
    cid = cwes[0].get("cwe_id", "")
    return "%s (%s)" % (CWE_COURT.get(cid) or (cwes[0].get("name") or cid), cid)


def lien(a, notes):
    """Write-up du blog s il existe, sinon la fiche CVE, sinon l advisory GitHub."""
    n = notes_de(a, notes)
    if n.get("writeup"):
        return n["writeup"]
    if a.get("cve_id"):
        return "https://www.cve.org/CVERecord?id=" + a["cve_id"]
    return a.get("html_url") or ("https://github.com/advisories/" + a["ghsa_id"])


def score_de(a, notes):
    """CVSS 4.0 publie par GitHub, sinon 3.x, sinon le score de l override, sinon rien."""
    n = notes_de(a, notes)
    if n.get("cvss"):
        return float(n["cvss"])
    sev = a.get("cvss_severities") or {}
    for k in ("cvss_v4", "cvss_v3"):
        s = (sev.get(k) or {}).get("score")
        if s:
            return float(s)
    s = (a.get("cvss") or {}).get("score")
    return float(s) if s else None


def badge(a, notes):
    sev = (a.get("severity") or "").lower()
    if sev == "moderate":
        sev = "medium"
    score = score_de(a, notes)
    txt = ("%.1f %s" % (score, sev.title())) if score is not None else sev.title()
    return "![%s](https://img.shields.io/badge/%s-%s?style=flat-square)" % (
        txt, txt.replace(" ", "-"), COULEUR.get(sev, "6e7781"))


def main():
    notes = json.loads(NOTES.read_text()) if NOTES.exists() else {}
    vus = {}
    for projet, a in list(depuis_depots()) + list(depuis_base_globale()):
        if a["ghsa_id"] not in vus:
            vus[a["ghsa_id"]] = (projet, a)

    ordre = sorted(vus.values(), key=lambda t: (
        RANG.get((t[1].get("severity") or "").lower(), 9),
        -(score_de(t[1], notes) or 0),
        t[1].get("published_at") or ""))

    lignes = ["| [%s](%s) | `%s` | %s | %s |" % (
        a.get("cve_id") or a["ghsa_id"], lien(a, notes), projet, badge(a, notes), classe(a, notes))
        for projet, a in ordre]

    cves = sum(1 for _, a in ordre if a.get("cve_id"))
    table = ("| Advisory | Project | CVSS | Class |\n|:---|:---|:---|:---|\n" + "\n".join(lignes))

    txt = README.read_text(encoding="utf-8")
    encours = re.search(r"&nbsp;·&nbsp; `([^`]*(?:triage|embargo)[^`]*)`", txt)
    compteurs = "`%d CVEs assigned` &nbsp;·&nbsp; `%d published advisories`" % (cves, len(ordre))
    if encours:
        compteurs += " &nbsp;·&nbsp; `%s`" % encours.group(1)

    neuf = re.sub(r"(?<=<!-- ADVISORIES:START -->\n).*?(?=\n<!-- ADVISORIES:END -->)",
                  table, txt, flags=re.S)
    neuf = re.sub(r"(?<=<!-- COUNTERS:START -->\n).*?(?=\n<!-- COUNTERS:END -->)",
                  compteurs, neuf, flags=re.S)

    # Un tableau qui retrecit apres une collecte incomplete est presque toujours une erreur de
    # transport, pas une advisory retiree. On refuse d ecrire et on sort en erreur.
    avant = txt.count("\n| [")
    if INCOMPLET and len(ordre) < avant and "--force" not in sys.argv:
        print("REFUS: %d advisories collectees contre %d dans le README, %d depot(s) en echec (%s). "
              "Relance avec GITHUB_TOKEN, ou --force si la baisse est voulue."
              % (len(ordre), avant, len(INCOMPLET), ", ".join(INCOMPLET[:3])), file=sys.stderr)
        sys.exit(2)

    if "--check" in sys.argv:
        print("%d advisories, %d CVEs" % (len(ordre), cves))
        sys.exit(1 if neuf != txt else 0)
    README.write_text(neuf, encoding="utf-8")
    print("%d advisories, %d CVEs, README %s" % (len(ordre), cves,
          "mis a jour" if neuf != txt else "inchange"))


if __name__ == "__main__":
    main()
