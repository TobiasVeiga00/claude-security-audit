# Attribution and data licensing

The source code in this repository is licensed under the [MIT License](LICENSE).

The plugin vendors small digests of public security data under `intel/`, and
queries other sources live at audit time. Each remains under its own terms,
reproduced below. None of these terms restrict the redistribution this plugin
performs, but several require the notices kept here.

---

## Vendored data (shipped in `intel/`)

### CISA Known Exploited Vulnerabilities Catalog

Public domain under [CC0 1.0 Universal](https://creativecommons.org/publicdomain/zero/1.0/).
No attribution is legally required; CISA is credited as a courtesy.
Source: <https://www.cisa.gov/known-exploited-vulnerabilities-catalog>

### MITRE ATT&CK

> © 2026 The MITRE Corporation. This work is reproduced and distributed with the
> permission of The MITRE Corporation.

MITRE ATT&CK® and ATT&CK® are registered trademarks of The MITRE Corporation.
Terms of use: <https://attack.mitre.org/resources/legal-and-branding/terms-of-use/>

### MITRE CWE

> Copyright © 2006–2026, The MITRE Corporation. CWE, CWSS, CWRAF, and the CWE
> logo are trademarks of The MITRE Corporation.

Terms of use: <https://cwe.mitre.org/about/termsofuse.html>

### FIRST CVSS v4.0 calculator tables

The MacroVector lookup tables under `intel/cvss/` are vendored from
[FIRSTdotorg/cvss-v4-calculator](https://github.com/FIRSTdotorg/cvss-v4-calculator),
licensed **BSD-2-Clause**:

> Copyright FIRST, Red Hat, and contributors. SPDX-License-Identifier: BSD-2-Clause

---

## Live data (fetched at audit time, not redistributed)

### NVD (NIST National Vulnerability Database)

This product uses the NVD API but is not endorsed or certified by the NVD. NVD
data is a work of the U.S. Government, in the public domain under 17 U.S.C.
Content retrieved via the API is not attributed to the NVD when modified, per
its terms of use: <https://nvd.nist.gov/developers/terms-of-use>

### FIRST EPSS

EPSS data © FIRST.org. Free for public use. <https://www.first.org/epss>

### OSV.dev

Records are served under their per-source licenses (a mix of CC-BY 4.0, CC0,
Apache-2.0, MIT and BSD). This plugin queries OSV live and does not redistribute
its records. <https://osv.dev>

### MITRE CVE

CVE® is a registered trademark of The MITRE Corporation. CVE records are used
under the CVE Terms of Use: <https://www.cve.org/Legal/TermsOfUse>

---

## OWASP frameworks

This plugin references OWASP framework identifiers, titles and version numbers
(Top 10, ASVS, WSTG, MASVS, MASTG, API Security, CI/CD, GenAI). These are facts,
not expression. The OWASP documents themselves are licensed CC-BY-SA and are
**linked, never copied**, precisely to keep this MIT-licensed repository clear of
the share-alike obligation.

---

## A note on trademarks

The trademarks above belong to their respective owners. Their appearance here
identifies the data sources this plugin uses; it does not imply endorsement of
this plugin by MITRE, FIRST, NIST, CISA, OWASP, or Anthropic.
