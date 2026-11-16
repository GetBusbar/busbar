# Security advisories

This directory holds the published advisory for each confirmed vulnerability in a released Busbar
version, handled under [SECURITY.md](../../../SECURITY.md). An advisory is published here when its fix
ships, together with the GitHub Security Advisory; an unfixed vulnerability stays private until then.
Shipped-behaviour and billing disclosures that are not vulnerabilities live in
[docs/advisories/](../../advisories/), not here.

## File name

`YYYY-MM-DD-<short-slug>.md`, dated the day the advisory is published.

## Header block

Every advisory starts with a YAML front-matter block, so a CVE Record can be produced from it without
re-reading the prose. Copy [TEMPLATE.md](TEMPLATE.md).

| Field | Required | Meaning |
|---|---|---|
| `id` | yes | `BUSBAR-SA-YYYY-NNN`, the project's own advisory number |
| `ghsa` | when issued | the GitHub Security Advisory id (`GHSA-xxxx-xxxx-xxxx`) |
| `cve` | yes | a list of CVE ids; `[]` until one is assigned, or when none was requested |
| `published` | yes | the publication date, `YYYY-MM-DD` |
| `severity` | yes | `critical`, `high`, `medium` or `low` (SECURITY.md's scale) |
| `cvss` | when scored | the CVSS v3.1 or v4.0 vector string |
| `cwe` | yes | a list of CWE ids (`CWE-79`) |
| `affected` | yes | per component: the product (`busbar`, or a plugin's repository name), its CPE when one exists, and the affected version range |
| `fixed` | yes | per component: the first fixed version on each supported line, or `none` |
| `credit` | yes | who reported it (with their consent), or `internal` |

Version ranges use the `>= 1.5.0, < 1.5.6` form. A component that is not fixed on a supported line
says so in `fixed` and in the prose.

## Body

The sections of the template: summary, impact, affected configurations, the fix (commit or release),
workarounds, and the timeline from report to publication.
