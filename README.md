# Veracode VEX Generator

> **Community tool.** Not an official Veracode product and not covered by Veracode Technical Support. Use at your own discretion; issues and PRs welcome.

Turns a Veracode SCA SBOM plus your Veracode SCA findings into a VEX document: one statement per CVE × component saying whether it affects you, and why. Mitigations your team approved in Veracode become machine-readable `not_affected` / `false_positive` statements that scanners, customers and auditors can consume.

## Why use it

- **Your triage, exported.** Approved Veracode mitigations (false positive, by design, network/OS environment, accepted risk, reported to library maintainer) map to the matching VEX states and justifications. The mitigation comments become the explanation.
- **Conservative by design.** Only *approved* mitigations count as not affected. Proposals stay under investigation. If two findings for one component disagree (agent vs. upload scan), the worse outcome wins and the report flags it.
- **Veracode risk data included.** EPSS score and percentile, exploit observed (CISA KEV), CVSS ratings, CWEs and policy status from Veracode are carried into the VEX.
- **Linked to your SBOM.** CycloneDX VEX points at SBOM components by BOM-Link (`urn:cdx:<serial>/<version>#<bom-ref>`). Run it on a trimmed SBOM ([Veracode SBOM Trim](https://github.com/ancient-cthulhu/Veracode-SBOM-Trim)) and statements for removed components drop out.
- **Valid output, every time.** CycloneDX output is schema-checked (JSON schema / XSD); OpenVEX output is checked for required fields, enums and CISA minimums (justification or impact statement for `not_affected`, action statement for `affected`). On failure nothing is written.
- **Drop-in for CI.** One file, Python 3.9+, standard library only, no network calls.

## Input and output

- SBOM: CycloneDX 1.4–1.6, JSON or XML, from the Veracode SBOM REST API (`type=application` / `type=agent`), with its `vulnerabilities` section. SPDX is rejected.
- Findings: Findings REST API export with `scan_type=SCA&include_annot=TRUE` (SCA must be the only scan type). Pass every page (`-f` is repeatable). Without findings every statement is `in_triage` / `under_investigation`.
- Scope: findings default to the latest policy scan; add `context=<sandbox_guid>` for a sandbox. Export the SBOM and findings from the same app and scan context.
- Output: CycloneDX VEX (JSON or XML, same spec version as the SBOM) or OpenVEX 0.2.0 (JSON). Inputs are never overwritten.
- Encoding: UTF-8, or UTF-16/32 with a BOM (what PowerShell `>` writes).

## Export the inputs

```bash
pip install httpie veracode-api-signing   # set VERACODE_API_KEY_ID / VERACODE_API_KEY_SECRET

# SBOM with vulnerabilities (application profile)
http --auth-type=veracode_hmac --check-status GET \
  "https://api.veracode.com/srcclr/sbom/v1/targets/<APP_GUID>/cyclonedx" \
  type==application -o app_sbom.json

# SCA findings with mitigation history (page through _links.next with page==N)
http --auth-type=veracode_hmac --check-status GET \
  "https://api.veracode.com/appsec/v2/applications/<APP_GUID>/findings" \
  scan_type==SCA include_annot==TRUE size==500 -o app_findings.json
```

## Install

```bash
pip install -r requirements.txt   # optional: enables CycloneDX schema validation
```

## Examples

```bash
# CycloneDX VEX (JSON), linked to the SBOM
python veracode_vex.py app_sbom.json -f app_findings.json -o app.vex.cdx.json --report

# CycloneDX VEX as XML
python veracode_vex.py app_sbom.json -f app_findings.json -o app.vex.cdx.xml --output-format xml

# OpenVEX for scanners such as Grype/Trivy
python veracode_vex.py app_sbom.json -f app_findings.json -o app.openvex.json \
  --format openvex --author "Acme Product Security"

# OpenVEX scoped to a container image (components become subcomponents)
python veracode_vex.py app_sbom.json -f app_findings.json -o app.openvex.json \
  --format openvex --author "Acme Product Security" --product "pkg:oci/app@sha256:<digest>"

# Several findings pages; leave free-text mitigation comments out of the VEX
python veracode_vex.py app_sbom.json -f page0.json -f page1.json -o app.vex.json --no-comments

# Publish only what you ship: trim first, then generate VEX on the trimmed SBOM
python sbom_trim.py app_sbom.json -o app_sbom.trimmed.json --public-only --exclude 'pkg:maven/com.acme/*'
python veracode_vex.py app_sbom.trimmed.json -f app_findings.json -o app.vex.json
```

## How Veracode outcomes map to VEX

| Veracode finding | CycloneDX `analysis` | OpenVEX |
|---|---|---|
| Approved: False positive | `false_positive` | `not_affected` + impact statement |
| Approved: Mitigate by design | `not_affected` / `protected_by_mitigating_control` | `not_affected` / `inline_mitigations_already_exist` |
| Approved: Network environment | `not_affected` / `protected_at_perimeter` | `not_affected` / `vulnerable_code_cannot_be_controlled_by_adversary` |
| Approved: OS environment | `not_affected` / `protected_at_runtime` | `not_affected` / `inline_mitigations_already_exist` |
| Approved: Accept risk | `exploitable` + `will_not_fix` | `affected` + action statement |
| Approved: Reported to library maintainer | `exploitable` + `can_not_fix` | `affected` + action statement |
| Approved, reason not in export | `in_triage` | `under_investigation` |
| Mitigation proposed, not approved | `in_triage` | `under_investigation` |
| Open, or mitigation rejected | `exploitable` + `update` | `affected` + action statement |
| Closed (no longer detected) | `resolved` | `fixed` |
| In the SBOM, no finding supplied | `in_triage` | `under_investigation` |

- The `analysis.detail` / impact statement holds the Veracode outcome plus the mitigation comments (Technique, Specifics, Remaining Risk, Verification). `--no-comments` keeps only the outcome. Usernames are never exported.
- `firstIssued` / `lastUpdated` (CycloneDX 1.5+) come from the finding's first-found date and the latest annotation.
- Properties on each CycloneDX vulnerability: `veracode:mitigation`, `veracode:resolution_status`, `veracode:epss_score`, `veracode:epss_percentile`, `veracode:epss_score_date`, `veracode:exploit_observed`, `veracode:exploit_source`, `veracode:violates_policy`.

## Matching findings to SBOM components

1. Upload & Scan: finding `component_path` equals the SBOM `File Path` property.
2. Agent scans: `.../pom.xml/group:artifact` (or `.../name`) plus version.
3. Fallback: `component_filename` (`<name>-<version>.<ext>`).

`--report` lists findings that matched no SBOM component (e.g. removed by trimming) or whose CVE is not on that component in the SBOM, and any conflicting findings.

## Options

| Option | Effect |
|---|---|
| `-f, --findings FILE` | Findings API export; repeat per page |
| `-o, --output PATH` | Output file (required; never an input) |
| `--format cyclonedx\|openvex` | VEX format (default `cyclonedx`) |
| `--output-format json\|xml` | CycloneDX serialization (default `json`) |
| `--author NAME` | OpenVEX author (the organization issuing the statements) |
| `--product ID` | OpenVEX: nest components under this product purl/IRI |
| `--no-comments` | Omit mitigation comments |
| `--report` | Print counts per state, unmatched and conflicting findings |
| `--no-validate` | Skip CycloneDX schema validation |
| `--indent N` | Output indent (default 2; 0 = compact) |

Exit codes: `0` written, `2` bad input or option, `3` output failed validation (nothing written).

## Limitations

- CycloneDX VEX needs the SBOM `serialNumber` (BOM-Link). OpenVEX works without it when components have purls.
- Veracode SCA findings do not carry fixed versions, so `affected` action statements say to update to a non-affected version.
- Statements reflect the findings export at the time it was taken; re-run after new scans or mitigation decisions.
