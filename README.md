# Veracode VEX Generator

> **Community tool.** Not an official Veracode product and not covered by Veracode Technical Support. Use at your own discretion; issues and PRs welcome.

Turns a Veracode SCA SBOM plus your Veracode SCA findings into a VEX document: one statement per CVE × component saying whether it affects you, and why. Mitigations your team approved in Veracode become machine-readable `not_affected` / `false_positive` statements that scanners, customers and auditors can consume.

## Why use it

- **Your triage, exported.** Approved Veracode mitigations (false positive, by design, network/OS environment, accepted risk, reported to library maintainer) map to the matching VEX states and justifications. The mitigation comments become the explanation.
- **Conservative by design.** Only *approved* mitigations count as not affected. Proposals stay under investigation. If two findings for one component disagree (agent vs. upload scan), the worse outcome wins and the report flags it.
- **Veracode risk data included.** EPSS score and percentile, exploit observed (CISA KEV), CVSS ratings, CWEs and policy status from Veracode are carried into the VEX.
- **Linked to your SBOM.** CycloneDX VEX points at SBOM components by BOM-Link (`urn:cdx:<serial>/<version>#<bom-ref>`). Run it on a trimmed SBOM ([Veracode SBOM Trim](https://github.com/ancient-cthulhu/Veracode-SBOM-Trim)) and statements for removed components drop out.
- **Valid output, every time.** CycloneDX output is schema-checked (JSON schema / XSD); OpenVEX output is checked for required fields, enums, one status per CVE × product and the CISA minimums (statement version, first issued and last updated, document last updated, justification or impact statement for `not_affected`, action statement for `affected`). On failure nothing is written.
- **Drop-in for CI.** One file, Python 3.9+, standard library only, no network calls.

## Input and output

- SBOM: CycloneDX 1.4–1.6, JSON or XML, from the Veracode SBOM REST API (`type=application` / `type=agent`), with its `vulnerabilities` section. SPDX is rejected.
- Findings: Findings REST API export with `scan_type=SCA&include_annot=TRUE` (SCA must be the only scan type). Pass every page (`-f` is repeatable); a finding repeated across pages (same `context_guid` and `issue_id`) is kept once, using the copy with the newest annotation or `last_seen_date`, with a warning when the copies differ. Without findings every statement is `in_triage` / `under_investigation`.
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
| Approved: Mitigate by design | `not_affected` / `protected_by_mitigating_control` | `not_affected` + impact statement |
| Approved: Network environment | `not_affected` / `protected_at_perimeter` | `not_affected` + impact statement |
| Approved: OS environment | `not_affected` / `protected_at_runtime` | `not_affected` + impact statement |
| Approved: Accept risk | `exploitable` + `will_not_fix` | `affected` + action statement |
| Approved: Reported to library maintainer | `exploitable` + `can_not_fix` | `affected` + action statement |
| Approved: Mitigated by environment (`BYENV`) | `not_affected` / `protected_by_mitigating_control` | `not_affected` + impact statement |
| Approved: Defer | `exploitable` | `affected` + action statement |
| Approved, reason not in export or not standing | `in_triage` | `under_investigation` |
| Mitigation proposed, not approved | `in_triage` | `under_investigation` |
| Open, or mitigation rejected | `exploitable` + `update` | `affected` + action statement |
| Closed in Veracode, but the SBOM still lists the CVE on that component | `in_triage` | `under_investigation` |
| In the SBOM, no finding supplied | `in_triage` | `under_investigation` |

- Several findings on one CVE × component (e.g. upload and agent scans) merge by outcome, worst first: open, deferred, reported to library, accepted risk, closed-but-listed / proposed / not analyzed, network/OS/generic environment, by design, false positive. Ties are broken on content, so input order never changes the result.
- A closed finding is never reported as `resolved` / `fixed`: every statement comes from the SBOM's own vulnerability list, so a closed finding there means the SBOM and the findings come from different scans (re-export both).
- The reason is read from the annotation history in time order: a reason action (`FP`, `APPDESIGN`/`BYDESIGN`, `NETENV`, `OSENV`, `BYENV`, `LIBRARY`, `ACCEPTRISK`, `DEFER`) is a proposal; `APPROVE`/`APPROVED` approves the pending proposal; `REJECT`/`REJECTED` drops it (a later approval without a new proposal does not bring it back); `REOPENED` withdraws the approval. A mitigation counts only when the finding's `resolution_status` is `APPROVED` and an approval still stands; when the two disagree the result is `in_triage`. Other actions (`COMMENT`, `REMEDIATED`, `NOACTIONTAKEN`, `CONFORMS`, `DEVIATES`, `CUSTOMCLEANSER*`) are comments only. With no history at all, a `POTENTIAL_FALSE_POSITIVE` resolution on an approved finding is read as an approved false positive.
- `BYENV` (environment, no detail) maps to the weakest CycloneDX justification, `protected_by_mitigating_control`, because it does not say whether the control is at the perimeter or at runtime.
- The `analysis.detail` / impact statement holds the Veracode outcome plus the mitigation comments (Technique, Specifics, Remaining Risk, Verification). For an approved mitigation only the approved proposal and its approval comment are used; open, rejected and proposed findings keep the whole history (including the rejection comment). `--no-comments` keeps only the outcome. Usernames are never exported.
- `firstIssued` / `lastUpdated` (CycloneDX 1.5+) are the first mitigation proposal and the newest annotation; without annotations `firstIssued` is the finding's first-found date and `lastUpdated` is left out.
- Properties on each CycloneDX vulnerability: `veracode:mitigation` (approved reason only), `veracode:proposed_mitigation` (pending proposal), `veracode:resolution_status`, `veracode:epss_score`, `veracode:epss_percentile`, `veracode:epss_score_date`, `veracode:exploit_observed`, `veracode:exploit_source`, `veracode:violates_policy`. `veracode:exploit_observed` is set only when Veracode returns a true/false value and its exploit service status is `available`; otherwise it is left out (unknown).
- OpenVEX gives no justification label for false positive, by design or environment mitigations; the impact statement names the approved Veracode mitigation instead. The labels mean more than Veracode records: `inline_mitigations_already_exist` is a built-in protection that cannot be disabled and fully prevents exploitation, and `vulnerable_code_cannot_be_controlled_by_adversary` is a property of the code, not of a network or OS control. Scanners that suppress only on a label will keep reporting these.
- OpenVEX has one status per CVE × product `@id`: SBOM components that share a purl are merged first (worst outcome wins, as above), and the check rejects a CVE × product listed in two statements.
- OpenVEX CISA fields: each statement has `version` 1, `timestamp` (first issued: the first mitigation proposal, else the first-found date, else the run time) and `last_updated` (newest annotation); the document `last_updated` is the newest statement update. A document with no statements fails the check (exit 3).

## Matching findings to SBOM components

Components are the SBOM `components` plus `metadata.component`, nested ones included.

1. Upload & Scan: every finding `component_path` that equals an SBOM `File Path` property (`\` read as `/`; exact case first, a case-insensitive match only when one path fits). The component version must equal the finding version.
2. Agent scans: `.../pom.xml/group:artifact` plus version, or a package path tail such as `.../node_modules/@scope/name` compared with `group/name` or the purl, plus version.
3. Fallback: `component_filename` (`<name>-<version>.<ext>`), used only when that name and version belong to one package (one group); otherwise the finding is reported as ambiguous and not applied.

Rules 2 and 3 apply only when rule 1 finds nothing. When the SBOM repeats a vulnerability id, its records are merged: the NVD source when present, ratings and CWEs combined, the first description and dates.

`--report` lists findings that matched no SBOM component (e.g. removed by trimming), whose CVE is not on that component in the SBOM, without a CVE id, ambiguous by file name, or whose version differs from the component at that path, and any conflicting findings. For an SBOM produced by sbom_trim (its tool entry or redacted components), unmatched findings are counted, not named. Warnings cover vulnerabilities without `affects` and upload findings against an SBOM without `File Path` properties (`sbom_trim --strip-paths`), which can then only match by file name: generate the VEX from the untrimmed SBOM, or trim without `--strip-paths`.

## Options

| Option | Effect |
|---|---|
| `-f, --findings FILE` | Findings API export; repeat per page |
| `-o, --output PATH` | Output file (required; never an input) |
| `--format cyclonedx\|openvex` | VEX format (default `cyclonedx`) |
| `--output-format json\|xml` | CycloneDX serialization (default `json`) |
| `--author NAME` | OpenVEX author, the organization issuing the statements (default `Unknown`, which prints a warning) |
| `--product ID` | OpenVEX: nest components under this product purl/IRI |
| `--no-comments` | Omit mitigation comments; properties keep only enum, number, date and short-token values |
| `--report` | Print counts per state, unmatched and conflicting findings, and warnings |
| `--no-validate` | Skip CycloneDX schema validation |
| `--indent N` | Output indent (default 2; 0 = compact) |
| `--version` | Print the tool version and exit |

Exit codes: `0` output written; `2` bad input or option (unreadable or malformed SBOM/findings, wrong field types, NaN/Infinity, nesting too deep, DOCTYPE in XML, bad command line), nothing written; `3` output failed validation, nothing written.

CycloneDX JSON validation checks `uniqueItems` with a hash set (linear time; the stock validator is quadratic: over a minute for 10k statements) and falls back to the library validator if its internals change.

## Limitations

- CycloneDX VEX needs the SBOM `serialNumber` (BOM-Link). OpenVEX works without it when components have purls.
- Veracode SCA findings do not carry fixed versions, so `affected` action statements say to update to a non-affected version.
- Statements reflect the findings export at the time it was taken; re-run after new scans or mitigation decisions.
- The Findings API spec says `include_annot` is not valid for SCA, and SCA exports seen so far carry no annotations. Approved SCA findings without annotations are reported as `in_triage` and the tool prints a warning with their count. Reading mitigation reasons from the Reporting API v2 (which has SCA mitigation fields) is planned.
