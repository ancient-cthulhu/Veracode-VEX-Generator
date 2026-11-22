#!/usr/bin/env python3
"""Generate VEX documents from a Veracode SCA CycloneDX SBOM and Veracode SCA findings.

Inputs: CycloneDX 1.4-1.6 SBOM (JSON or XML) with a ``vulnerabilities`` section, and
optionally one or more Findings API exports (``scan_type=SCA&include_annot=TRUE``).
Outputs: standalone CycloneDX VEX (JSON or XML, linked to the SBOM by BOM-Link) or
OpenVEX 0.2.0 JSON. One statement per CVE x component; mitigations come from the
findings' approved annotations.

Core is stdlib only; CycloneDX output is schema-validated when
``cyclonedx-python-lib[json-validation,xml-validation]`` is installed. No network calls.
"""

from __future__ import annotations

import argparse
import json
import math
import os
import re
import sys
import tempfile
import uuid
import xml.etree.ElementTree as ET
from collections import Counter, OrderedDict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Iterator, List, Optional, Sequence, Set, Tuple
from urllib.parse import quote, unquote

__version__ = "1.0.0"
TOOL_NAME = "veracode_vex"
SUPPORTED_SPECS = ("1.4", "1.5", "1.6")
CDX_NS = "http://cyclonedx.org/schema/bom/"
OPENVEX_CONTEXT = "https://openvex.dev/ns/v0.2.0"
VC_FILE_PATH = "File Path"

EXIT_OK = 0
EXIT_INPUT = 2
EXIT_INVALID = 3

# CycloneDX analysis enums (1.4-1.6).
CDX_STATES = ("resolved", "resolved_with_pedigree", "exploitable", "in_triage",
              "false_positive", "not_affected")
CDX_JUSTIFICATIONS = ("code_not_present", "code_not_reachable", "requires_configuration",
                      "requires_dependency", "requires_environment", "protected_by_compiler",
                      "protected_at_runtime", "protected_at_perimeter",
                      "protected_by_mitigating_control")
CDX_RESPONSES = ("can_not_fix", "will_not_fix", "update", "rollback", "workaround_available")
# OpenVEX 0.2.0 enums.
OV_STATUSES = ("not_affected", "affected", "fixed", "under_investigation")
OV_JUSTIFICATIONS = ("component_not_present", "vulnerable_code_not_present",
                     "vulnerable_code_not_in_execute_path",
                     "vulnerable_code_cannot_be_controlled_by_adversary",
                     "inline_mitigations_already_exist")

BOM_LINK_RE = re.compile(
    r"^urn:cdx:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}/[1-9][0-9]*(#.+)?$")
SERIAL_RE = re.compile(
    r"^urn:uuid:([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$", re.I)
# Chars XML 1.0 cannot carry (and lone surrogates UTF-8 cannot); stripped from output strings.
XML_BAD_CHARS = re.compile("[\x00-\x08\x0b\x0c\x0e-\x1f\ud800-\udfff\ufffe\uffff]")
FRAGMENT_SAFE = ":@!$&'()*+,;=/?-._~"
MAX_NESTING = 64  # nested XML components; real SBOMs use < 5
# Allowed before the root element: BOM/whitespace, XML declaration and PIs, comments.
XML_PROLOG_SKIP = re.compile(r"(?:[\s\ufeff]|<\?.*?\?>|<!--.*?-->)*", re.S)
# --no-comments: property values must be enums/tokens/dates, never free text.
RESOLUTION_STATUSES = ("APPROVED", "PROPOSED", "REJECTED", "NONE")
TOKEN_RE = re.compile(r"[A-Za-z0-9_.-]{1,32}(?:, ?[A-Za-z0-9_.-]{1,32}){0,7}", re.ASCII)  # "KEV,..."
SBOM_TRIM_NAMES = ("sbom_trim", "sbom-trim")
REDACTED_PROPERTY = "external:redacted"
REDACTED_REF_RE = re.compile(r"^redacted-[0-9]+$", re.ASCII)


class VexError(Exception):
    """Unusable input or option; message is shown to the user."""


# --------------------------------------------------------------------------- #
# Mitigation model
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class Rule:
    """How one Veracode outcome maps to CycloneDX and OpenVEX."""

    label: str
    cdx_state: str
    cdx_justification: Optional[str]
    cdx_responses: Tuple[str, ...]
    ov_status: str
    ov_justification: Optional[str]


# Veracode mitigation reasons (Findings API 2.1 Annotation.action). Only approved ones count.
MITIGATIONS: Dict[str, Rule] = {
    "FP": Rule("False positive", "false_positive", None, (), "not_affected", None),
    # OpenVEX: no justification label for design/environment controls. The spec labels claim
    # more (inline_mitigations_already_exist: built in, cannot be disabled, complete;
    # vulnerable_code_cannot_be_controlled_by_adversary: a code property, not an external
    # control), so the impact_statement names the control instead.
    "APPDESIGN": Rule("Mitigated by design", "not_affected", "protected_by_mitigating_control",
                      (), "not_affected", None),
    "NETENV": Rule("Mitigated by network environment", "not_affected", "protected_at_perimeter",
                   (), "not_affected", None),
    "OSENV": Rule("Mitigated by OS environment", "not_affected", "protected_at_runtime",
                  (), "not_affected", None),
    "ACCEPTRISK": Rule("Risk accepted", "exploitable", None, ("will_not_fix",), "affected", None),
    "LIBRARY": Rule("Reported to library maintainer", "exploitable", None, ("can_not_fix",),
                    "affected", None),
    # Generic environment control: the weakest CDX claim (reduces likelihood/impact).
    "BYENV": Rule("Mitigated by environment", "not_affected", "protected_by_mitigating_control",
                  (), "not_affected", None),
    "DEFER": Rule("Remediation deferred", "exploitable", None, (), "affected", None),
}
OPEN = Rule("Open", "exploitable", None, ("update",), "affected", None)
PROPOSED = Rule("Mitigation proposed", "in_triage", None, (), "under_investigation", None)
CLOSED = Rule("Fixed", "resolved", None, (), "fixed", None)
NO_FINDING = Rule("Not analyzed", "in_triage", None, (), "under_investigation", None)
# CLOSED finding on a pair the SBOM still lists: inputs disagree, so never claim fixed.
STALE_CLOSED = Rule("Closed in Veracode, still in SBOM", "in_triage", None, (),
                    "under_investigation", None)
STALE_NOTE = ("Veracode closed this finding but the SBOM still lists it; re-export both from "
              "the same scan.")

# Annotation action spellings seen in the API and UI, normalised (upper, no separators).
ACTION_ALIASES = {
    "FP": "FP", "FALSEPOSITIVE": "FP", "POTENTIALFALSEPOSITIVE": "FP",
    "REPORTEDFALSEPOSITIVE": "FP",
    "APPDESIGN": "APPDESIGN", "MITIGATEBYDESIGN": "APPDESIGN", "MITIGATEDBYDESIGN": "APPDESIGN",
    "BYDESIGN": "APPDESIGN",
    "NETENV": "NETENV", "MITIGATEBYNETWORKENVIRONMENT": "NETENV",
    "MITIGATEDBYNETWORKENVIRONMENT": "NETENV", "NETWORKENVIRONMENT": "NETENV",
    "OSENV": "OSENV", "MITIGATEBYOSENVIRONMENT": "OSENV", "MITIGATEDBYOSENVIRONMENT": "OSENV",
    "OSENVIRONMENT": "OSENV",
    "LIBRARY": "LIBRARY", "REPORTEDTOLIBRARYMAINTAINER": "LIBRARY",
    "ACCEPTRISK": "ACCEPTRISK", "ACCEPTTHERISK": "ACCEPTRISK", "RISKACCEPTED": "ACCEPTRISK",
    "ACCEPTED": "ACCEPTED", "APPROVED": "ACCEPTED", "APPROVE": "ACCEPTED",
    "APPROVEMITIGATION": "ACCEPTED",
    "REJECTED": "REJECTED", "REJECT": "REJECTED", "REJECTMITIGATION": "REJECTED",
    "REOPENED": "REOPENED", "REOPEN": "REOPENED",
    "BYENV": "BYENV", "DEFER": "DEFER",
    "COMMENT": "COMMENT",
}
# Other actions (REMEDIATED, NOACTIONTAKEN, CONFORMS, DEVIATES, CUSTOMCLEANSER*) are comments.

# Merge order for several findings on one CVE x component: highest (worst) wins.
RULE_RANK = {r.label: n for n, r in enumerate(reversed((
    OPEN, MITIGATIONS["DEFER"], MITIGATIONS["LIBRARY"], MITIGATIONS["ACCEPTRISK"],
    STALE_CLOSED, PROPOSED, NO_FINDING,
    MITIGATIONS["NETENV"], MITIGATIONS["OSENV"], MITIGATIONS["BYENV"],
    MITIGATIONS["APPDESIGN"], MITIGATIONS["FP"], CLOSED)))}


@dataclass
class Verdict:
    """Outcome for one CVE x component."""

    rule: Rule
    notes: List[str] = field(default_factory=list)
    comments: List[str] = field(default_factory=list)
    first_issued: Optional[str] = None
    last_updated: Optional[str] = None
    mitigation: Optional[str] = None  # approved Veracode reason, e.g. APPDESIGN
    proposed: Optional[str] = None  # pending (unapproved) reason
    resolution_status: Optional[str] = None
    finding_count: int = 0


# --------------------------------------------------------------------------- #
# Reading inputs
# --------------------------------------------------------------------------- #


def _read_text(path: str) -> str:
    try:
        with open(path, "rb") as fh:
            raw = fh.read()
    except OSError as exc:
        raise VexError(f"cannot read {path}: {exc}") from exc
    # PowerShell `>` writes UTF-16; honour BOMs, default UTF-8.
    if raw.startswith((b"\xff\xfe\x00\x00", b"\x00\x00\xfe\xff")):
        enc = "utf-32"
    elif raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        enc = "utf-16"
    else:
        enc = "utf-8-sig"
    try:
        return raw.decode(enc)
    except UnicodeDecodeError as exc:
        raise VexError(f"cannot read {path}: not {enc.upper()} text ({exc.reason})") from exc


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _kids(el: Any, name: str) -> List[Any]:
    return [c for c in el if _local(c.tag) == name]


def _kid(el: Any, name: str) -> Optional[Any]:
    found = _kids(el, name)
    return found[0] if found else None


def _text(el: Any, name: str) -> Optional[str]:
    child = _kid(el, name)
    return child.text.strip() if child is not None and child.text else None


def _ascii_int(s: Optional[str]) -> Optional[int]:
    """int of plain ASCII digits; str.isdigit() also accepts '²', which int() rejects."""
    s = (s or "").strip()
    return int(s) if s.isascii() and s.isdigit() else None


def _xml_component(el: Any, depth: int = 0) -> Dict[str, Any]:
    if depth > MAX_NESTING:
        raise VexError(f"input XML nests components more than {MAX_NESTING} levels deep")
    comp: Dict[str, Any] = {}
    for attr in ("type", "bom-ref"):
        if el.get(attr):
            comp[attr] = el.get(attr)
    for key in ("group", "name", "version", "purl"):
        val = _text(el, key)
        if val is not None:
            comp[key] = val
    props = _kid(el, "properties")
    if props is not None:
        comp["properties"] = [{"name": p.get("name"), "value": (p.text or "").strip()}
                              for p in _kids(props, "property")]
    nested = _kid(el, "components")
    if nested is not None:
        comp["components"] = [_xml_component(c, depth + 1) for c in _kids(nested, "component")]
    return comp


def _xml_vuln(el: Any) -> Dict[str, Any]:
    vuln: Dict[str, Any] = {}
    if el.get("bom-ref"):
        vuln["bom-ref"] = el.get("bom-ref")
    vuln["id"] = _text(el, "id")
    src = _kid(el, "source")
    if src is not None:
        vuln["source"] = {k: v for k, v in (("name", _text(src, "name")),
                                            ("url", _text(src, "url"))) if v}
    ratings = _kid(el, "ratings")
    if ratings is not None:
        out = []
        for r in _kids(ratings, "rating"):
            rating: Dict[str, Any] = {}
            score = _text(r, "score")
            if score is not None:
                try:
                    num = float(score)
                except ValueError:
                    pass
                else:
                    if math.isfinite(num):  # NaN/INF are not JSON numbers
                        rating["score"] = num
            for key in ("severity", "method", "vector"):
                val = _text(r, key)
                if val:
                    rating[key] = val
            out.append(rating)
        vuln["ratings"] = out
    cwes = _kid(el, "cwes")
    if cwes is not None:
        vuln["cwes"] = [n for n in (_ascii_int(c.text) for c in _kids(cwes, "cwe")) if n is not None]
    for key in ("description", "created", "published", "updated"):
        val = _text(el, key)
        if val is not None:
            vuln[key] = val
    affects = _kid(el, "affects")
    if affects is not None:
        vuln["affects"] = [{"ref": _text(t, "ref")} for t in _kids(affects, "target")]
    return vuln


def xml_to_sbom(text: str) -> Dict[str, Any]:
    """Read the parts of a CycloneDX XML SBOM this tool needs into the JSON model."""
    # No XXE / billion laughs: a DOCTYPE (and so any ENTITY) can only sit in the prolog,
    # so refuse any "<!" markup there (any case); expat rejects one anywhere else.
    rest = text[XML_PROLOG_SKIP.match(text).end():]  # type: ignore[union-attr]
    if rest.startswith("<!"):
        raise VexError("input XML has a DOCTYPE/ENTITY declaration; refusing to parse")
    try:
        root = ET.fromstring(text)
    except ET.ParseError as exc:
        raise VexError(f"input is not valid XML: {exc}") from exc
    ns = root.tag[1:].split("}")[0] if root.tag.startswith("{") else ""
    if _local(root.tag) != "bom" or not ns.startswith(CDX_NS):
        raise VexError("input XML is not a CycloneDX BOM")
    bom: Dict[str, Any] = {"bomFormat": "CycloneDX", "specVersion": ns[len(CDX_NS):]}
    if root.get("serialNumber"):
        bom["serialNumber"] = root.get("serialNumber")
    ver = root.get("version", "1")
    num = _ascii_int(ver)
    bom["version"] = ver if num is None else num
    meta = _kid(root, "metadata")
    if meta is not None:
        bom["metadata"] = {}
        comp = _kid(meta, "component")
        if comp is not None:
            bom["metadata"]["component"] = _xml_component(comp)
    comps = _kid(root, "components")
    bom["components"] = [_xml_component(c) for c in _kids(comps, "component")] if comps is not None else []
    vulns = _kid(root, "vulnerabilities")
    if vulns is not None:
        bom["vulnerabilities"] = [_xml_vuln(v) for v in _kids(vulns, "vulnerability")]
    return bom


def read_sbom(path: str) -> Dict[str, Any]:
    """Load and check a CycloneDX SBOM (JSON or XML)."""
    text = _read_text(path)
    stripped = text.lstrip()
    if stripped.startswith("SPDXVersion:"):
        raise VexError("input is an SPDX document; only CycloneDX is supported")
    if stripped.startswith("<"):
        try:
            bom = xml_to_sbom(text)
        except RecursionError as exc:
            raise VexError("SBOM XML is nested too deeply") from exc
    else:
        bom = _load_json(text, "SBOM")
    if not isinstance(bom, dict):
        raise VexError("SBOM is not a JSON object")
    if "spdxVersion" in bom or "SPDXID" in bom:
        raise VexError("input is an SPDX SBOM; export CycloneDX from Veracode instead")
    if bom.get("bomFormat") != "CycloneDX":
        raise VexError("input is not a CycloneDX SBOM (bomFormat != 'CycloneDX')")
    if bom.get("specVersion") not in SUPPORTED_SPECS:
        raise VexError(f"CycloneDX specVersion {bom.get('specVersion')!r} is not supported; "
                       f"supported: {', '.join(SUPPORTED_SPECS)}")
    if not isinstance(bom.get("components", []), list):
        raise VexError("'components' must be an array")
    vulns = bom.get("vulnerabilities")
    if not isinstance(vulns, list) or not vulns:
        # Common cause: SBOM API called with vulnerability=false.
        raise VexError("SBOM has no vulnerabilities; export it with vulnerabilities included "
                       "(SBOM API: omit vulnerability=false)")
    for i, v in enumerate(vulns):
        if not isinstance(v, dict) or not isinstance(v.get("id"), str) or not v["id"]:
            raise VexError(f"vulnerabilities[{i}] has no id")
        if not isinstance(v.get("affects", []), list):
            raise VexError(f"vulnerabilities[{i}].affects must be an array")
    # Refs go into BOM-Links and the output file: no lone surrogates (UTF-8 cannot encode them).
    for comp in iter_components(all_components(bom)):
        _check_text(comp.get("bom-ref"), "component bom-ref")
    for i, v in enumerate(vulns):
        _check_text(v["id"], f"vulnerabilities[{i}].id")
        for a in v.get("affects") or []:
            if isinstance(a, dict):
                _check_text(a.get("ref"), f"vulnerabilities[{i}].affects ref")
    return bom


def _check_text(val: Any, where: str) -> None:
    if isinstance(val, str):
        try:
            val.encode("utf-8")
        except UnicodeEncodeError as exc:
            raise VexError(f"{where} {val!r} is not valid Unicode (lone surrogate)") from exc


def _reject_constant(token: str) -> Any:
    """json.loads hook: NaN/Infinity are not RFC 8259 JSON and break strict consumers."""
    raise ValueError(f"non-standard number {token} (NaN/Infinity are not allowed in JSON)")


def _load_json(text: str, what: str) -> Any:
    try:
        return json.loads(text, parse_constant=_reject_constant)
    except RecursionError as exc:
        raise VexError(f"{what} JSON is nested too deeply") from exc
    except ValueError as exc:  # JSONDecodeError, >4300-digit ints, NaN/Infinity
        raise VexError(f"{what} is not valid JSON: {exc}") from exc


# Finding fields read as text: wrong JSON types must stop with a message, not a traceback.
FINDING_STR_FIELDS = (
    ("finding_status", ("status", "resolution", "resolution_status", "first_found_date",
                        "last_seen_date")),
    ("finding_details", ("version", "component_filename")),
)


def _check_finding_types(path: str, i: int, f: Dict[str, Any]) -> None:
    def bad(name: str, kind: str) -> VexError:
        return VexError(f"{path}: findings[{i}].{name} must be {kind}")

    d = f.get("finding_details")
    dd = d if isinstance(d, dict) else {}
    # The API spec types finding_details.metadata as a string (example: object); both are read.
    for name, val, typ in (("finding_details", d, dict),
                           ("finding_status", f.get("finding_status"), dict),
                           ("finding_details.cve", dd.get("cve"), dict),
                           ("finding_details.metadata", dd.get("metadata"), (dict, str)),
                           ("annotations", f.get("annotations"), list),
                           ("finding_details.component_path", dd.get("component_path"), list)):
        if val is not None and not isinstance(val, typ):
            raise bad(name, "an array" if typ is list else "an object")
    for parent, keys in FINDING_STR_FIELDS:
        obj = f.get(parent)
        for k in keys:
            if isinstance(obj, dict) and obj.get(k) is not None and not isinstance(obj[k], str):
                raise bad(f"{parent}.{k}", "a string")
    cve = dd.get("cve") or {}
    if cve.get("name") is not None and not isinstance(cve["name"], str):
        raise bad("finding_details.cve.name", "a string")
    if cve.get("exploitability") is not None and not isinstance(cve["exploitability"], dict):
        raise bad("finding_details.cve.exploitability", "an object")
    meta = dd.get("metadata")
    if isinstance(meta, dict) and meta.get("sca_scan_mode") is not None \
            and not isinstance(meta["sca_scan_mode"], str):
        raise bad("finding_details.metadata.sca_scan_mode", "a string")
    for j, p in enumerate(dd.get("component_path") or []):
        if not isinstance(p, dict) or not isinstance(p.get("path", ""), str):
            raise bad(f"finding_details.component_path[{j}]", "an object with a string path")
    for j, a in enumerate(f.get("annotations") or []):
        if not isinstance(a, dict):
            raise bad(f"annotations[{j}]", "an object")
        for k in ("action", "created", "comment", "technique", "specifics", "remaining_risk",
                  "verification"):
            if a.get(k) is not None and not isinstance(a[k], str):
                raise bad(f"annotations[{j}].{k}", "a string")


def _page_warning(path: str, page: Any) -> None:
    """Warn when an export is one page of several; non-integer page fields are ignored."""
    if not isinstance(page, dict):
        return
    total, number = page.get("total_pages"), page.get("number", 0)
    if not isinstance(total, int) or not isinstance(number, int) \
            or isinstance(total, bool) or isinstance(number, bool):
        return
    if total > 1:
        print(f"warning: {path} is page {number + 1} of {total}; pass every page",
              file=sys.stderr)


def read_findings(paths: Sequence[str]) -> List[Dict[str, Any]]:
    """Load SCA findings from Findings API exports; duplicates across pages are dropped."""
    out: List[Dict[str, Any]] = []
    seen: Set[str] = set()
    by_issue: Dict[Tuple[str, str], int] = {}
    differ = 0
    for path in paths:
        data = _load_json(_read_text(path), path)
        # Accept the API response, {"findings": [...]}, or a bare list.
        if isinstance(data, dict):
            emb = data.get("_embedded")
            if "_embedded" in data and not isinstance(emb, dict):
                raise VexError(f"{path}: '_embedded' must be an object")
            items = emb.get("findings") if isinstance(emb, dict) else data.get("findings")
            _page_warning(path, data.get("page"))
        else:
            items = data
        if not isinstance(items, list):
            raise VexError(f"{path}: no findings list (expected a Findings API response)")
        for i, f in enumerate(items):
            if not isinstance(f, dict):
                raise VexError(f"{path}: findings[{i}] is not an object")
            if str(f.get("scan_type", "SCA")).upper() != "SCA":
                continue  # SAST/DAST have no CVE x component
            _check_finding_types(path, i, f)
            key = json.dumps(f, sort_keys=True)
            if key in seen:
                continue
            seen.add(key)
            # Same finding on two pages (data changed between page requests): keep the newest.
            iid = f.get("issue_id")
            if isinstance(iid, (int, str)) and not isinstance(iid, bool) and str(iid):
                ik = (str(f.get("context_guid")), str(iid))
                if ik in by_issue:
                    differ += 1
                    j = by_issue[ik]
                    if _freshness(f) > _freshness(out[j]):  # ties keep the first copy
                        out[j] = f
                    continue
                by_issue[ik] = len(out)
            out.append(f)
    if differ:
        print(f"warning: {differ} finding(s) repeat a context_guid + issue_id with different "
              "content (copies differ); kept the copy with the newest annotation or "
              "last_seen_date", file=sys.stderr)
    return out


def _freshness(f: Dict[str, Any]) -> Tuple[datetime, datetime]:
    """(newest annotation, last_seen_date) for picking the newest copy of a finding."""
    anns = f.get("annotations")
    dts = [_parse_dt(a.get("created")) for a in anns if isinstance(a, dict)] \
        if isinstance(anns, list) else []
    st = f.get("finding_status")
    seen = _parse_dt(st.get("last_seen_date")) if isinstance(st, dict) else None
    return max([d for d in dts if d] or [DT_MIN]), seen or DT_MIN


# --------------------------------------------------------------------------- #
# SBOM index and finding matching
# --------------------------------------------------------------------------- #


def iter_components(comps: Any) -> Iterator[Dict[str, Any]]:
    """Depth-first over components, including nested ones."""
    stack = list(reversed(comps)) if isinstance(comps, list) else []
    while stack:
        comp = stack.pop()
        if isinstance(comp, dict):
            yield comp
            nested = comp.get("components")
            if isinstance(nested, list):
                stack.extend(reversed(nested))


def _prop(comp: Dict[str, Any], name: str) -> List[str]:
    props = comp.get("properties")
    if not isinstance(props, list):
        return []
    return [p["value"] for p in props if isinstance(p, dict) and p.get("name") == name
            and isinstance(p.get("value"), str)]


def _low(val: Any) -> str:
    return val.lower() if isinstance(val, str) else ""


def all_components(bom: Dict[str, Any]) -> List[Any]:
    """metadata.component (sbom_trim keeps it as an affects target) plus components."""
    meta = bom.get("metadata")
    root = meta.get("component") if isinstance(meta, dict) else None
    comps = bom.get("components")
    return ([root] if isinstance(root, dict) else []) + (comps if isinstance(comps, list) else [])


def _norm_path(path: str) -> str:
    return path.replace("\\", "/")


def _purl_key(purl: Any) -> str:
    """'namespace/name' of a purl, lower case: pkg:npm/%40babel/types@7 -> '@babel/types'."""
    if not isinstance(purl, str) or not purl.startswith("pkg:"):
        return ""
    body = re.split(r"[?#]", purl[4:], maxsplit=1)[0]
    head, _, last = body.rpartition("/")
    if not head:
        return ""  # type only, no name
    name = last.split("@", 1)[0]
    ns = head.split("/", 1)[1] if "/" in head else ""
    return unquote(f"{ns}/{name}" if ns else name).lower()


def _comp_keys(comp: Dict[str, Any]) -> Set[str]:
    """Names a package path tail can carry: 'group/name' (npm '@scope/name'), else 'name'; purl."""
    name, group = _low(comp.get("name")), _low(comp.get("group"))
    keys = {f"{group}/{name}" if group else name, _purl_key(comp.get("purl"))}
    return {k for k in keys if k}


class SbomIndex:
    """Lookups from Veracode finding fields to SBOM bom-refs."""

    def __init__(self, bom: Dict[str, Any]) -> None:
        self.comps: Dict[str, Dict[str, Any]] = {}
        self.by_path: Dict[str, Set[str]] = {}  # exact File Path ('/' separators)
        self.path_case: Dict[str, Set[str]] = {}  # lower-case path -> exact paths
        self.by_gav: Dict[Tuple[str, str, str], Set[str]] = {}
        self.by_key: Dict[Tuple[str, str], Set[str]] = {}  # (package key, version)
        self.by_nv: Dict[Tuple[str, str], Set[str]] = {}
        self.has_paths = False
        for comp in iter_components(all_components(bom)):
            ref = comp.get("bom-ref")
            if not isinstance(ref, str):
                continue
            self.comps[ref] = comp
            for path in _prop(comp, VC_FILE_PATH):
                path = _norm_path(path)
                self.has_paths = True
                self.by_path.setdefault(path, set()).add(ref)
                self.path_case.setdefault(path.lower(), set()).add(path)
            name, ver = _low(comp.get("name")), _low(comp.get("version"))
            self.by_gav.setdefault((_low(comp.get("group")), name, ver), set()).add(ref)
            for key in _comp_keys(comp):
                self.by_key.setdefault((key, ver), set()).add(ref)
            self.by_nv.setdefault((name, ver), set()).add(ref)

    def _path_refs(self, path: str) -> Set[str]:
        """Exact File Path first; a case-folded match only when one SBOM path folds to it."""
        if path in self.by_path:
            return self.by_path[path]
        folded = self.path_case.get(path.lower(), set())
        return self.by_path[next(iter(folded))] if len(folded) == 1 else set()

    def _version_ok(self, ref: str, ver: str) -> bool:
        have = _low(self.comps[ref].get("version"))
        return not (ver and have) or have == ver

    def match(self, finding: Dict[str, Any]) -> Set[str]:
        """bom-refs a finding refers to; empty when nothing matches."""
        return self.resolve(finding)[0]

    def resolve(self, finding: Dict[str, Any]) -> Tuple[Set[str], str]:
        """(bom-refs, problem); problem is 'ambiguous' or 'version' when nothing was applied."""
        raw = finding.get("finding_details")
        d: Dict[str, Any] = raw if isinstance(raw, dict) else {}
        ver = _low(d.get("version"))
        cp = d.get("component_path")
        paths = [_norm_path(p["path"]) for p in (cp if isinstance(cp, list) else [])
                 if isinstance(p, dict) and isinstance(p.get("path"), str)]
        # 1. Upload scans: component_path == SBOM "File Path", over every path, same version.
        hits: Set[str] = set()
        wrong_version = False
        for path in paths:
            refs = self._path_refs(path)
            good = {r for r in refs if self._version_ok(r, ver)}
            wrong_version = wrong_version or len(good) < len(refs)
            hits |= good
        if hits:
            return hits, ""
        # 2. Agent scans: ".../pom.xml/group:artifact", or a package tail such as
        #    ".../node_modules/@scope/name" compared with group/name or the purl, + version.
        for path in paths:
            segs = [s for s in path.rstrip("/").split("/") if s]
            if not segs:
                continue
            if ":" in segs[-1]:
                group, art = segs[-1].split(":", 1)
                hits |= self.by_gav.get((group.lower(), art.split(":")[0].lower(), ver), set())
                continue
            least = 2 if len(segs) > 1 and segs[-2].startswith("@") else 1  # keep npm scopes
            for n in range(min(len(segs), 6), least - 1, -1):  # most specific tail first
                cand = self.by_key.get(("/".join(segs[-n:]).lower(), ver))
                if cand:
                    hits |= cand
                    break
        if hits:
            return hits, ""
        # 3. Filename "<name>-<version>.<ext>": name only, so it must identify one package.
        fname = _low(d.get("component_filename"))
        if ver and fname:
            stem = os.path.splitext(fname)[0]
            if stem.endswith("-" + ver):
                refs = self.by_nv.get((stem[: -len(ver) - 1], ver), set())
                groups = {_low(self.comps[r].get("group")) for r in refs}
                if len(groups) == 1:
                    return set(refs), ""
                if refs:
                    return set(), "ambiguous"
        return set(), "version" if wrong_version else ""


# --------------------------------------------------------------------------- #
# Finding classification
# --------------------------------------------------------------------------- #


def _norm_action(val: Any) -> str:
    key = re.sub(r"[^A-Z]", "", str(val or "").upper())
    return ACTION_ALIASES.get(key, key)


# RFC 3339 / ISO 8601 subset; 3.9 fromisoformat rejects "Z" and 1-2 digit fractions.
DT_RE = re.compile(r"^(\d{4})-(\d{2})-(\d{2})(?:[Tt ](\d{2}):(\d{2})(?::(\d{2})(?:[.,](\d+))?)?)?"
                   r"\s*([Zz]|[+-]\d{2}:?\d{2})?$", re.ASCII)
DT_MIN = datetime(1, 1, 1, tzinfo=timezone.utc)


def _parse_dt(val: Any) -> Optional[datetime]:
    """Aware UTC datetime from a Veracode date string; naive means UTC; None if invalid."""
    m = DT_RE.match(val.strip()) if isinstance(val, str) else None
    if not m:
        return None
    y, mo, d, h, mi, s, frac, tz = m.groups()
    try:
        dt = datetime(int(y), int(mo), int(d), int(h or 0), int(mi or 0), int(s or 0),
                      int((frac or "0")[:6].ljust(6, "0")), tzinfo=timezone.utc)
        if tz and tz not in "Zz":
            off = timedelta(hours=int(tz[1:3]), minutes=int(tz[-2:]))
            dt = dt - off if tz[0] == "+" else dt + off
    except (ValueError, OverflowError):
        return None
    return dt


def _clean(text: Any) -> str:
    """Single comment, normalised newlines, no XML-invalid chars."""
    if not isinstance(text, str):
        return ""
    text = XML_BAD_CHARS.sub("", text.replace("\r\n", "\n").replace("\r", "\n"))
    return "\n".join(line.rstrip() for line in text.strip().split("\n"))


def _annotation_text(ann: Dict[str, Any]) -> str:
    # TSRV may come as fields or inside the comment; usernames are never used.
    parts = [_clean(ann.get("comment"))]
    for key, label in (("technique", "Technique"), ("specifics", "Specifics"),
                       ("remaining_risk", "Remaining Risk"), ("verification", "Verification")):
        val = _clean(ann.get(key))
        if val and val not in parts[0]:
            parts.append(f"{label}: {val}")
    return "\n".join(p for p in parts if p)


@dataclass
class Trail:
    """Mitigation state after replaying an annotation history, oldest first."""

    approved: Optional[Dict[str, Any]] = None  # proposal whose approval still stands
    approval: Optional[Dict[str, Any]] = None  # annotation that approved it
    pending: Optional[Dict[str, Any]] = None  # proposal awaiting review
    first_proposal: Optional[Dict[str, Any]] = None


def sort_annotations(raw: Any) -> List[Dict[str, Any]]:
    """Oldest first by parsed `created`; an undated entry stays right after its predecessor."""
    anns = [a for a in raw if isinstance(a, dict)] if isinstance(raw, list) else []
    keyed = []
    prev = DT_MIN
    for i, ann in enumerate(anns):
        dt = _parse_dt(ann.get("created"))
        prev = dt or prev
        keyed.append((dt or prev, i, ann))
    keyed.sort(key=lambda k: (k[0], k[1]))
    return [k[2] for k in keyed]


def replay(anns: List[Dict[str, Any]]) -> Trail:
    """Proposal -> APPROVE/REJECT -> REOPEN state machine over sorted annotations."""
    t = Trail()
    for ann in anns:
        act = _norm_action(ann.get("action"))
        if act in MITIGATIONS:
            t.pending = ann
            if t.first_proposal is None:
                t.first_proposal = ann
        elif act == "ACCEPTED" and t.pending is not None:
            t.approved, t.approval, t.pending = t.pending, ann, None
        elif act == "REJECTED":
            t.pending = None  # a later bare approval must not resurrect it
        elif act == "REOPENED":
            t.approved = t.approval = t.pending = None
    return t


def classify(finding: Dict[str, Any], comments: bool = True) -> Verdict:
    """Map one Veracode SCA finding to a VEX outcome."""
    st = finding.get("finding_status") or {}
    status = str(st.get("status") or "").upper()
    resolution = str(st.get("resolution") or "").upper()
    rstatus = str(st.get("resolution_status") or "").upper()
    anns = sort_annotations(finding.get("annotations"))
    trail = replay(anns)
    approved = _norm_action(trail.approved.get("action")) if trail.approved else None
    pending = _norm_action(trail.pending.get("action")) if trail.pending else None
    if not anns and "FALSE_POSITIVE" in resolution:
        approved = "FP"  # no history exported: the resolution is the only reason source
    v = Verdict(rule=OPEN, resolution_status=rstatus or None, finding_count=1)
    # Analysis dates: first proposal .. newest annotation; first_found_date only without them.
    dates = [d for d in (_iso(a.get("created")) for a in anns) if d]
    if dates:
        first = _iso(trail.first_proposal.get("created")) if trail.first_proposal else None
        v.first_issued, v.last_updated = first or min(dates), max(dates)
    else:
        v.first_issued = _iso(st.get("first_found_date"))

    # Status and history must agree; otherwise the conservative outcome wins.
    if rstatus == "APPROVED":
        if approved:
            v.rule, v.mitigation = MITIGATIONS[approved], approved
            v.notes.append(f"Approved Veracode mitigation: {v.rule.label}.")
        elif anns:
            v.rule = PROPOSED
            v.notes.append("Veracode status is APPROVED but no approval stands in the "
                           "annotation history (rejected or reopened); treated as in triage.")
        else:
            # Approved, reason unknown: never claim not_affected without the reason.
            v.rule = PROPOSED
            v.notes.append("Veracode mitigation approved; reason not in export "
                           "(re-export with include_annot=TRUE).")
    elif rstatus == "PROPOSED":
        v.rule, v.proposed = PROPOSED, pending
        label = MITIGATIONS[pending].label if pending else "unknown reason"
        v.notes.append(f"Mitigation proposed in Veracode ({label}); pending approval.")
    elif status == "CLOSED":
        v.rule = CLOSED
        v.notes.append("Finding closed in Veracode SCA: no longer detected.")
    else:
        v.rule = OPEN
        v.notes.append("Open in Veracode SCA; no approved mitigation.")
        if rstatus == "REJECTED":
            v.notes.append("Proposed mitigation was rejected.")
    if comments:
        # Approved: only the approved proposal and its approval; else the full history.
        src = [a for a in (trail.approved, trail.approval) if a] if v.mitigation else anns
        for ann in src:
            text = _annotation_text(ann)
            if text and text not in v.comments:
                v.comments.append(text)
    return v


def approved_without_history(findings: List[Dict[str, Any]]) -> int:
    """APPROVED findings with no annotations that end up in triage (reason unknown)."""
    return sum(1 for f in findings
               if str((f.get("finding_status") or {}).get("resolution_status") or "").upper()
               == "APPROVED" and not f.get("annotations") and classify(f, False).rule is PROPOSED)


def merge(verdicts: List[Verdict]) -> Tuple[Verdict, bool]:
    """Combine several findings on one CVE x component; returns (verdict, conflict)."""
    if len(verdicts) == 1:
        return verdicts[0], False
    # Rank on rules, then on content, so input order never changes the result.
    ordered = sorted(verdicts, key=lambda v: (-RULE_RANK.get(v.rule.label, len(RULE_RANK)),
                                              v.mitigation or "", v.proposed or "",
                                              v.resolution_status or "", _detail(v)))
    worst = ordered[0]
    out = Verdict(rule=worst.rule, mitigation=worst.mitigation, proposed=worst.proposed,
                  resolution_status=worst.resolution_status,
                  finding_count=sum(v.finding_count for v in verdicts))
    conflict = len({v.rule.label for v in verdicts}) > 1
    for v in ordered:
        if v.rule is not worst.rule:
            continue  # losing outcomes are only named in the conflict note
        for note in v.notes:
            if note not in out.notes:
                out.notes.append(note)
        for c in v.comments:
            if c not in out.comments:
                out.comments.append(c)
    if conflict:
        others = sorted({v.rule.label for v in verdicts if v.rule is not worst.rule})
        out.notes.append(f"Other Veracode findings for this component: {', '.join(others)}.")
    firsts = [v.first_issued for v in verdicts if v.first_issued]
    lasts = [v.last_updated for v in verdicts if v.last_updated]
    out.first_issued = min(firsts) if firsts else None
    out.last_updated = max(lasts) if lasts else None
    return out, conflict


# --------------------------------------------------------------------------- #
# Correlation
# --------------------------------------------------------------------------- #


@dataclass
class Pair:
    """One CVE x component from the SBOM, with its verdict."""

    vuln_id: str
    ref: str
    verdict: Verdict
    finding: Optional[Dict[str, Any]] = None  # a representative finding (EPSS etc.)
    private: bool = False  # --no-comments: properties carry no free text


@dataclass
class Report:
    """Counts and warnings for --report."""

    findings_total: int = 0
    findings_matched: int = 0
    findings_no_component: List[str] = field(default_factory=list)
    findings_not_in_sbom: List[str] = field(default_factory=list)
    findings_no_id: List[str] = field(default_factory=list)
    findings_ambiguous: List[str] = field(default_factory=list)
    findings_wrong_version: List[str] = field(default_factory=list)
    conflicts: List[str] = field(default_factory=list)
    pairs_without_finding: int = 0
    states: Counter = field(default_factory=Counter)
    statements: int = 0
    warnings: List[str] = field(default_factory=list)
    trimmed: bool = False  # SBOM came from sbom_trim: never name findings it does not list

    def format(self, fmt: str) -> str:
        lines = [f"VEX ({fmt}): {self.statements} statements, "
                 f"{sum(self.states.values())} CVE x component pairs"]
        for state, n in sorted(self.states.items()):
            lines.append(f"  {state:<22}{n}")
        lines.append(f"Findings: {self.findings_total} read, {self.findings_matched} matched")
        if self.pairs_without_finding:
            lines.append(f"  {self.pairs_without_finding} SBOM pairs had no finding (in_triage)")
        unmatched = (
            ("Findings with no SBOM component", self.findings_no_component),
            ("Findings whose CVE is not on that SBOM component", self.findings_not_in_sbom),
            ("Findings without a CVE id", self.findings_no_id),
            ("Ambiguous findings: file name fits several packages (not applied)",
             self.findings_ambiguous),
            ("Findings whose version differs from the SBOM component at that path",
             self.findings_wrong_version))
        for title, items in unmatched + (("Conflicting findings (worst state used)",
                                          self.conflicts),):
            if not items:
                continue
            if self.trimmed and items is not self.conflicts:
                lines.append(f"{title}: {len(items)} (trimmed SBOM; names not shown)")
                continue
            lines.append(f"{title}: {len(items)}")
            lines.extend(f"  {x}" for x in items[:20])
            if len(items) > 20:
                lines.append(f"  ... {len(items) - 20} more")
        lines.extend(f"Note: {w}" for w in self.warnings)
        return "\n".join(lines)


def _details(f: Dict[str, Any]) -> Dict[str, Any]:
    d = f.get("finding_details")
    return d if isinstance(d, dict) else {}


def _scan_mode(f: Dict[str, Any]) -> str:
    meta = _details(f).get("metadata")  # the API spec types it as a string: ignore that form
    mode = meta.get("sca_scan_mode") if isinstance(meta, dict) else None
    return mode.lower() if isinstance(mode, str) else ""


def _cve_name(f: Dict[str, Any]) -> Optional[str]:
    cve = _details(f).get("cve")
    name = cve.get("name") if isinstance(cve, dict) else None
    return name if isinstance(name, str) and name else None


def _finding_label(f: Dict[str, Any]) -> str:
    d = _details(f)
    parts = (_cve_name(f) or "?", d.get("component_filename") or "?", d.get("version") or "",
             _scan_mode(f))
    return " ".join(str(p) for p in parts).strip()


def is_trimmed(bom: Dict[str, Any]) -> bool:
    """True when sbom_trim produced the SBOM (its tool entry or redacted placeholders)."""
    meta = bom.get("metadata")
    tools = meta.get("tools") if isinstance(meta, dict) else None
    items: List[Any] = tools if isinstance(tools, list) else []
    if isinstance(tools, dict):
        for k in ("components", "services"):
            items += tools[k] if isinstance(tools.get(k), list) else []
    if any(isinstance(t, dict) and _low(t.get("name")) in SBOM_TRIM_NAMES for t in items):
        return True
    return any(_prop(c, REDACTED_PROPERTY) or REDACTED_REF_RE.match(str(c.get("bom-ref", "")))
               for c in iter_components(all_components(bom)))


def merge_vuln_records(records: List[Dict[str, Any]]) -> Dict[str, Any]:
    """One record per id: NVD source when present, ratings/cwes unioned, first text/dates."""
    if len(records) == 1:
        return records[0]
    out = dict(records[0])
    sources = [r["source"] for r in records if isinstance(r.get("source"), dict)]
    nvd = [s for s in sources if _low(s.get("name")) == "nvd"]
    if nvd or sources:
        out["source"] = (nvd or sources)[0]
    ratings: List[Any] = []
    seen_r: Set[str] = set()
    cwes: List[Any] = []
    for n, r in enumerate(records):
        raw_r, raw_c = r.get("ratings"), r.get("cwes")
        new: Set[str] = set()
        for rating in raw_r if isinstance(raw_r, list) else []:
            if not isinstance(rating, dict):
                continue
            key = json.dumps([rating.get("method"), rating.get("vector"), rating.get("source")],
                             sort_keys=True, default=str)
            if n == 0 or key not in seen_r:  # later records add only new (method, vector, source)
                new.add(key)
                ratings.append(rating)
        seen_r |= new
        for c in raw_c if isinstance(raw_c, list) else []:
            if c not in cwes:
                cwes.append(c)
    out["ratings"], out["cwes"] = ratings, cwes
    for k in ("description", "created", "published", "updated"):
        out[k] = next((r[k] for r in records if isinstance(r.get(k), str) and r[k]), None)
    return out


def correlate(bom: Dict[str, Any], findings: List[Dict[str, Any]],
              comments: bool = True) -> Tuple[List[Pair], Dict[str, Dict[str, Any]], Report]:
    """Return (pairs in SBOM order, merged SBOM vuln per id, report)."""
    report = Report(findings_total=len(findings), trimmed=is_trimmed(bom))
    index = SbomIndex(bom)
    records: "OrderedDict[str, List[Dict[str, Any]]]" = OrderedDict()
    order: "OrderedDict[Tuple[str, str], None]" = OrderedDict()
    for v in bom["vulnerabilities"]:
        records.setdefault(v["id"], []).append(v)  # Veracode can repeat an id: merged below
        for a in v.get("affects") or []:
            ref = a.get("ref") if isinstance(a, dict) else None
            if isinstance(ref, str) and ref:
                if ref not in index.comps:
                    report.warnings.append(f"{v['id']} affects unknown ref {ref!r}; skipped")
                    continue
                order[(v["id"], ref)] = None
    base = OrderedDict((vid, merge_vuln_records(recs)) for vid, recs in records.items())
    for vid, recs in records.items():
        if not any(r.get("affects") for r in recs):
            report.warnings.append(f"{vid} has no affects; no statement")
    if findings and not index.has_paths and any(_scan_mode(f) == "upload" for f in findings):
        report.warnings.append("SBOM has no File Path properties; upload findings are matched "
                               "by file name only")
    by_pair: Dict[Tuple[str, str], List[Tuple[Verdict, Dict[str, Any]]]] = {}
    for f in findings:
        cve = _cve_name(f)
        if cve is None:
            report.findings_no_id.append(_finding_label(f))
            continue
        refs, problem = index.resolve(f)
        if not refs:
            {"ambiguous": report.findings_ambiguous, "version": report.findings_wrong_version}.get(
                problem, report.findings_no_component).append(_finding_label(f))
            continue
        hit = [r for r in refs if (cve, r) in order]
        if not hit:
            report.findings_not_in_sbom.append(_finding_label(f))
            continue
        report.findings_matched += 1
        verdict = classify(f, comments)
        if verdict.rule is CLOSED:  # the SBOM still lists this pair, so "fixed" would be false
            verdict.rule, verdict.notes = STALE_CLOSED, [STALE_NOTE]
        for r in hit:
            by_pair.setdefault((cve, r), []).append((verdict, f))
    pairs: List[Pair] = []
    for (vid, ref) in order:
        entries = by_pair.get((vid, ref))
        if not entries:
            report.pairs_without_finding += 1
            verdict = Verdict(rule=NO_FINDING,
                              notes=["No Veracode SCA finding supplied for this component."])
            pairs.append(Pair(vid, ref, verdict))
            continue
        verdict, conflict = merge([e[0] for e in entries])
        if conflict:
            report.conflicts.append(f"{vid} {ref}")
        # Prefer a finding with EPSS data for the properties.
        rep = next((e[1] for e in entries
                    if (_details(e[1]).get("cve") or {}).get("exploitability")), entries[0][1])
        pairs.append(Pair(vid, ref, verdict, rep, private=not comments))
    for p in pairs:
        report.states[p.verdict.rule.cdx_state] += 1
    return pairs, base, report


# --------------------------------------------------------------------------- #
# CycloneDX VEX
# --------------------------------------------------------------------------- #


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def bom_link(serial: str, version: int, ref: str) -> str:
    """BOM-Link to a component of the SBOM: urn:cdx:<uuid>/<version>#<bom-ref>."""
    m = SERIAL_RE.match(serial)
    if not m:
        raise VexError(f"SBOM serialNumber {serial!r} is not urn:uuid:<uuid>")
    # Fragment chars per RFC 3986 stay as-is; '#', spaces etc. are percent-encoded.
    try:
        frag = quote(ref, safe=FRAGMENT_SAFE)
    except UnicodeEncodeError as exc:
        raise VexError(f"bom-ref {ref!r} is not valid Unicode (lone surrogate)") from exc
    return f"urn:cdx:{m.group(1).lower()}/{version}#{frag}"


def _detail(v: Verdict) -> str:
    return "\n".join(v.notes + v.comments)


def _vuln_props(pair: Pair, v: Verdict) -> List[Dict[str, str]]:
    props: List[Dict[str, str]] = []
    # --no-comments: export only enum, number, date and short-token values (no free text).
    strict = pair.private
    if v.mitigation:
        props.append({"name": "veracode:mitigation", "value": v.mitigation})
    if v.proposed:
        props.append({"name": "veracode:proposed_mitigation", "value": v.proposed})
    if v.resolution_status and (not strict or v.resolution_status in RESOLUTION_STATUSES):
        props.append({"name": "veracode:resolution_status", "value": v.resolution_status})
    if pair.finding:
        cve = (pair.finding.get("finding_details") or {}).get("cve") or {}
        raw = cve.get("exploitability")
        ex: Dict[str, Any] = raw if isinstance(raw, dict) else {}
        for key in ("epss_score", "epss_percentile", "epss_score_date"):
            val = ex.get(key)
            if val in (None, ""):
                continue
            if strict and not (_parse_dt(val) is not None if key == "epss_score_date" else
                               isinstance(val, (int, float)) and not isinstance(val, bool)):
                continue
            props.append({"name": f"veracode:{key}", "value": str(val)})
        # Only a real bool from a working exploit service; null/unavailable means unknown.
        obs = ex.get("exploit_observed")
        service = str(ex.get("exploit_service_status") or "").lower()
        if isinstance(obs, bool) and service == "available":
            props.append({"name": "veracode:exploit_observed", "value": str(obs).lower()})
        source = ex.get("exploit_source")
        if source and (not strict or (isinstance(source, str) and TOKEN_RE.fullmatch(source))):
            props.append({"name": "veracode:exploit_source", "value": str(source)})
        if "violates_policy" in pair.finding:
            props.append({"name": "veracode:violates_policy",
                          "value": str(bool(pair.finding["violates_policy"])).lower()})
    return props


def _copy_ratings(ratings: Any) -> List[Dict[str, Any]]:
    out = []
    for r in ratings if isinstance(ratings, list) else []:
        if not isinstance(r, dict):
            continue
        rating: Dict[str, Any] = {}
        if isinstance(r.get("source"), dict) and r["source"].get("name"):
            rating["source"] = {k: r["source"][k] for k in ("name", "url") if r["source"].get(k)}
        score = r.get("score")
        finite = not isinstance(score, float) or math.isfinite(score)  # NaN/INF are not JSON
        if isinstance(score, (int, float)) and not isinstance(score, bool) and finite:
            rating["score"] = score
        for key in ("severity", "method", "vector"):
            if isinstance(r.get(key), str) and r[key]:
                rating[key] = r[key]
        if rating:
            out.append(rating)
    return out


def _group(pairs: Sequence[Any], key_fn: Any) -> "OrderedDict[Any, List[Any]]":
    groups: "OrderedDict[Any, List[Any]]" = OrderedDict()
    for p in pairs:
        groups.setdefault(key_fn(p), []).append(p)
    return groups


def build_cdx(bom: Dict[str, Any], pairs: List[Pair], base: Dict[str, Dict[str, Any]],
              report: Report) -> Dict[str, Any]:
    """Standalone CycloneDX VEX whose affects point at the SBOM via BOM-Link."""
    spec = bom["specVersion"]
    serial = bom.get("serialNumber")
    if not isinstance(serial, str):
        raise VexError("SBOM has no serialNumber; a standalone VEX needs it to link back")
    sver = bom.get("version", 1)
    if not isinstance(sver, int) or isinstance(sver, bool) or sver < 1:
        raise VexError(f"SBOM version {sver!r} is not a positive integer")
    meta: Dict[str, Any] = {"timestamp": _now()}
    if spec == "1.4":
        meta["tools"] = [{"vendor": "community", "name": TOOL_NAME, "version": __version__}]
    else:
        meta["tools"] = {"components": [{"type": "application", "name": TOOL_NAME,
                                         "version": __version__}]}
    meta_raw = bom.get("metadata")
    meta_in: Dict[str, Any] = meta_raw if isinstance(meta_raw, dict) else {}
    root = meta_in.get("component")
    if isinstance(root, dict) and isinstance(root.get("name"), str) and root["name"]:
        meta["component"] = {k: root[k] for k in ("type", "bom-ref", "group", "name", "version",
                                                  "purl") if isinstance(root.get(k), str)}
        meta["component"].setdefault("type", "application")
    vex: Dict[str, Any] = {
        "bomFormat": "CycloneDX", "specVersion": spec,
        "serialNumber": f"urn:uuid:{uuid.uuid4()}", "version": 1, "metadata": meta,
        "vulnerabilities": [],
    }

    def key(p: Pair) -> Any:
        v = p.verdict
        return (p.vuln_id, v.rule.cdx_state, v.rule.cdx_justification, v.rule.cdx_responses,
                _detail(v), tuple(x["name"] + "=" + x["value"] for x in _vuln_props(p, v)))

    used: Set[str] = set()
    for (vid, state, just, responses, detail, _), group in _group(pairs, key).items():
        src = base[vid]
        n, ref = 1, vid
        while ref in used:  # same id, different analysis -> distinct bom-ref
            n += 1
            ref = f"{vid}#{n}"
        used.add(ref)
        out: Dict[str, Any] = {"bom-ref": ref, "id": vid}
        if isinstance(src.get("source"), dict) and src["source"]:
            out["source"] = {k: src["source"][k] for k in ("name", "url") if src["source"].get(k)}
        ratings = _copy_ratings(src.get("ratings"))
        if ratings:
            out["ratings"] = ratings
        raw_cwes = src.get("cwes")
        cwes = [c for c in (raw_cwes if isinstance(raw_cwes, list) else [])
                if isinstance(c, int) and not isinstance(c, bool)]
        if cwes:
            out["cwes"] = cwes
        for k in ("description", "created", "published", "updated"):
            if isinstance(src.get(k), str) and src[k]:
                out[k] = _clean(src[k]) if k == "description" else src[k]
        analysis: Dict[str, Any] = {"state": state}
        if just:
            analysis["justification"] = just
        if responses:
            analysis["response"] = list(responses)
        if detail:
            analysis["detail"] = detail
        if spec != "1.4":
            firsts = [p.verdict.first_issued for p in group if p.verdict.first_issued]
            lasts = [p.verdict.last_updated for p in group if p.verdict.last_updated]
            if firsts:
                analysis["firstIssued"] = min(firsts)  # already RFC 3339 UTC
            if lasts:
                analysis["lastUpdated"] = max(lasts)
        out["analysis"] = analysis
        out["affects"] = [{"ref": bom_link(serial, sver, p.ref)} for p in group]
        props = _vuln_props(group[0], group[0].verdict)
        if props:
            out["properties"] = props
        vex["vulnerabilities"].append(out)
    report.statements = len(vex["vulnerabilities"])
    return vex


def _iso(val: Any) -> Optional[str]:
    """Veracode dates -> RFC 3339 UTC (schema date-time); None when unparseable."""
    dt = _parse_dt(val)
    if dt is None:
        return None
    # Manual format: strftime("%Y") does not zero-pad years < 1000 on every platform.
    return (f"{dt.year:04d}-{dt.month:02d}-{dt.day:02d}T{dt.hour:02d}:{dt.minute:02d}:"
            f"{dt.second:02d}Z")


# CycloneDX XML: element order follows the XSD sequences.
VULN_ORDER = ("id", "source", "ratings", "cwes", "description", "created", "published",
              "updated", "analysis", "affects")


def _sub(parent: Any, tag: str, text: Any = None, **attrs: str) -> Any:
    el = ET.SubElement(parent, tag, {k.replace("_", "-"): _clean(v) for k, v in attrs.items()})
    if text is not None:
        el.text = _clean(str(text)) if isinstance(text, str) else str(text)
    return el


def cdx_to_xml(vex: Dict[str, Any], indent: int = 2) -> str:
    """Serialize the VEX document built by build_cdx() to CycloneDX XML."""
    spec = vex["specVersion"]
    ns = CDX_NS + spec
    ET.register_namespace("", ns)
    q = lambda t: f"{{{ns}}}{t}"  # noqa: E731
    root = ET.Element(q("bom"), {"serialNumber": vex["serialNumber"], "version": str(vex["version"])})
    meta = vex["metadata"]
    m = _sub(root, q("metadata"))
    _sub(m, q("timestamp"), meta["timestamp"])
    tools = _sub(m, q("tools"))
    if isinstance(meta["tools"], list):
        for t in meta["tools"]:
            tool = _sub(tools, q("tool"))
            for k in ("vendor", "name", "version"):
                if t.get(k):
                    _sub(tool, q(k), t[k])
    else:
        comps = _sub(tools, q("components"))
        for t in meta["tools"]["components"]:
            c = _sub(comps, q("component"), type=t["type"])
            _sub(c, q("name"), t["name"])
            _sub(c, q("version"), t["version"])
    if meta.get("component"):
        mc = meta["component"]
        attrs = {"type": mc["type"]}
        if mc.get("bom-ref"):
            attrs["bom_ref"] = mc["bom-ref"]
        c = _sub(m, q("component"), **attrs)
        for k in ("group", "name", "version", "purl"):
            if mc.get(k):
                _sub(c, q(k), mc[k])
    vulns = _sub(root, q("vulnerabilities"))
    for v in vex["vulnerabilities"]:
        ve = _sub(vulns, q("vulnerability"), bom_ref=v["bom-ref"])
        for k in VULN_ORDER:
            if k not in v:
                continue
            val = v[k]
            if k == "source":
                s = _sub(ve, q("source"))
                for sk in ("name", "url"):
                    if val.get(sk):
                        _sub(s, q(sk), val[sk])
            elif k == "ratings":
                rs = _sub(ve, q("ratings"))
                for r in val:
                    re_ = _sub(rs, q("rating"))
                    if r.get("source"):
                        s = _sub(re_, q("source"))
                        for sk in ("name", "url"):
                            if r["source"].get(sk):
                                _sub(s, q(sk), r["source"][sk])
                    for rk in ("score", "severity", "method", "vector"):
                        if rk in r:
                            _sub(re_, q(rk), r[rk])
            elif k == "cwes":
                cs = _sub(ve, q("cwes"))
                for cwe in val:
                    _sub(cs, q("cwe"), cwe)
            elif k == "analysis":
                a = _sub(ve, q("analysis"))
                _sub(a, q("state"), val["state"])
                if val.get("justification"):
                    _sub(a, q("justification"), val["justification"])
                if val.get("response"):
                    rs = _sub(a, q("responses"))
                    for r in val["response"]:
                        _sub(rs, q("response"), r)
                for ak in ("detail", "firstIssued", "lastUpdated"):
                    if val.get(ak):
                        _sub(a, q(ak), val[ak])
            elif k == "affects":
                af = _sub(ve, q("affects"))
                for t in val:
                    _sub(_sub(af, q("target")), q("ref"), t["ref"])
            else:
                _sub(ve, q(k), val)
        if v.get("properties"):
            ps = _sub(ve, q("properties"))
            for p in v["properties"]:
                _sub(ps, q("property"), p["value"], name=p["name"])
    if indent > 0:
        ET.indent(root, " " * indent)
    return '<?xml version="1.0" encoding="UTF-8"?>\n' + ET.tostring(root, encoding="unicode") + "\n"


# --------------------------------------------------------------------------- #
# OpenVEX
# --------------------------------------------------------------------------- #


def _ov_action(pair: Pair, comp: Dict[str, Any]) -> str:
    rule = pair.verdict.rule
    who = "@".join(x for x in (comp.get("name"), comp.get("version")) if isinstance(x, str))
    if rule is MITIGATIONS["ACCEPTRISK"]:
        return "Risk accepted after review in Veracode; no fix planned."
    if rule is MITIGATIONS["LIBRARY"]:
        return "Reported to the library maintainer; no fixed version available yet."
    if rule is MITIGATIONS["DEFER"]:
        return (f"Remediation deferred after review in Veracode; update {who or 'the component'} "
                f"to a version not affected by {pair.vuln_id} when scheduled.")
    return f"Update {who or 'the component'} to a version not affected by {pair.vuln_id}."


def build_openvex(bom: Dict[str, Any], pairs: List[Pair], base: Dict[str, Dict[str, Any]],
                  report: Report, author: str, product: Optional[str]) -> Dict[str, Any]:
    """OpenVEX 0.2.0 document; one statement per CVE and outcome."""
    index = SbomIndex(bom)
    serial, sver = bom.get("serialNumber"), bom.get("version", 1)
    now = _now()
    statements: List[Dict[str, Any]] = []

    def product_id(ref: str) -> Optional[str]:
        comp = index.comps[ref]
        if isinstance(comp.get("purl"), str) and comp["purl"]:
            return comp["purl"]
        if isinstance(serial, str) and SERIAL_RE.match(serial) and isinstance(sver, int):
            return bom_link(serial, sver, ref)
        return None

    def key(item: Tuple[str, Pair]) -> Any:
        p = item[1]
        v = p.verdict
        text = _detail(v)
        action = _ov_action(p, index.comps[p.ref]) if v.rule.ov_status == "affected" else ""
        return (p.vuln_id, v.rule.ov_status, v.rule.ov_justification, text, action)

    # One verdict per CVE x product @id: components sharing a purl merge, worst wins.
    by_pid: "OrderedDict[Tuple[str, str], List[Pair]]" = OrderedDict()
    skipped = 0
    for p in pairs:
        pid = product_id(p.ref)
        if pid is None:
            skipped += 1
            continue
        by_pid.setdefault((p.vuln_id, pid), []).append(p)
    items: List[Tuple[str, Pair]] = []
    for (vid, pid), ps in by_pid.items():
        if len(ps) == 1:
            items.append((pid, ps[0]))
            continue
        verdict, conflict = merge([q.verdict for q in ps])
        if conflict:
            report.conflicts.append(f"{vid} {pid}")
        rep = next((q for q in ps if q.finding), ps[0])
        items.append((pid, Pair(vid, rep.ref, verdict, rep.finding)))

    for (vid, status, just, text, action), group in _group(items, key).items():
        prods: List[Dict[str, Any]] = []
        for pid, _ in group:
            item: Dict[str, Any] = {"@id": pid}
            if pid.startswith("pkg:"):
                item["identifiers"] = {"purl": pid}
            prods.append(item)
        if product:
            prods = [{"@id": product, "subcomponents": prods}]
        # CISA: statement first issued / last updated come from the verdicts, not run time.
        firsts = [p.verdict.first_issued for _, p in group if p.verdict.first_issued]
        ts = min(firsts) if firsts else now
        lasts = [p.verdict.last_updated or p.verdict.first_issued for _, p in group]
        st: Dict[str, Any] = {"vulnerability": {"name": vid}, "version": 1, "timestamp": ts,
                              "last_updated": max([x for x in lasts if x] + [ts]),
                              "products": prods, "status": status}
        desc = base[vid].get("description")
        if isinstance(desc, str) and desc:
            st["vulnerability"]["description"] = _clean(desc)
        if status == "not_affected":
            if just:
                st["justification"] = just
            st["impact_statement"] = text  # always set; CISA minimum for not_affected
        elif status == "affected":
            st["action_statement"] = action
            if text:
                st["status_notes"] = text
        elif text:
            st["status_notes"] = text
        statements.append(st)
    if skipped:
        report.warnings.append(f"{skipped} component(s) had no purl and no SBOM serialNumber; "
                               "left out of the OpenVEX document")
    report.statements = len(statements)
    return {
        "@context": OPENVEX_CONTEXT,
        "@id": f"urn:uuid:{uuid.uuid4()}",
        "author": author,
        "timestamp": now,
        "last_updated": max((st["last_updated"] for st in statements), default=now),
        "version": 1,
        "tooling": f"{TOOL_NAME}/{__version__}",
        "statements": statements,
    }


# --------------------------------------------------------------------------- #
# Checks
# --------------------------------------------------------------------------- #

RFC3339_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$")


def check_openvex(doc: Dict[str, Any]) -> List[str]:
    """OpenVEX 0.2.0 required fields, enums and CISA minimums; empty when valid."""
    errs: List[str] = []
    for k in ("@context", "@id", "author", "timestamp", "version", "statements"):
        if k not in doc:
            errs.append(f"missing {k}")
    if doc.get("@context") != OPENVEX_CONTEXT:
        errs.append("@context is not OpenVEX 0.2.0")
    if not RFC3339_RE.match(str(doc.get("timestamp", ""))):
        errs.append("timestamp is not RFC 3339")
    doc_last = _parse_dt(doc.get("last_updated"))
    if not RFC3339_RE.match(str(doc.get("last_updated", ""))) or doc_last is None:
        errs.append("last_updated missing or not RFC 3339 (CISA document last updated)")
    if not doc.get("statements"):
        errs.append("no statements: a VEX document needs at least one (components need a purl "
                    "or the SBOM a serialNumber)")
    owner: Dict[Tuple[str, str, str], int] = {}
    for i, st in enumerate(doc.get("statements") or []):
        where = f"statements[{i}]"
        vname = (st.get("vulnerability") or {}).get("name")
        if not vname:
            errs.append(f"{where}: vulnerability.name missing")
        prods = st.get("products") or []
        if not prods or any(not isinstance(p, dict) or not p.get("@id") for p in prods):
            errs.append(f"{where}: products missing or without @id")
        # One status per vulnerability x product (x subcomponent when nested).
        for p in prods if isinstance(prods, list) else []:
            if not isinstance(p, dict):
                continue
            subs = [s.get("@id") for s in p.get("subcomponents") or [] if isinstance(s, dict)]
            for sub in subs or [""]:
                okey = (str(vname), str(p.get("@id")), str(sub or ""))
                if okey in owner and owner[okey] != i:
                    errs.append(f"{where}: {vname} x {okey[1]} {okey[2]} is in more than one "
                                "statement")
                owner.setdefault(okey, i)
        status = st.get("status")
        if status not in OV_STATUSES:
            errs.append(f"{where}: bad status {status!r}")
        if st.get("justification") and st["justification"] not in OV_JUSTIFICATIONS:
            errs.append(f"{where}: bad justification {st['justification']!r}")
        if status == "not_affected" and not (st.get("justification") or st.get("impact_statement")):
            errs.append(f"{where}: not_affected needs justification or impact_statement")
        if status == "affected" and not st.get("action_statement"):
            errs.append(f"{where}: affected needs action_statement")
        if st.get("timestamp") and not RFC3339_RE.match(st["timestamp"]):
            errs.append(f"{where}: timestamp is not RFC 3339")
        # CISA statement minimums, in the OpenVEX 0.2.0 schema fields.
        ver = st.get("version")
        if not isinstance(ver, int) or isinstance(ver, bool) or ver < 1:
            errs.append(f"{where}: version missing (CISA statement version)")
        first = _parse_dt(st.get("timestamp"))
        last = _parse_dt(st.get("last_updated"))
        if first is None:
            errs.append(f"{where}: timestamp missing (CISA statement first issued)")
        if last is None or not RFC3339_RE.match(str(st.get("last_updated"))):
            errs.append(f"{where}: last_updated missing or not RFC 3339 "
                        "(CISA statement last updated)")
        elif first is not None and last < first:
            errs.append(f"{where}: last_updated is before timestamp")
        elif doc_last is not None and last > doc_last:
            errs.append(f"{where}: last_updated is after the document last_updated")
    return errs


def check_cdx(vex: Dict[str, Any], bom: Dict[str, Any]) -> List[str]:
    """Enums and BOM-Links that resolve to SBOM components; empty when valid."""
    errs: List[str] = []
    index = SbomIndex(bom)
    m = SERIAL_RE.match(bom.get("serialNumber", ""))
    prefix = f"urn:cdx:{m.group(1).lower()}/{bom.get('version', 1)}#" if m else None
    for i, v in enumerate(vex["vulnerabilities"]):
        a = v.get("analysis") or {}
        if a.get("state") not in CDX_STATES:
            errs.append(f"vulnerabilities[{i}]: bad state {a.get('state')!r}")
        if a.get("justification") and a["justification"] not in CDX_JUSTIFICATIONS:
            errs.append(f"vulnerabilities[{i}]: bad justification")
        if any(r not in CDX_RESPONSES for r in a.get("response") or []):
            errs.append(f"vulnerabilities[{i}]: bad response")
        for t in v.get("affects") or []:
            ref = t.get("ref", "")
            if not BOM_LINK_RE.match(ref) or not prefix or not ref.startswith(prefix):
                errs.append(f"vulnerabilities[{i}]: affects ref {ref!r} is not a BOM-Link to the SBOM")
            else:
                if unquote(ref[len(prefix):]) not in index.comps:
                    errs.append(f"vulnerabilities[{i}]: {ref!r} does not resolve in the SBOM")
    return errs


def validate_schema(text: str, spec_version: str, fmt: str) -> Optional[str]:
    """CycloneDX schema validation; None when valid. ImportError if the lib is missing."""
    from cyclonedx.schema import SchemaVersion  # type: ignore

    if fmt == "xml":
        from cyclonedx.validation.xml import XmlValidator as Validator  # type: ignore
    else:
        fast = _fast_json_validator(spec_version)
        if fast is not None:
            error = next(iter(fast.iter_errors(json.loads(text))), None)
            return None if error is None else str(error)
        from cyclonedx.validation.json import JsonStrictValidator as Validator  # type: ignore
    error = Validator(SchemaVersion.from_version(spec_version)).validate_str(text)
    return None if error is None else str(error)


_FAST_VALIDATORS: Dict[str, Any] = {}


def _fast_json_validator(spec_version: str) -> Any:
    """cyclonedx's strict JSON validator with an O(n) ``uniqueItems``; None if unavailable.

    jsonschema checks ``uniqueItems`` pairwise (O(n^2): 10k statements take minutes).
    Same schema, registry and format checker, so decisions and messages are unchanged.
    Uses library internals, hence the broad fallback to the library validator.
    """
    if spec_version not in _FAST_VALIDATORS:
        fast = None
        try:
            from cyclonedx.schema import SchemaVersion  # type: ignore
            from cyclonedx.validation.json import JsonStrictValidator  # type: ignore
            from jsonschema.validators import extend  # type: ignore

            ref = JsonStrictValidator(SchemaVersion.from_version(spec_version))._validator
            cls = extend(type(ref), {"uniqueItems": _unique_items})
            fast = cls(ref.schema, registry=ref._registry, format_checker=ref.format_checker)
        except Exception:  # noqa: BLE001 - missing extra or changed internals: library path
            fast = None
        _FAST_VALIDATORS[spec_version] = fast
    return _FAST_VALIDATORS[spec_version]


def _unique_items(validator: Any, unique: Any, instance: Any, schema: Any) -> Iterator[Any]:
    """``uniqueItems`` keyword with a hash set; same message as jsonschema's."""
    if not (unique and validator.is_type(instance, "array")):
        return
    seen: Set[Any] = set()
    for item in instance:
        key = _json_key(item)
        if key in seen:
            from jsonschema.exceptions import ValidationError  # type: ignore

            yield ValidationError(f"{instance!r} has non-unique elements")
            return
        seen.add(key)


def _json_key(value: Any) -> Any:
    """Hashable key equal exactly when jsonschema's ``equal`` is (true != 1, 1 == 1.0)."""
    if isinstance(value, bool):
        return ("b", value)
    if isinstance(value, (int, float)):
        return ("n", value)
    if isinstance(value, str):
        return ("s", value)
    if isinstance(value, list):
        return ("l", tuple(_json_key(v) for v in value))
    if isinstance(value, dict):
        return ("d", frozenset((k, _json_key(v)) for k, v in value.items()))
    return ("o", value)


# --------------------------------------------------------------------------- #
# Output and CLI
# --------------------------------------------------------------------------- #


def _same_file(a: str, b: str) -> bool:
    if os.path.exists(a) and os.path.exists(b):
        return os.path.samefile(a, b)
    return os.path.normcase(os.path.abspath(a)) == os.path.normcase(os.path.abspath(b))


def write_text(path: str, text: str) -> None:
    """Write atomically (temp file in the same directory, then rename)."""
    directory = os.path.dirname(os.path.abspath(path))
    if not os.path.isdir(directory):
        raise VexError(f"output directory does not exist: {directory}")
    if os.path.isdir(path):
        raise VexError(f"output path is a directory: {path}")
    fd, tmp = tempfile.mkstemp(prefix=f".{TOOL_NAME}-", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
        os.replace(tmp, path)
    except (OSError, UnicodeEncodeError) as exc:  # encode: text with a lone surrogate
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise VexError(f"cannot write {path}: {exc}") from exc


def _dumps(doc: Dict[str, Any], indent: int) -> str:
    try:  # allow_nan=False: NaN/Infinity are not JSON; strict consumers reject them
        return json.dumps(doc, indent=indent or None, ensure_ascii=False, allow_nan=False) + "\n"
    except ValueError as exc:
        raise VexError(f"output would not be valid JSON: {exc}") from exc


def build_parser() -> argparse.ArgumentParser:
    """CLI definition."""
    p = argparse.ArgumentParser(
        prog="veracode_vex.py",
        description="Generate CycloneDX VEX or OpenVEX from a Veracode SCA SBOM and findings.",
    )
    p.add_argument("sbom", help="CycloneDX JSON or XML SBOM from Veracode, with vulnerabilities")
    p.add_argument("-f", "--findings", action="append", default=[], metavar="FILE",
                   help="Findings API export (scan_type=SCA&include_annot=TRUE); repeat per page")
    p.add_argument("-o", "--output", required=True, help="output path (never an input)")
    p.add_argument("--format", choices=("cyclonedx", "openvex"), default="cyclonedx",
                   help="VEX format (default cyclonedx)")
    p.add_argument("--output-format", choices=("json", "xml"), default="json",
                   help="CycloneDX serialization (default json; OpenVEX is JSON only)")
    p.add_argument("--author", default="Unknown",
                   help="OpenVEX author: the organization issuing the statements "
                        "(default Unknown, with a warning)")
    p.add_argument("--product", metavar="ID",
                   help="OpenVEX: wrap components as subcomponents of this product (purl/IRI)")
    p.add_argument("--no-comments", action="store_true",
                   help="leave mitigation comments out of the VEX (state and reason stay)")
    p.add_argument("--report", action="store_true",
                   help="print counts, unmatched and conflicting findings and warnings to stdout")
    p.add_argument("--no-validate", action="store_true", help="skip schema validation")
    p.add_argument("--indent", type=int, default=2, help="output indent (default 2; 0 = compact)")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def main(argv: Optional[List[str]] = None) -> int:
    """CLI entry point; returns the process exit code."""
    for stream in (sys.stdout, sys.stderr):
        # A cp1252 console/pipe (Windows, PYTHONUTF8=0) must not crash --report after the
        # output was written; unencodable characters become \uXXXX.
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            try:
                reconfigure(errors="backslashreplace")
            except (ValueError, OSError):
                pass
    args = build_parser().parse_args(argv)
    try:
        if args.format == "openvex" and args.output_format == "xml":
            raise VexError("OpenVEX is JSON only; drop --output-format xml")
        for src in [args.sbom] + args.findings:
            if _same_file(src, args.output):
                raise VexError("--output must differ from every input file")
        bom = read_sbom(args.sbom)
        findings = read_findings(args.findings)
        if not args.findings:
            print("warning: no --findings; every statement is in_triage/under_investigation",
                  file=sys.stderr)
        blind = approved_without_history(findings)
        if blind:
            print(f"warning: {blind} approved findings have no mitigation details; the Findings "
                  "API does not return annotations for SCA (include_annot is not valid for SCA "
                  "per the API spec), so they are reported as in_triage", file=sys.stderr)
        pairs, base, report = correlate(bom, findings, comments=not args.no_comments)
        indent = max(args.indent, 0)
        if args.format == "openvex":
            doc = build_openvex(bom, pairs, base, report, args.author, args.product)
            errs = check_openvex(doc)
            if args.author == "Unknown":
                report.warnings.append("OpenVEX author is 'Unknown'; set --author")
            text = _dumps(doc, indent)
            label = "OpenVEX 0.2.0"
        else:
            doc = build_cdx(bom, pairs, base, report)
            errs = check_cdx(doc, bom)
            if args.output_format == "xml":
                text = cdx_to_xml(doc, indent)
            else:
                text = _dumps(doc, indent)
            label = f"CycloneDX {doc['specVersion']} {args.output_format.upper()}"
            if not args.no_validate and not errs:
                try:
                    error = validate_schema(text, doc["specVersion"], args.output_format)
                except ImportError:
                    print(f"warning: cyclonedx-python-lib[{args.output_format}-validation] not "
                          "installed; schema validation skipped", file=sys.stderr)
                else:
                    if error:
                        errs = [error]
        if errs:
            print(f"error: output failed {label} checks; nothing written:", file=sys.stderr)
            for e in errs[:20]:
                print(f"  {e}", file=sys.stderr)
            return EXIT_INVALID
        write_text(args.output, text)
    except VexError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return EXIT_INPUT
    except RecursionError:  # deep input structures that slipped past the readers
        print("error: input is nested too deeply", file=sys.stderr)
        return EXIT_INPUT
    if args.report:
        print(report.format(label))
    else:
        for w in report.warnings:
            print(f"warning: {w}", file=sys.stderr)
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
