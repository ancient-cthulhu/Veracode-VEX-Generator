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
import os
import re
import sys
import tempfile
import uuid
import xml.etree.ElementTree as ET
from collections import Counter, OrderedDict
from dataclasses import dataclass, field
from datetime import datetime, timezone
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
# Chars XML 1.0 cannot carry; stripped from every output string.
XML_BAD_CHARS = re.compile("[\x00-\x08\x0b\x0c\x0e-\x1f\ufffe\uffff]")
FRAGMENT_SAFE = ":@!$&'()*+,;=/?-._~"


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


# Veracode mitigation actions (Annotations API / UI). Only approved ones count.
MITIGATIONS: Dict[str, Rule] = {
    "FP": Rule("False positive", "false_positive", None, (), "not_affected", None),
    "APPDESIGN": Rule("Mitigated by design", "not_affected", "protected_by_mitigating_control",
                      (), "not_affected", "inline_mitigations_already_exist"),
    "NETENV": Rule("Mitigated by network environment", "not_affected", "protected_at_perimeter",
                   (), "not_affected", "vulnerable_code_cannot_be_controlled_by_adversary"),
    "OSENV": Rule("Mitigated by OS environment", "not_affected", "protected_at_runtime",
                  (), "not_affected", "inline_mitigations_already_exist"),
    "ACCEPTRISK": Rule("Risk accepted", "exploitable", None, ("will_not_fix",), "affected", None),
    "LIBRARY": Rule("Reported to library maintainer", "exploitable", None, ("can_not_fix",),
                    "affected", None),
}
OPEN = Rule("Open", "exploitable", None, ("update",), "affected", None)
PROPOSED = Rule("Mitigation proposed", "in_triage", None, (), "under_investigation", None)
CLOSED = Rule("Fixed", "resolved", None, (), "fixed", None)
NO_FINDING = Rule("Not analyzed", "in_triage", None, (), "under_investigation", None)

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
    "COMMENT": "COMMENT",
}

# Merge order for several findings on one CVE x component: worst wins.
STATE_RANK = {"exploitable": 4, "in_triage": 3, "not_affected": 2, "false_positive": 1,
              "resolved": 0}


@dataclass
class Verdict:
    """Outcome for one CVE x component."""

    rule: Rule
    notes: List[str] = field(default_factory=list)
    comments: List[str] = field(default_factory=list)
    first_issued: Optional[str] = None
    last_updated: Optional[str] = None
    mitigation: Optional[str] = None  # Veracode action code, e.g. APPDESIGN
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


def _xml_component(el: Any) -> Dict[str, Any]:
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
        comp["components"] = [_xml_component(c) for c in _kids(nested, "component")]
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
                    rating["score"] = float(score)
                except ValueError:
                    pass
            for key in ("severity", "method", "vector"):
                val = _text(r, key)
                if val:
                    rating[key] = val
            out.append(rating)
        vuln["ratings"] = out
    cwes = _kid(el, "cwes")
    if cwes is not None:
        vuln["cwes"] = [int(c.text) for c in _kids(cwes, "cwe") if c.text and c.text.strip().isdigit()]
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
    if "<!DOCTYPE" in text or "<!ENTITY" in text:  # no XXE / billion laughs
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
    bom["version"] = int(ver) if ver.isdigit() else ver
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
        bom = xml_to_sbom(text)
    else:
        try:
            bom = json.loads(text)
        except (json.JSONDecodeError, RecursionError) as exc:
            raise VexError(f"SBOM is not valid JSON: {exc}") from exc
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
    return bom


def read_findings(paths: Sequence[str]) -> List[Dict[str, Any]]:
    """Load SCA findings from Findings API exports; exact duplicates are dropped."""
    out: List[Dict[str, Any]] = []
    seen: Set[str] = set()
    for path in paths:
        try:
            data = json.loads(_read_text(path))
        except (json.JSONDecodeError, RecursionError) as exc:
            raise VexError(f"{path}: not valid JSON: {exc}") from exc
        # Accept the API response, {"findings": [...]}, or a bare list.
        if isinstance(data, dict):
            emb = data.get("_embedded")
            if "_embedded" in data and not isinstance(emb, dict):
                raise VexError(f"{path}: '_embedded' must be an object")
            items = emb.get("findings") if isinstance(emb, dict) else data.get("findings")
            page = data.get("page") or {}
            if isinstance(page, dict) and (page.get("total_pages") or 1) > 1:
                print(f"warning: {path} is page {page.get('number', 0) + 1} of "
                      f"{page['total_pages']}; pass every page", file=sys.stderr)
        else:
            items = data
        if not isinstance(items, list):
            raise VexError(f"{path}: no findings list (expected a Findings API response)")
        for i, f in enumerate(items):
            if not isinstance(f, dict):
                raise VexError(f"{path}: findings[{i}] is not an object")
            if str(f.get("scan_type", "SCA")).upper() != "SCA":
                continue  # SAST/DAST have no CVE x component
            # Shape checks so bad exports fail with a message, not a traceback.
            d = f.get("finding_details")
            dd = d if isinstance(d, dict) else {}
            for name, val, typ in (("finding_details", d, dict),
                                   ("finding_status", f.get("finding_status"), dict),
                                   ("finding_details.cve", dd.get("cve"), dict),
                                   ("finding_details.metadata", dd.get("metadata"), dict),
                                   ("annotations", f.get("annotations"), list),
                                   ("finding_details.component_path", dd.get("component_path"), list)):
                if val is not None and not isinstance(val, typ):
                    kind = "an object" if typ is dict else "an array"
                    raise VexError(f"{path}: findings[{i}].{name} must be {kind}")
            key = json.dumps(f, sort_keys=True)
            if key not in seen:
                seen.add(key)
                out.append(f)
    return out


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


class SbomIndex:
    """Lookups from Veracode finding fields to SBOM bom-refs."""

    def __init__(self, bom: Dict[str, Any]) -> None:
        self.comps: Dict[str, Dict[str, Any]] = {}
        self.by_path: Dict[str, Set[str]] = {}
        self.by_gav: Dict[Tuple[str, str, str], Set[str]] = {}
        self.by_nv: Dict[Tuple[str, str], Set[str]] = {}
        for comp in iter_components(bom.get("components")):
            ref = comp.get("bom-ref")
            if not isinstance(ref, str):
                continue
            self.comps[ref] = comp
            for path in _prop(comp, VC_FILE_PATH):
                self.by_path.setdefault(path.lower(), set()).add(ref)
            name, ver = _low(comp.get("name")), _low(comp.get("version"))
            self.by_gav.setdefault((_low(comp.get("group")), name, ver), set()).add(ref)
            self.by_nv.setdefault((name, ver), set()).add(ref)

    def match(self, finding: Dict[str, Any]) -> Set[str]:
        """bom-refs a finding refers to; empty when nothing matches."""
        d = finding.get("finding_details") or {}
        ver = _low(d.get("version"))
        paths: List[str] = [p["path"] for p in d.get("component_path") or []
                            if isinstance(p, dict) and isinstance(p.get("path"), str)]
        # 1. Upload scans: component_path == SBOM "File Path".
        for path in paths:
            refs = self.by_path.get(path.lower())
            if refs:
                return set(refs)
        # 2. Agent scans: ".../pom.xml/group:artifact" (or ".../name") + version.
        for path in paths:
            last = path.rstrip("/").rsplit("/", 1)[-1]
            if ":" in last:
                group, art = last.split(":", 1)
                refs = self.by_gav.get((group.lower(), art.split(":")[0].lower(), ver))
            else:
                refs = self.by_nv.get((last.lower(), ver))
            if refs:
                return set(refs)
        # 3. Filename "<name>-<version>.<ext>".
        fname = _low(d.get("component_filename"))
        if ver and fname:
            stem = os.path.splitext(fname)[0]
            if stem.endswith("-" + ver):
                refs = self.by_nv.get((stem[: -len(ver) - 1], ver))
                if refs:
                    return set(refs)
        return set()


# --------------------------------------------------------------------------- #
# Finding classification
# --------------------------------------------------------------------------- #


def _norm_action(val: Any) -> str:
    key = re.sub(r"[^A-Z]", "", str(val or "").upper())
    return ACTION_ALIASES.get(key, key)


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


def classify(finding: Dict[str, Any], comments: bool = True) -> Verdict:
    """Map one Veracode SCA finding to a VEX outcome."""
    st = finding.get("finding_status") or {}
    status = str(st.get("status") or "").upper()
    resolution = str(st.get("resolution") or "").upper()
    rstatus = str(st.get("resolution_status") or "").upper()
    anns = [a for a in finding.get("annotations") or [] if isinstance(a, dict)]
    anns.sort(key=lambda a: str(a.get("created") or ""))  # stable; undated keep order
    proposal = None
    for ann in anns:
        if _norm_action(ann.get("action")) in MITIGATIONS:
            proposal = ann
    action = _norm_action(proposal.get("action")) if proposal else None
    if action is None and "FALSE_POSITIVE" in resolution:
        action = "FP"
    dates = [str(a["created"]) for a in anns if a.get("created")]
    v = Verdict(rule=OPEN, resolution_status=rstatus or None, finding_count=1)
    v.first_issued = st.get("first_found_date") or (dates[0] if dates else None)
    v.last_updated = dates[-1] if dates else v.first_issued

    if rstatus == "APPROVED":
        if action:
            v.rule, v.mitigation = MITIGATIONS[action], action
            v.notes.append(f"Approved Veracode mitigation: {MITIGATIONS[action].label}.")
        else:
            # Approved, reason unknown: never claim not_affected without the reason.
            v.rule = PROPOSED
            v.notes.append("Veracode mitigation approved; reason not in export "
                           "(re-export with include_annot=TRUE).")
    elif rstatus == "PROPOSED":
        v.rule, v.mitigation = PROPOSED, action
        label = MITIGATIONS[action].label if action else "unknown reason"
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
        for ann in anns:
            text = _annotation_text(ann)
            if text and text not in v.comments:
                v.comments.append(text)
    return v


def merge(verdicts: List[Verdict]) -> Tuple[Verdict, bool]:
    """Combine several findings on one CVE x component; returns (verdict, conflict)."""
    if len(verdicts) == 1:
        return verdicts[0], False
    worst = max(verdicts, key=lambda v: STATE_RANK.get(v.rule.cdx_state, 5))
    out = Verdict(rule=worst.rule, mitigation=worst.mitigation,
                  resolution_status=worst.resolution_status,
                  finding_count=sum(v.finding_count for v in verdicts))
    # Responses only when the winning state carries them; keep deterministic order.
    conflict = len({(v.rule.cdx_state, v.rule.cdx_justification, v.rule.cdx_responses)
                    for v in verdicts}) > 1
    for v in verdicts:
        for note in v.notes:
            if note not in out.notes and v.rule.cdx_state == worst.rule.cdx_state:
                out.notes.append(note)
        for c in v.comments:
            if c not in out.comments and v.rule.cdx_state == worst.rule.cdx_state:
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


@dataclass
class Report:
    """Counts and warnings for --report."""

    findings_total: int = 0
    findings_matched: int = 0
    findings_no_component: List[str] = field(default_factory=list)
    findings_not_in_sbom: List[str] = field(default_factory=list)
    conflicts: List[str] = field(default_factory=list)
    pairs_without_finding: int = 0
    states: Counter = field(default_factory=Counter)
    statements: int = 0
    warnings: List[str] = field(default_factory=list)

    def format(self, fmt: str) -> str:
        lines = [f"VEX ({fmt}): {self.statements} statements, "
                 f"{sum(self.states.values())} CVE x component pairs"]
        for state, n in sorted(self.states.items()):
            lines.append(f"  {state:<22}{n}")
        lines.append(f"Findings: {self.findings_total} read, {self.findings_matched} matched")
        if self.pairs_without_finding:
            lines.append(f"  {self.pairs_without_finding} SBOM pairs had no finding (in_triage)")
        for title, items in (("Findings with no SBOM component", self.findings_no_component),
                             ("Findings whose CVE is not on that SBOM component",
                              self.findings_not_in_sbom),
                             ("Conflicting findings (worst state used)", self.conflicts)):
            if items:
                lines.append(f"{title}: {len(items)}")
                lines.extend(f"  {x}" for x in items[:20])
                if len(items) > 20:
                    lines.append(f"  ... {len(items) - 20} more")
        lines.extend(f"Note: {w}" for w in self.warnings)
        return "\n".join(lines)


def _finding_label(f: Dict[str, Any]) -> str:
    d = f.get("finding_details") or {}
    cve = (d.get("cve") or {}).get("name") or "?"
    mode = ((d.get("metadata") or {}).get("sca_scan_mode") or "").lower()
    return f"{cve} {d.get('component_filename') or '?'} {d.get('version') or ''} {mode}".strip()


def correlate(bom: Dict[str, Any], findings: List[Dict[str, Any]],
              comments: bool = True) -> Tuple[List[Pair], Dict[str, Dict[str, Any]], Report]:
    """Return (pairs in SBOM order, first SBOM vuln per id, report)."""
    report = Report(findings_total=len(findings))
    index = SbomIndex(bom)
    base: "OrderedDict[str, Dict[str, Any]]" = OrderedDict()
    order: "OrderedDict[Tuple[str, str], None]" = OrderedDict()
    for v in bom["vulnerabilities"]:
        base.setdefault(v["id"], v)  # Veracode can repeat an id; first record wins
        for a in v.get("affects") or []:
            ref = a.get("ref") if isinstance(a, dict) else None
            if isinstance(ref, str) and ref:
                if ref not in index.comps:
                    report.warnings.append(f"{v['id']} affects unknown ref {ref!r}; skipped")
                    continue
                order[(v["id"], ref)] = None
    by_pair: Dict[Tuple[str, str], List[Tuple[Verdict, Dict[str, Any]]]] = {}
    for f in findings:
        cve = ((f.get("finding_details") or {}).get("cve") or {}).get("name")
        refs = index.match(f)
        if not cve or not refs:
            report.findings_no_component.append(_finding_label(f))
            continue
        hit = [r for r in refs if (cve, r) in order]
        if not hit:
            report.findings_not_in_sbom.append(_finding_label(f))
            continue
        report.findings_matched += 1
        verdict = classify(f, comments)
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
        rep = next((e[1] for e in entries if ((e[1].get("finding_details") or {}).get("cve") or {})
                    .get("exploitability")), entries[0][1])
        pairs.append(Pair(vid, ref, verdict, rep))
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
    return f"urn:cdx:{m.group(1).lower()}/{version}#{quote(ref, safe=FRAGMENT_SAFE)}"


def _detail(v: Verdict) -> str:
    return "\n".join(v.notes + v.comments)


def _vuln_props(pair: Pair, v: Verdict) -> List[Dict[str, str]]:
    props: List[Dict[str, str]] = []
    if v.mitigation:
        props.append({"name": "veracode:mitigation", "value": v.mitigation})
    if v.resolution_status:
        props.append({"name": "veracode:resolution_status", "value": v.resolution_status})
    if pair.finding:
        cve = (pair.finding.get("finding_details") or {}).get("cve") or {}
        raw = cve.get("exploitability")
        ex: Dict[str, Any] = raw if isinstance(raw, dict) else {}
        for key in ("epss_score", "epss_percentile", "epss_score_date"):
            if ex.get(key) not in (None, ""):
                props.append({"name": f"veracode:{key}", "value": str(ex[key])})
        if "exploit_observed" in ex:
            props.append({"name": "veracode:exploit_observed",
                          "value": str(bool(ex["exploit_observed"])).lower()})
        if ex.get("exploit_source"):
            props.append({"name": "veracode:exploit_source", "value": str(ex["exploit_source"])})
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
        if isinstance(r.get("score"), (int, float)) and not isinstance(r.get("score"), bool):
            rating["score"] = r["score"]
        for key in ("severity", "method", "vector"):
            if isinstance(r.get(key), str) and r[key]:
                rating[key] = r[key]
        if rating:
            out.append(rating)
    return out


def _group(pairs: List[Pair], key_fn: Any) -> "OrderedDict[Any, List[Pair]]":
    groups: "OrderedDict[Any, List[Pair]]" = OrderedDict()
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
        cwes = [c for c in src.get("cwes") or [] if isinstance(c, int) and not isinstance(c, bool)]
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
                analysis["firstIssued"] = _iso(min(firsts))
            if lasts:
                analysis["lastUpdated"] = _iso(max(lasts))
        out["analysis"] = analysis
        out["affects"] = [{"ref": bom_link(serial, sver, p.ref)} for p in group]
        props = _vuln_props(group[0], group[0].verdict)
        if props:
            out["properties"] = props
        vex["vulnerabilities"].append(out)
    report.statements = len(vex["vulnerabilities"])
    return vex


def _iso(val: str) -> str:
    """Veracode dates -> RFC 3339 (schema date-time); unparseable values pass through."""
    s = val.strip()
    try:
        dt = datetime.fromisoformat(s.replace("Z", "+00:00"))
    except ValueError:
        return s
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


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

    def key(p: Pair) -> Any:
        v = p.verdict
        text = _detail(v)
        action = _ov_action(p, index.comps[p.ref]) if v.rule.ov_status == "affected" else ""
        return (p.vuln_id, v.rule.ov_status, v.rule.ov_justification, text, action)

    skipped = 0
    for (vid, status, just, text, action), group in _group(pairs, key).items():
        prods: List[Dict[str, Any]] = []
        seen: Set[str] = set()
        for p in group:
            pid = product_id(p.ref)
            if pid is None:
                skipped += 1
                continue
            if pid in seen:
                continue
            seen.add(pid)
            item: Dict[str, Any] = {"@id": pid}
            if pid.startswith("pkg:"):
                item["identifiers"] = {"purl": pid}
            prods.append(item)
        if not prods:
            continue
        if product:
            prods = [{"@id": product, "subcomponents": prods}]
        st: Dict[str, Any] = {"vulnerability": {"name": vid}, "timestamp": now,
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
    for i, st in enumerate(doc.get("statements") or []):
        where = f"statements[{i}]"
        if not (st.get("vulnerability") or {}).get("name"):
            errs.append(f"{where}: vulnerability.name missing")
        prods = st.get("products") or []
        if not prods or any(not isinstance(p, dict) or not p.get("@id") for p in prods):
            errs.append(f"{where}: products missing or without @id")
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
        from cyclonedx.validation.json import JsonStrictValidator as Validator  # type: ignore
    error = Validator(SchemaVersion.from_version(spec_version)).validate_str(text)
    return None if error is None else str(error)


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
    except OSError as exc:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise VexError(f"cannot write {path}: {exc}") from exc


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
                   help="OpenVEX author: the organization issuing the statements")
    p.add_argument("--product", metavar="ID",
                   help="OpenVEX: wrap components as subcomponents of this product (purl/IRI)")
    p.add_argument("--no-comments", action="store_true",
                   help="leave mitigation comments out of the VEX (state and reason stay)")
    p.add_argument("--report", action="store_true", help="print a summary to stdout")
    p.add_argument("--no-validate", action="store_true", help="skip schema validation")
    p.add_argument("--indent", type=int, default=2, help="output indent (default 2)")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return p


def main(argv: Optional[List[str]] = None) -> int:
    """CLI entry point; returns the process exit code."""
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
        pairs, base, report = correlate(bom, findings, comments=not args.no_comments)
        indent = max(args.indent, 0)
        if args.format == "openvex":
            doc = build_openvex(bom, pairs, base, report, args.author, args.product)
            errs = check_openvex(doc)
            if args.author == "Unknown":
                report.warnings.append("OpenVEX author is 'Unknown'; set --author")
            text = json.dumps(doc, indent=indent or None, ensure_ascii=False) + "\n"
            label = "OpenVEX 0.2.0"
        else:
            doc = build_cdx(bom, pairs, base, report)
            errs = check_cdx(doc, bom)
            if args.output_format == "xml":
                text = cdx_to_xml(doc, indent)
            else:
                text = json.dumps(doc, indent=indent or None, ensure_ascii=False) + "\n"
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
    if args.report:
        print(report.format(label))
    else:
        for w in report.warnings:
            print(f"warning: {w}", file=sys.stderr)
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
