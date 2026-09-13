"""Evaluate a Sigma rule's detection logic directly against an ECS event (SPEC §5, §8.1).

This is how AEGIS manufactures *real* alerts from lab telemetry: a rule that matches an event
produces a ``detection_finding`` whose triggering ``event_id`` is recorded, so every alert is
grounded in a document that ``EvidenceRef``s can resolve to. Ground-truth windows then label each
alert TP/FP.

It is a compact, dependency-light evaluator that supports the Sigma constructs the curated pack
actually uses: field/value maps with modifiers (``contains``, ``startswith``, ``endswith``, ``all``,
``re``, ``cased``, ``windash``, ``exists``, numeric ``lt/lte/gt/gte``), list-valued OR semantics,
null matching, and condition expressions with ``and``/``or``/``not``, parentheses, and the
``N of <glob>`` / ``all of <glob>`` / ``all of them`` aggregations.

Rules whose logsource does not correspond to the event's category, or that use a modifier we do not
implement (e.g. base64), simply do not match - a safe, conservative default (no spurious alert).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

import yaml

# Sigma field name -> ECS flat attribute on our event dict (lab.common.ecs.EcsEvent.to_row keys).
FIELD_MAP: dict[str, tuple[str, ...]] = {
    "Image": ("process_executable",),
    "OriginalFileName": ("process_name",),
    "CommandLine": ("process_command_line",),
    "ParentImage": ("process_parent_executable",),
    "ParentCommandLine": ("process_parent_command_line",),
    "ProcessId": ("process_pid",),
    "ParentProcessId": ("process_parent_pid",),
    "User": ("user_name",),
    "TargetUserName": ("user_target_name",),
    "SubjectUserName": ("user_name",),
    "IntegrityLevel": ("process_integrity_level",),
    "Hashes": ("process_hash_sha256", "process_hash_md5", "process_hash_imphash"),
    "sha256": ("process_hash_sha256", "file_hash_sha256"),
    "md5": ("process_hash_md5",),
    "Imphash": ("process_hash_imphash",),
    "TargetFilename": ("file_path",),
    "Filename": ("file_name",),
    "TargetObject": ("registry_path",),
    "Details": ("registry_data",),
    "ImageLoaded": ("file_path",),
    "QueryName": ("dns_question_name",),
    "DestinationIp": ("destination_ip",),
    "DestinationPort": ("destination_port",),
    "SourceIp": ("source_ip",),
    "DestinationHostname": ("dns_question_name",),
    "ServiceName": ("service_name",),
    "ServiceFileName": ("process_executable",),
    "ScriptBlockText": ("script_block_text",),
    "Message": ("message",),
    "EventID": ("event_code",),
    "Channel": ("event_channel",),
    "Provider_Name": ("event_provider",),
    "Computer": ("host_name",),
    "LogonType": ("logon_type",),
    "TaskName": ("task_name",),
    "IpAddress": ("source_ip",),
    "Product": (),  # metadata not in our ECS row -> never matches (safe)
}

# Sigma logsource category -> acceptable (event_category, {actions}) on our events.
CATEGORY_MAP: dict[str, set[str]] = {
    "process_creation": {"process_created"},
    "image_load": {"image_loaded"},
    "process_access": {"process_access"},
    "file_event": {"file_created", "file_delete"},
    "file_change": {"file_created"},
    "registry_set": {"registry_value_set"},
    "registry_add": {"registry_object_added"},
    "registry_event": {"registry_value_set", "registry_object_added"},
    "registry_delete": {"registry_object_added"},
    "network_connection": {"network_connection"},
    "dns_query": {"dns_query"},
    "dns": {"dns_query"},
    "pipe_created": {"pipe_created"},
    "ps_script": {"script_block_logged"},
    "ps_module": {"module_logged"},
    "create_remote_thread": {"create_remote_thread"},
    "create_stream_hash": {"file_created"},
}
SERVICE_CHANNELS: dict[str, set[str]] = {
    "security": {"Security"},
    "system": {"System"},
    "powershell": {"Microsoft-Windows-PowerShell/Operational", "Windows PowerShell"},
    "powershell-classic": {"Windows PowerShell"},
    "sysmon": {"Microsoft-Windows-Sysmon/Operational"},
}


@dataclass(frozen=True)
class SigmaMatch:
    rule_id: str
    title: str
    level: str
    techniques: tuple[str, ...]
    tactics: tuple[str, ...]
    matched_fields: tuple[str, ...]


class CompiledRule:
    """A Sigma rule pre-parsed for fast repeated matching."""

    __slots__ = (
        "condition",
        "description",
        "detection",
        "id",
        "level",
        "logsource",
        "status",
        "tactics",
        "techniques",
        "title",
    )

    def __init__(self, doc: dict[str, Any]) -> None:
        self.id = str(doc.get("id", doc.get("title", "")))
        self.title = str(doc.get("title", ""))
        self.level = str(doc.get("level", "medium")).lower()
        self.status = str(doc.get("status", "test")).lower()
        self.description = doc.get("description")
        tags = [str(t) for t in doc.get("tags") or []]
        self.techniques = tuple(
            t.split(".", 1)[1].upper()
            for t in tags
            if t.startswith("attack.t") and t[8:9].isdigit()
        )
        self.tactics = tuple(
            t.split(".", 1)[1]
            for t in tags
            if t.startswith("attack.") and not t.lower().startswith("attack.t")
        )
        self.logsource = {k: str(v).lower() for k, v in (doc.get("logsource") or {}).items()}
        detection = dict(doc.get("detection") or {})
        self.condition = str(detection.pop("condition", ""))
        self.detection = detection  # remaining keys are search identifiers

    # -------------------------------------------------------------- logsource gate
    def logsource_ok(self, event: dict[str, Any]) -> bool:
        cat = self.logsource.get("category")
        svc = self.logsource.get("service")
        if cat and cat in CATEGORY_MAP and event.get("event_action") not in CATEGORY_MAP[cat]:
            return False
        if (
            svc
            and svc in SERVICE_CHANNELS
            and event.get("event_channel") not in SERVICE_CHANNELS[svc]
        ):
            return False
        # Too broad to match safely without a category or service.
        return bool(cat or svc)

    def matches(self, event: dict[str, Any]) -> SigmaMatch | None:
        if not self.logsource_ok(event) or not self.condition:
            return None
        matched_fields: set[str] = set()
        results = {
            sid: _eval_search(search, event, matched_fields)
            for sid, search in self.detection.items()
        }
        try:
            fired = _eval_condition(self.condition, results)
        except (ValueError, KeyError):
            return None
        if not fired:
            return None
        return SigmaMatch(
            self.id,
            self.title,
            self.level,
            self.techniques,
            self.tactics,
            tuple(sorted(matched_fields)),
        )


# ------------------------------------------------------------------------------------------------
# search-identifier evaluation
# ------------------------------------------------------------------------------------------------
def _event_values(field: str, event: dict[str, Any]) -> list[str]:
    attrs = FIELD_MAP.get(field)
    if attrs is None:
        # Unknown field -> try snake_case direct hit, else no value (won't match).
        attrs = (field.lower(),) if field.lower() in event else ()
    out: list[str] = []
    for a in attrs:
        v = event.get(a)
        if v is not None:
            out.append(str(v))
    return out


def _match_scalar(field: str, spec: Any, event: dict[str, Any], matched: set[str]) -> bool:
    base, _, mods_str = field.partition("|")
    mods = mods_str.split("|") if mods_str else []
    values = _event_values(base, event)

    if "exists" in mods:
        want = spec if isinstance(spec, bool) else str(spec).lower() == "true"
        present = bool(values)
        if present == want:
            matched.add(base)
            return True
        return False

    if spec is None:  # field: null  -> matches when absent/empty
        if not values:
            matched.add(base)
            return True
        return False

    candidates = spec if isinstance(spec, list) else [spec]
    numeric_mods = {"lt", "lte", "gt", "gte"} & set(mods)
    for ev in values:
        for want in candidates:
            if numeric_mods:
                if _num_cmp(ev, want, next(iter(numeric_mods))):
                    matched.add(base)
                    return True
                continue
            if _str_match(ev, str(want), mods):
                matched.add(base)
                return True
    return False


def _num_cmp(ev: str, want: Any, op: str) -> bool:
    try:
        a, b = float(ev), float(want)
    except (TypeError, ValueError):
        return False
    return {"lt": a < b, "lte": a <= b, "gt": a > b, "gte": a >= b}[op]


def _str_match(ev: str, want: str, mods: list[str]) -> bool:
    cased = "cased" in mods
    hay = ev if cased else ev.lower()
    needle = want if cased else want.lower()
    if "windash" in mods:
        hay = hay.replace(chr(0x2F), chr(0x2D)).replace(chr(0x2013), chr(0x2D))
        needle = needle.replace("/", "-")
    if "re" in mods:
        flags = 0 if cased else re.IGNORECASE
        try:
            return re.search(want, ev, flags) is not None
        except re.error:
            return False
    if "contains" in mods:
        return needle in hay
    if "startswith" in mods:
        return hay.startswith(needle)
    if "endswith" in mods:
        return hay.endswith(needle)
    # Sysmon Hashes field is "ALGO=hash,..."; allow substring for hash equality checks.
    if len(needle) in (32, 40, 64) and "=" not in needle:
        return needle in hay
    return hay == needle


def _eval_search(search: Any, event: dict[str, Any], matched: set[str]) -> bool:
    """A search identifier is a dict (AND of fields, each maybe |all) or a list (OR of maps)."""
    if isinstance(search, list):
        # list of maps or plain values -> OR
        for item in search:
            if isinstance(item, dict):
                if _eval_map(item, event, matched):
                    return True
            else:
                # keywords: match against message/cmdline anywhere
                if _keyword_match(str(item), event, matched):
                    return True
        return False
    if isinstance(search, dict):
        return _eval_map(search, event, matched)
    return False


def _eval_map(m: dict[str, Any], event: dict[str, Any], matched: set[str]) -> bool:
    for field, spec in m.items():
        is_all = field.endswith("|all") or "|all" in field
        if isinstance(spec, list) and is_all:
            base = field.replace("|all", "")
            if not all(_match_scalar(base, s, event, matched) for s in spec):
                return False
        else:
            if not _match_scalar(field, spec, event, matched):
                return False
    return True


def _keyword_match(kw: str, event: dict[str, Any], matched: set[str]) -> bool:
    hay = " ".join(
        str(event.get(a, ""))
        for a in (
            "process_command_line",
            "message",
            "script_block_text",
            "process_parent_command_line",
        )
    ).lower()
    if kw.lower() in hay:
        matched.add("keyword")
        return True
    return False


# ------------------------------------------------------------------------------------------------
# condition expression evaluation
# ------------------------------------------------------------------------------------------------
_TOKEN_RE = re.compile(r"\(|\)|\b(?:and|or|not)\b|[^\s()]+", re.IGNORECASE)


def _resolve_glob(pattern: str, results: dict[str, bool]) -> list[bool]:
    if pattern == "them":
        return list(results.values())
    if pattern.endswith("*"):
        pre = pattern[:-1]
        return [v for k, v in results.items() if k.startswith(pre)]
    return [results[pattern]] if pattern in results else [False]


def _eval_condition(condition: str, results: dict[str, bool]) -> bool:
    tokens: list[str] = _TOKEN_RE.findall(condition)
    pos = 0

    def peek() -> str | None:
        return tokens[pos] if pos < len(tokens) else None

    def nxt() -> str:
        nonlocal pos
        t = tokens[pos]
        pos += 1
        return t

    def parse_or() -> bool:
        val = parse_and()
        while peek() and peek().lower() == "or":  # type: ignore[union-attr]
            nxt()
            val = parse_and() or val
        return val

    def parse_and() -> bool:
        val = parse_not()
        while peek() and peek().lower() == "and":  # type: ignore[union-attr]
            nxt()
            val = parse_not() and val
        return val

    def parse_not() -> bool:
        if peek() and peek().lower() == "not":  # type: ignore[union-attr]
            nxt()
            return not parse_not()
        return parse_atom()

    def parse_atom() -> bool:
        t = peek()
        if t == "(":
            nxt()
            val = parse_or()
            if peek() == ")":
                nxt()
            return val
        # aggregation: "<N|all> of <glob>"
        if t and (t.isdigit() or t.lower() == "all"):
            quant = nxt()
            if peek() and peek().lower() == "of":  # type: ignore[union-attr]
                nxt()
                glob = nxt()
                vals = _resolve_glob(glob, results)
                if quant.lower() == "all":
                    return all(vals) and len(vals) > 0
                return sum(vals) >= int(quant)
        ident = nxt()
        return results.get(ident, False)

    return parse_or()


class SigmaRuleset:
    """A set of compiled rules loaded from the pack JSONL, matched over events."""

    def __init__(self, rules: list[CompiledRule]) -> None:
        self.rules = rules

    @classmethod
    def from_pack(cls, pack_jsonl: Any, include_holdout: bool = False) -> SigmaRuleset:
        import json
        from pathlib import Path

        rules: list[CompiledRule] = []
        with Path(pack_jsonl).open(encoding="utf-8") as f:
            for line in f:
                if not line.strip():
                    continue
                rec = json.loads(line)
                if rec.get("holdout") and not include_holdout:
                    continue
                try:
                    doc = yaml.safe_load(rec["yaml"])
                except yaml.YAMLError:
                    continue
                if isinstance(doc, dict) and "detection" in doc:
                    rules.append(CompiledRule(doc))
        return cls(rules)

    @classmethod
    def from_yaml_docs(cls, docs: list[dict[str, Any]]) -> SigmaRuleset:
        return cls([CompiledRule(d) for d in docs if "detection" in d])

    def match_event(self, event: dict[str, Any]) -> list[SigmaMatch]:
        out: list[SigmaMatch] = []
        for rule in self.rules:
            m = rule.matches(event)
            if m is not None:
                out.append(m)
        return out

    def __len__(self) -> int:
        return len(self.rules)
