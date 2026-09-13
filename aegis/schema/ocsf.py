"""OCSF v1.x Pydantic models used throughout AEGIS.

Scope: the two Findings-category classes AEGIS ingests (``security_finding`` class_uid 2001,
``detection_finding`` class_uid 2004) plus the objects they embed. Field names, ``*_id`` enum
values and ``class_uid``/``category_uid`` constants follow the OCSF 1.3 schema
(https://schema.ocsf.io). Models are hand-curated from the OCSF JSON schema so that mypy --strict
and pydantic validation apply; unknown extra fields are preserved (``extra="allow"``) so no source
detail is lost during normalisation.

Conventions
-----------
* Every ``*_id`` enum has a sibling ``*`` string label that OCSF allows to be derived; helper
  ``with_labels()`` fills the labels from the ids.
* Timestamps are timezone-aware ``datetime``; OCSF's epoch-millis ``time`` is exposed via
  ``time_ms``.
* ``unmapped`` carries source fields that have no OCSF home (OCSF sanctioned escape hatch).
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from enum import IntEnum
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

OCSF_VERSION = "1.3.0"


# --------------------------------------------------------------------------------------------
# Enumerations (OCSF dictionary values)
# --------------------------------------------------------------------------------------------
class CategoryUid(IntEnum):
    SYSTEM_ACTIVITY = 1
    FINDINGS = 2
    IAM = 3
    NETWORK_ACTIVITY = 4
    DISCOVERY = 5
    APPLICATION_ACTIVITY = 6


class ClassUid(IntEnum):
    SECURITY_FINDING = 2001
    VULNERABILITY_FINDING = 2002
    COMPLIANCE_FINDING = 2003
    DETECTION_FINDING = 2004
    INCIDENT_FINDING = 2005


class SeverityId(IntEnum):
    UNKNOWN = 0
    INFORMATIONAL = 1
    LOW = 2
    MEDIUM = 3
    HIGH = 4
    CRITICAL = 5
    FATAL = 6
    OTHER = 99


SEVERITY_LABEL: dict[int, str] = {
    0: "Unknown",
    1: "Informational",
    2: "Low",
    3: "Medium",
    4: "High",
    5: "Critical",
    6: "Fatal",
    99: "Other",
}


class StatusId(IntEnum):
    UNKNOWN = 0
    NEW = 1
    IN_PROGRESS = 2
    SUPPRESSED = 3
    RESOLVED = 4
    OTHER = 99


class ActivityId(IntEnum):
    """Activity for Findings classes."""

    UNKNOWN = 0
    CREATE = 1
    UPDATE = 2
    CLOSE = 3
    OTHER = 99


class ConfidenceId(IntEnum):
    UNKNOWN = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    OTHER = 99


class ImpactId(IntEnum):
    UNKNOWN = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4
    OTHER = 99


class RiskLevelId(IntEnum):
    INFO = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class ObservableTypeId(IntEnum):
    """OCSF ``observable.type_id`` dictionary (subset that a SOC agent extracts)."""

    UNKNOWN = 0
    HOSTNAME = 1
    IP_ADDRESS = 2
    MAC_ADDRESS = 3
    USER_NAME = 4
    EMAIL_ADDRESS = 5
    URL_STRING = 6
    FILE_NAME = 7
    HASH = 8
    PROCESS_NAME = 9
    RESOURCE_UID = 10
    PORT = 11
    SUBNET = 12
    COMMAND_LINE = 13
    COUNTRY = 14
    PROCESS_ID = 15
    HTTP_USER_AGENT = 16
    CWE_OBJECT_UID = 17
    CVE_UID = 18
    USER_CREDENTIAL_UID = 19
    ENDPOINT = 20
    USER = 21
    EMAIL = 22
    URL = 23
    FILE = 24
    PROCESS = 25
    GEO_LOCATION = 26
    CONTAINER = 27
    REGISTRY_KEY = 28
    REGISTRY_VALUE = 29
    FINGERPRINT = 30
    OTHER = 99


OBSERVABLE_LABEL: dict[int, str] = {
    0: "Unknown",
    1: "Hostname",
    2: "IP Address",
    3: "MAC Address",
    4: "User Name",
    5: "Email Address",
    6: "URL String",
    7: "File Name",
    8: "Hash",
    9: "Process Name",
    10: "Resource UID",
    11: "Port",
    12: "Subnet",
    13: "Command Line",
    14: "Country",
    15: "Process ID",
    16: "HTTP User-Agent",
    17: "CWE Object: uid",
    18: "CVE Object: uid",
    19: "User Credential ID",
    20: "Endpoint",
    21: "User",
    22: "Email",
    23: "Uniform Resource Locator",
    24: "File",
    25: "Process",
    26: "Geo Location",
    27: "Container",
    28: "Registry Key",
    29: "Registry Value",
    30: "Fingerprint",
    99: "Other",
}


# --------------------------------------------------------------------------------------------
# Base
# --------------------------------------------------------------------------------------------
class OCSFObject(BaseModel):
    """Base for every OCSF object: tolerant of extra fields, strict on declared types."""

    model_config = ConfigDict(extra="allow", populate_by_name=True, validate_assignment=True)


# --------------------------------------------------------------------------------------------
# Objects
# --------------------------------------------------------------------------------------------
class Product(OCSFObject):
    name: str | None = None
    vendor_name: str | None = None
    version: str | None = None
    uid: str | None = None
    feature: dict[str, Any] | None = None


class Extension(OCSFObject):
    name: str
    uid: str
    version: str


class Metadata(OCSFObject):
    version: str = OCSF_VERSION
    product: Product
    profiles: list[str] = Field(default_factory=list)
    uid: str | None = None
    correlation_uid: str | None = None
    event_code: str | None = None
    original_time: str | None = None
    logged_time: datetime | None = None
    log_name: str | None = None
    log_provider: str | None = None
    labels: list[str] = Field(default_factory=list)
    extensions: list[Extension] = Field(default_factory=list)


class Tactic(OCSFObject):
    uid: str  # "TA0006"
    name: str | None = None
    src_url: str | None = None


class Technique(OCSFObject):
    uid: str  # "T1003.001"
    name: str | None = None
    src_url: str | None = None

    @field_validator("uid")
    @classmethod
    def _norm(cls, v: str) -> str:
        v = v.strip().upper()
        if not v.startswith("T") or not v[1:].replace(".", "").isdigit():
            raise ValueError(f"not an ATT&CK technique id: {v!r}")
        return v

    @property
    def parent(self) -> str:
        return self.uid.split(".")[0]


class Attack(OCSFObject):
    """MITRE ATT&CK mapping."""

    technique: Technique | None = None
    sub_technique: Technique | None = None
    tactic: Tactic | None = None
    tactics: list[Tactic] = Field(default_factory=list)
    version: str | None = None


class Analytic(OCSFObject):
    """The rule / model that produced the finding."""

    name: str | None = None
    uid: str | None = None
    type: str | None = None  # "Rule", "Behavioral", "Statistical", "Learning (ML/DL)"
    type_id: int | None = None
    category: str | None = None
    desc: str | None = None
    version: str | None = None
    related_analytics: list[Analytic] = Field(default_factory=list)


class KillChainPhase(OCSFObject):
    phase: str | None = None
    phase_id: int | None = None


class FindingInfo(OCSFObject):
    title: str
    uid: str
    desc: str | None = None
    types: list[str] = Field(default_factory=list)
    analytic: Analytic | None = None
    attacks: list[Attack] = Field(default_factory=list)
    kill_chain: list[KillChainPhase] = Field(default_factory=list)
    created_time: datetime | None = None
    modified_time: datetime | None = None
    first_seen_time: datetime | None = None
    last_seen_time: datetime | None = None
    data_sources: list[str] = Field(default_factory=list)
    product_uid: str | None = None
    related_events: list[dict[str, Any]] = Field(default_factory=list)
    src_url: str | None = None

    @property
    def technique_ids(self) -> list[str]:
        out: list[str] = []
        for a in self.attacks:
            for t in (a.sub_technique, a.technique):
                if t is not None and t.uid not in out:
                    out.append(t.uid)
        return out


class Account(OCSFObject):
    name: str | None = None
    type: str | None = None
    type_id: int | None = None
    uid: str | None = None


class User(OCSFObject):
    name: str | None = None
    uid: str | None = None
    domain: str | None = None
    email_addr: str | None = None
    full_name: str | None = None
    type: str | None = None
    type_id: int | None = None
    account: Account | None = None
    groups: list[dict[str, Any]] = Field(default_factory=list)


class Fingerprint(OCSFObject):
    algorithm: str  # "MD5" | "SHA-1" | "SHA-256" | "SHA-512" | "IMPHASH" ...
    algorithm_id: int | None = None
    value: str

    @field_validator("value")
    @classmethod
    def _lower(cls, v: str) -> str:
        return v.strip().lower()


class File(OCSFObject):
    name: str | None = None
    path: str | None = None
    type: str | None = None
    type_id: int | None = None
    hashes: list[Fingerprint] = Field(default_factory=list)
    size: int | None = None
    signature: dict[str, Any] | None = None
    company_name: str | None = None
    product: Product | None = None
    parent_folder: str | None = None
    mime_type: str | None = None


class Process(OCSFObject):
    pid: int | None = None
    uid: str | None = None  # process GUID
    name: str | None = None
    cmd_line: str | None = None
    file: File | None = None
    user: User | None = None
    created_time: datetime | None = None
    terminated_time: datetime | None = None
    integrity: str | None = None
    parent_process: Process | None = None
    session: dict[str, Any] | None = None


class OS(OCSFObject):
    name: str | None = None
    type: str | None = None
    type_id: int | None = None
    version: str | None = None
    build: str | None = None


class NetworkInterface(OCSFObject):
    name: str | None = None
    ip: str | None = None
    mac: str | None = None
    type: str | None = None
    type_id: int | None = None


class Device(OCSFObject):
    hostname: str | None = None
    name: str | None = None
    uid: str | None = None
    ip: str | None = None
    mac: str | None = None
    domain: str | None = None
    type: str | None = None
    type_id: int | None = None
    os: OS | None = None
    network_interfaces: list[NetworkInterface] = Field(default_factory=list)
    is_managed: bool | None = None
    # Lab CMDB extension (profile "aegis_asset") — asset criticality is used by playbook choice.
    criticality: Literal["critical", "high", "medium", "low"] | None = None
    owner: User | None = None
    zone: str | None = None


class Location(OCSFObject):
    city: str | None = None
    country: str | None = None
    coordinates: list[float] | None = None
    continent: str | None = None
    is_on_premises: bool | None = None


class NetworkEndpoint(OCSFObject):
    hostname: str | None = None
    ip: str | None = None
    port: int | None = None
    mac: str | None = None
    domain: str | None = None
    uid: str | None = None
    name: str | None = None
    location: Location | None = None
    intermediate_ips: list[str] = Field(default_factory=list)
    svc_name: str | None = None
    type: str | None = None
    type_id: int | None = None


class Session(OCSFObject):
    uid: str | None = None
    created_time: datetime | None = None
    is_remote: bool | None = None
    issuer: str | None = None


class Actor(OCSFObject):
    process: Process | None = None
    user: User | None = None
    session: Session | None = None
    invoked_by: str | None = None
    idp: dict[str, Any] | None = None
    authorizations: list[dict[str, Any]] = Field(default_factory=list)


class RegistryKey(OCSFObject):
    path: str
    is_system: bool | None = None
    modified_time: datetime | None = None


class RegistryValue(OCSFObject):
    name: str | None = None
    path: str | None = None
    data: str | None = None
    type: str | None = None
    type_id: int | None = None


class Url(OCSFObject):
    url_string: str | None = None
    hostname: str | None = None
    path: str | None = None
    port: int | None = None
    query_string: str | None = None
    scheme: str | None = None


class Container(OCSFObject):
    name: str | None = None
    uid: str | None = None
    image: dict[str, Any] | None = None


class Reputation(OCSFObject):
    base_score: float | None = None
    provider: str | None = None
    score: str | None = None
    score_id: int | None = None


class Observable(OCSFObject):
    """An entity extracted from the finding that the agent can pivot on."""

    name: str  # OCSF attribute path, e.g. "actor.process.cmd_line" or "device.hostname"
    type_id: ObservableTypeId
    type: str | None = None
    value: str | None = None
    reputation: Reputation | None = None

    @model_validator(mode="after")
    def _label(self) -> Observable:
        if self.type is None:
            self.type = OBSERVABLE_LABEL.get(int(self.type_id), "Other")
        return self


class Enrichment(OCSFObject):
    """TI / asset / identity enrichment attached to a finding.

    ``data`` is treated as *data* (never instructions) when serialised for an LLM — see §4/§9.
    """

    name: str
    value: str
    data: dict[str, Any]
    provider: str | None = None
    type: str | None = None
    created_time: datetime | None = None


class Evidences(OCSFObject):
    """OCSF ``evidences`` object: the raw activity that triggered the detection."""

    actor: Actor | None = None
    process: Process | None = None
    file: File | None = None
    api: dict[str, Any] | None = None
    connection_info: dict[str, Any] | None = None
    src_endpoint: NetworkEndpoint | None = None
    dst_endpoint: NetworkEndpoint | None = None
    device: Device | None = None
    user: User | None = None
    url: Url | None = None
    reg_key: RegistryKey | None = None
    reg_value: RegistryValue | None = None
    container: Container | None = None
    query: dict[str, Any] | None = None
    data: dict[str, Any] | None = None  # raw source event(s) verbatim
    # AEGIS extension: the SIEM document id(s) so EvidenceRef can resolve to a real document.
    event_uids: list[str] = Field(default_factory=list)


class Remediation(OCSFObject):
    desc: str
    kb_article_list: list[dict[str, Any]] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)


class Vulnerability(OCSFObject):
    desc: str | None = None
    cve: dict[str, Any] | None = None
    severity: str | None = None
    title: str | None = None


# --------------------------------------------------------------------------------------------
# Base Event and Findings classes
# --------------------------------------------------------------------------------------------
class BaseEvent(OCSFObject):
    """OCSF base event. Subclasses pin ``category_uid`` / ``class_uid``."""

    category_uid: CategoryUid
    class_uid: ClassUid
    activity_id: ActivityId = ActivityId.CREATE
    type_uid: int | None = None  # class_uid * 100 + activity_id
    time: datetime
    metadata: Metadata
    severity_id: SeverityId = SeverityId.UNKNOWN
    severity: str | None = None
    status_id: StatusId = StatusId.NEW
    status: str | None = None
    status_detail: str | None = None
    message: str | None = None
    observables: list[Observable] = Field(default_factory=list)
    enrichments: list[Enrichment] = Field(default_factory=list)
    raw_data: str | None = None
    unmapped: dict[str, Any] = Field(default_factory=dict)
    timezone_offset: int | None = None
    count: int = 1
    duration: int | None = None
    start_time: datetime | None = None
    end_time: datetime | None = None
    category_name: str | None = None
    class_name: str | None = None
    activity_name: str | None = None
    type_name: str | None = None

    @field_validator("time", "start_time", "end_time", mode="after")
    @classmethod
    def _aware(cls, v: datetime | None) -> datetime | None:
        if v is not None and v.tzinfo is None:
            return v.replace(tzinfo=UTC)
        return v

    @model_validator(mode="after")
    def _derive(self) -> BaseEvent:
        if self.type_uid is None:
            self.type_uid = int(self.class_uid) * 100 + int(self.activity_id)
        if self.severity is None:
            self.severity = SEVERITY_LABEL.get(int(self.severity_id))
        if self.status is None:
            self.status = self.status_id.name.replace("_", " ").title()
        if self.activity_name is None:
            self.activity_name = self.activity_id.name.title()
        return self

    @property
    def time_ms(self) -> int:
        return int(self.time.timestamp() * 1000)

    def content_hash(self) -> str:
        """Stable hash of the semantic content (used for dedupe and LLM-call caching)."""
        payload = self.model_dump(mode="json", exclude={"metadata": {"logged_time"}})
        return hashlib.sha256(
            json.dumps(payload, sort_keys=True, default=str).encode("utf-8")
        ).hexdigest()


class SecurityFinding(BaseEvent):
    """OCSF ``security_finding`` (2001) — legacy generic finding class."""

    category_uid: CategoryUid = CategoryUid.FINDINGS
    class_uid: ClassUid = ClassUid.SECURITY_FINDING
    class_name: str | None = "Security Finding"
    category_name: str | None = "Findings"
    finding: FindingInfo
    analytic: Analytic | None = None
    attacks: list[Attack] = Field(default_factory=list)
    state_id: int | None = None
    state: str | None = None
    confidence_id: ConfidenceId | None = None
    confidence_score: int | None = None
    impact_id: ImpactId | None = None
    impact_score: int | None = None
    risk_level_id: RiskLevelId | None = None
    risk_score: int | None = None
    resources: list[dict[str, Any]] = Field(default_factory=list)
    process: Process | None = None
    malware: list[dict[str, Any]] = Field(default_factory=list)
    vulnerabilities: list[Vulnerability] = Field(default_factory=list)
    compliance: dict[str, Any] | None = None
    data_sources: list[str] = Field(default_factory=list)
    evidence: dict[str, Any] | None = None
    nist: list[str] = Field(default_factory=list)


class DetectionFinding(BaseEvent):
    """OCSF ``detection_finding`` (2004) — the canonical alert type inside AEGIS."""

    category_uid: CategoryUid = CategoryUid.FINDINGS
    class_uid: ClassUid = ClassUid.DETECTION_FINDING
    class_name: str | None = "Detection Finding"
    category_name: str | None = "Findings"
    finding_info: FindingInfo
    evidences: list[Evidences] = Field(default_factory=list)
    confidence_id: ConfidenceId | None = None
    confidence_score: int | None = None
    impact_id: ImpactId | None = None
    impact_score: int | None = None
    risk_level_id: RiskLevelId | None = None
    risk_score: int | None = None
    risk_details: str | None = None
    resources: list[dict[str, Any]] = Field(default_factory=list)
    device: Device | None = None
    actor: Actor | None = None
    remediation: Remediation | None = None
    vulnerabilities: list[Vulnerability] = Field(default_factory=list)
    malware: list[dict[str, Any]] = Field(default_factory=list)
    is_alert: bool = True
    disposition: str | None = None
    disposition_id: int | None = None
    comment: str | None = None

    # ------------------------------------------------------------------ helpers
    @property
    def alert_id(self) -> str:
        return self.finding_info.uid

    @property
    def technique_ids(self) -> list[str]:
        return self.finding_info.technique_ids

    def observable_values(self, *types: ObservableTypeId) -> list[str]:
        wanted = set(types) or set(ObservableTypeId)
        return [o.value for o in self.observables if o.type_id in wanted and o.value]

    def hostnames(self) -> list[str]:
        vals = self.observable_values(ObservableTypeId.HOSTNAME)
        if self.device and self.device.hostname and self.device.hostname not in vals:
            vals.append(self.device.hostname)
        return vals

    def user_names(self) -> list[str]:
        vals = self.observable_values(ObservableTypeId.USER_NAME)
        if (
            self.actor
            and self.actor.user
            and self.actor.user.name
            and self.actor.user.name not in vals
        ):
            vals.append(self.actor.user.name)
        return vals

    def free_text_fields(self) -> dict[str, str]:
        """Every attacker-influenceable free-text field (for the injection guard, §9.3)."""
        out: dict[str, str] = {}
        if self.message:
            out["message"] = self.message
        if self.finding_info.desc:
            out["finding_info.desc"] = self.finding_info.desc
        out["finding_info.title"] = self.finding_info.title
        for o in self.observables:
            if o.value:
                out[f"observables[{o.name}]"] = o.value
        for i, ev in enumerate(self.evidences):
            proc = ev.process or (ev.actor.process if ev.actor else None)
            if proc and proc.cmd_line:
                out[f"evidences[{i}].process.cmd_line"] = proc.cmd_line
            if ev.file and ev.file.path:
                out[f"evidences[{i}].file.path"] = ev.file.path
        return out


OCSFFinding = SecurityFinding | DetectionFinding


def new_metadata(product: str, vendor: str, version: str | None = None, **kw: Any) -> Metadata:
    return Metadata(product=Product(name=product, vendor_name=vendor, version=version), **kw)


def utcnow() -> datetime:
    return datetime.now(tz=UTC)
