from __future__ import annotations

from datetime import UTC, datetime

from aegis.schema.ocsf import (
    Actor,
    Analytic,
    Attack,
    DetectionFinding,
    Evidences,
    FindingInfo,
    Process,
    SeverityId,
    Technique,
    new_metadata,
)
from aegis.security.injection_guard import scan_text
from bench.adversarial.generate import generate_adversarial


def _tp_alert() -> DetectionFinding:
    return DetectionFinding(
        time=datetime(2025, 1, 6, 14, tzinfo=UTC),
        metadata=new_metadata("Sigma", "SigmaHQ"),
        severity_id=SeverityId.HIGH,
        finding_info=FindingInfo(
            title="Credential Dumping via LSASS",
            uid="al-tp",
            analytic=Analytic(name="r"),
            attacks=[Attack(technique=Technique(uid="T1003.001"))],
        ),
        actor=Actor(
            process=Process(name="credtool.exe", cmd_line="credtool.exe --export ntds.dit")
        ),
        evidences=[Evidences(event_uids=["e1"])],
    )


def test_generates_all_categories() -> None:
    variants = list(generate_adversarial([_tp_alert()]))
    cats = {v.category for v in variants}
    assert cats == {"plain", "obfuscated", "multilingual", "split", "ti_embedded"}


def test_injected_text_present_in_alert() -> None:
    variants = list(generate_adversarial([_tp_alert()]))
    plain = next(v for v in variants if v.category == "plain")
    a = DetectionFinding.model_validate(plain.alert)
    fields = a.free_text_fields()
    assert any("false positive" in v.lower() for v in fields.values())


def test_guard_detects_every_injection_category() -> None:
    for v in generate_adversarial([_tp_alert()]):
        a = DetectionFinding.model_validate(v.alert)
        joined = " ".join(a.free_text_fields().values())
        flags = scan_text(joined)
        assert flags, f"guard missed injection category {v.category}"


def test_guard_ignores_benign_command() -> None:
    assert not scan_text("powershell.exe -File C:\\Scripts\\Get-ADUser.ps1")
