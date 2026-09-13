"""Build false-positive alerts directly from benign-noise episodes (SPEC §5.4, §8.1).

Sigma-matching benign telemetry yields few and undiverse false positives, because good benign
activity rarely matches attack rules exactly. But the noise generators *know* what benign activity
they produced, so each episode is turned into the detection a rule-based SIEM would realistically
raise on it - a genuine false positive with a known ``fp_type``. The alert's triggering event is the
episode's most alarming real event, so tools can still query and cite it.

This is not fabrication: these are exactly the look-alike benign activities (legit procdump, admin
PsExec, authenticated vuln scans, backup VSS, software deployment) that generate the bulk of a real
SOC's false positives.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import UTC, datetime, timedelta

from lab.common.ecs import EcsEvent
from lab.common.winevent import map_windows_event
from lab.noise.generators import NoiseContext, Org, generate, sysmon_process

from aegis.ingest.generate import AlertRecord
from aegis.schema.normalize.sigma import finding_from_sigma
from aegis.schema.normalize.sigma_match import SigmaMatch

# Benchmark noise config - MUST match the noise that is materialised into the snapshot so the
# investigation can find the surrounding benign/ambiguous events and cite them.
BENCH_NOISE_SEED = 1337
BENCH_NOISE_DAYS = 90
BENCH_NOISE_PER_DAY = 24
AMBIGUOUS_SEED = 4242

# fp_type -> (detection rule title, ATT&CK technique(s), severity level, which event to alert on)
FP_TYPE_RULE: dict[str, tuple[str, tuple[str, ...], str]] = {
    "admin_powershell": (
        "Suspicious PowerShell Encoded/Scripted Execution",
        ("T1059.001", "T1027"),
        "high",
    ),
    "psexec_admin": (
        "PsExec Service Installation / Remote Execution",
        ("T1569.002", "T1021.002"),
        "high",
    ),
    "vuln_scanner": ("Multiple Failed Logons - Possible Password Spray", ("T1110.003",), "high"),
    "backup_agent": ("Volume Shadow Copy Access / NTDS Handling", ("T1003.003", "T1490"), "high"),
    "software_deployment": ("Msiexec Remote Package Execution", ("T1218.007", "T1072"), "medium"),
    "dev_procdump": ("Suspicious ProcDump Usage Against a Process", ("T1003.001",), "high"),
    "service_account_lockout": (
        "Repeated Authentication Failures - Password Spray",
        ("T1110.003",),
        "high",
    ),
    "redteam_tool_name_benign": ("Offensive Security Tool Name Detected", ("T1588.002",), "high"),
    "scheduled_task_maintenance": (
        "Scheduled Task Creation via System Process",
        ("T1053.005",),
        "medium",
    ),
    "helpdesk_remote_support": (
        "Local Reconnaissance Commands After Remote Logon",
        ("T1087.001", "T1069.001"),
        "medium",
    ),
}

# The event within an episode that best represents the "detection": prefer a process-creation event
# whose command line is the alarming one.
_ALARM_PROC = {
    "admin_powershell": "powershell.exe",
    "psexec_admin": "psexec64.exe",
    "vuln_scanner": "cmd.exe",
    "backup_agent": "vssadmin.exe",
    "software_deployment": "msiexec.exe",
    "dev_procdump": "procdump64.exe",
    "service_account_lockout": None,
    "redteam_tool_name_benign": None,
    "scheduled_task_maintenance": "forfiles.exe",
    "helpdesk_remote_support": "net.exe",
}


def _pick_event(events: list[EcsEvent], fp_type: str) -> EcsEvent:
    want = _ALARM_PROC.get(fp_type)
    if want:
        for e in events:
            if (e.process_name or "").lower() == want:
                return e
    # else the last process-creation event, or just the last event
    procs = [e for e in events if e.event_action == "process_created"]
    return procs[-1] if procs else events[-1]


def generate_noise_fp_alerts(
    *,
    seed: int = BENCH_NOISE_SEED,
    days: int = BENCH_NOISE_DAYS,
    per_day: int = BENCH_NOISE_PER_DAY,
    start: datetime | None = None,
) -> Iterator[AlertRecord]:
    """Yield one false-positive ``AlertRecord`` per benign-noise episode."""
    for events, window in generate(seed=seed, days=days, episodes_per_day=per_day, start=start):
        if not events:
            continue
        fp_type = window.fp_type or "admin_powershell"
        rule_title, techniques, level = FP_TYPE_RULE.get(
            fp_type, ("Benign Administrative Activity", (), "medium")
        )
        ev = _pick_event(events, fp_type)
        row = {k: v for k, v in ev.to_row().items() if v is not None}
        row["@timestamp"] = ev.timestamp
        match = SigmaMatch(
            rule_id=f"fp:{fp_type}",
            title=rule_title,
            level=level,
            techniques=techniques,
            tactics=(),
            matched_fields=("Image",),
        )
        finding = finding_from_sigma(match, row, description=f"Detection raised on {fp_type}")
        yield AlertRecord(
            alert=finding,
            gold_label="false_positive",
            gold_techniques=[],
            fp_type=fp_type,
            scenario_id=f"noise:{fp_type}",
            dataset="noise",
            triggering_event_id=ev.event_id,
            rule_id=match.rule_id,
        )


# Ambiguous, borderline dual-use activity against sensitive targets -> gold escalate. The events are
# real benign-shaped telemetry with a genuinely alarming command line (procdump of lsass by a dev,
# psexec to a DC by helpdesk), so a human should look. Deterministic given AMBIGUOUS_SEED.
_AMBIGUOUS_TEMPLATES = [
    (
        "dev.kumar",
        "WS-DEV1",
        "C:\\Tools\\procdump64.exe",
        "procdump64.exe -accepteula -ma lsass.exe C:\\dumps\\lsass.dmp",
        "Credential Dumping via ProcDump on LSASS",
        ("T1003.001",),
    ),
    (
        "hd.singh",
        "DC01",
        "C:\\Tools\\PsExec64.exe",
        "PsExec64.exe \\\\DC01 -s cmd /c whoami",
        "PsExec Execution Against Domain Controller",
        ("T1569.002", "T1021.002"),
    ),
    (
        "adm.patel",
        "DC01",
        "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
        "powershell.exe -nop -w hidden -enc SQBFAFgAKAAuAC4AKQA=",
        "Encoded PowerShell on Domain Controller",
        ("T1059.001", "T1027"),
    ),
    (
        "adm.wu",
        "SQL01",
        "C:\\Windows\\System32\\vssadmin.exe",
        "vssadmin create shadow /for=C:",
        "Volume Shadow Copy Creation on Database Server",
        ("T1003.003",),
    ),
]


def generate_ambiguous(
    n: int, *, start: datetime | None = None
) -> Iterator[tuple[list[EcsEvent], AlertRecord]]:
    """Yield (events, escalate-gold AlertRecord) for n borderline cases."""
    org = Org()
    base = start or datetime(2025, 3, 1, tzinfo=UTC)
    ctx = NoiseContext(AMBIGUOUS_SEED, base, org)
    for i in range(n):
        user, host, image, cmd, title, techs = _AMBIGUOUS_TEMPLATES[i % len(_AMBIGUOUS_TEMPLATES)]
        ts = base + timedelta(hours=i * 3)
        # A small benign-looking parent chain plus the alarming process.
        flat_parent = sysmon_process(
            ctx,
            ts,
            host,
            user,
            "C:\\Windows\\System32\\cmd.exe",
            '"C:\\Windows\\System32\\cmd.exe" ',
            "C:\\Windows\\explorer.exe",
            "C:\\Windows\\Explorer.EXE",
            "Medium",
        )
        flat = sysmon_process(
            ctx,
            ts + timedelta(seconds=2),
            host,
            user,
            image,
            cmd,
            "C:\\Windows\\System32\\cmd.exe",
            '"C:\\Windows\\System32\\cmd.exe" ',
        )
        events: list[EcsEvent] = []
        for fl in (flat_parent, flat):
            ev = map_windows_event(fl, dataset="noise", dataset_ref="ambiguous", tags=["ambiguous"])
            if ev is not None:
                events.append(ev)
        if not events:
            continue
        alarming = events[-1]
        row = {k: v for k, v in alarming.to_row().items() if v is not None}
        row["@timestamp"] = alarming.timestamp
        match = SigmaMatch(
            rule_id=f"amb:{i}",
            title=title,
            level="high",
            techniques=techs,
            tactics=(),
            matched_fields=("Image",),
        )
        finding = finding_from_sigma(match, row, description="Borderline dual-use activity")
        rec = AlertRecord(
            alert=finding,
            gold_label="escalate",
            gold_techniques=list(techs),
            fp_type=None,
            scenario_id=f"ambiguous:{i % len(_AMBIGUOUS_TEMPLATES)}",
            dataset="noise",
            triggering_event_id=alarming.event_id,
            rule_id=match.rule_id,
        )
        yield events, rec
