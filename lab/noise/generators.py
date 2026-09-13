"""Benign activity + realistic false-positive generators (SPEC §5.4).

Each generator produces telemetry for a *legitimate* activity that commonly trips detection rules,
tagged with an ``fp_type``. Output is Windows-shaped flat events (Sysmon 1/3/10/11, Security
4624/4625/4688, System 7045, PowerShell 4104) fed through the same ``map_windows_event`` mapper as
real data, so noise and attack telemetry are indistinguishable by shape - only by content.

Each run also emits one ``GroundTruthWindow`` per generated episode with ``label="fp"`` and its
``fp_type``, so the benchmark can stratify FPs (§8.1).

Design rules (§9.2): generators emulate *administrative* behaviour only - no payloads, no exploit
strings, no credential material. Tool names appear exactly as they do in legitimate IT usage.

Everything is deterministic given ``seed``.
"""

from __future__ import annotations

import hashlib
import random
from collections.abc import Callable, Iterator
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import yaml
from lab.common.ecs import EcsEvent
from lab.common.winevent import map_windows_event
from lab.emulation.ground_truth import GroundTruthWindow

ORG_YAML = Path(__file__).with_name("org.yaml")
SYSMON = "Microsoft-Windows-Sysmon/Operational"
SECURITY = "Security"
SYSTEM = "System"
POWERSHELL = "Microsoft-Windows-PowerShell/Operational"

FP_TYPES: tuple[str, ...] = (
    "admin_powershell",
    "psexec_admin",
    "vuln_scanner",
    "backup_agent",
    "software_deployment",
    "dev_procdump",
    "service_account_lockout",
    "redteam_tool_name_benign",
    "scheduled_task_maintenance",
    "helpdesk_remote_support",
)


class Org:
    def __init__(self, path: Path = ORG_YAML) -> None:
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
        self.domain: str = doc["domain"]
        self.hosts: list[dict[str, Any]] = doc["hosts"]
        self.users: list[dict[str, Any]] = doc["users"]
        self.hours = doc["business_hours"]

    def hosts_by_role(self, *roles: str) -> list[dict[str, Any]]:
        return [h for h in self.hosts if h["role"] in roles]

    def host(self, name: str) -> dict[str, Any]:
        return next(h for h in self.hosts if h["name"] == name)

    def users_by(self, **kw: Any) -> list[dict[str, Any]]:
        return [u for u in self.users if all(u.get(k) == v for k, v in kw.items())]


class NoiseContext:
    """Deterministic ids, guids and timestamps for one generation run."""

    def __init__(self, seed: int, start: datetime, org: Org) -> None:
        self.rng = random.Random(seed)
        self.start = start
        self.org = org
        self._pid = 1000 + self.rng.randint(0, 3000)
        self._record = 0

    def pid(self) -> int:
        self._pid += self.rng.randint(4, 64)
        return self._pid

    def guid(self, *parts: Any) -> str:
        h = hashlib.md5("|".join(map(str, parts)).encode()).hexdigest()
        return f"{{{h[:8]}-{h[8:12]}-{h[12:16]}-{h[16:20]}-{h[20:32]}}}"

    def logon_id(self) -> str:
        return hex(0x10000 + self.rng.randint(0, 0xFFFFF))

    def business_time(self, day_offset: int) -> datetime:
        h = self.rng.randint(self.org.hours["start"], self.org.hours["end"] - 1)
        return self.start + timedelta(
            days=day_offset,
            hours=h,
            minutes=self.rng.randint(0, 59),
            seconds=self.rng.randint(0, 59),
        )

    def off_hours_time(self, day_offset: int) -> datetime:
        h = self.rng.choice([1, 2, 3, 22, 23])
        return self.start + timedelta(days=day_offset, hours=h, minutes=self.rng.randint(0, 59))

    def sha256(self, name: str) -> str:
        return hashlib.sha256(f"benign-binary:{name}".encode()).hexdigest()


def _ts(dt: datetime) -> str:
    return dt.astimezone(UTC).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]


def sysmon_process(
    ctx: NoiseContext,
    ts: datetime,
    host: str,
    user: str,
    image: str,
    cmdline: str,
    parent_image: str,
    parent_cmdline: str,
    integrity: str = "High",
) -> dict[str, Any]:
    pid, ppid = ctx.pid(), ctx.pid()
    return {
        "@timestamp": ts.isoformat(),
        "Channel": SYSMON,
        "SourceName": "Microsoft-Windows-Sysmon",
        "EventID": 1,
        "Hostname": host,
        "UtcTime": _ts(ts),
        "ProcessGuid": ctx.guid(host, pid, ts),
        "ProcessId": str(pid),
        "Image": image,
        "CommandLine": cmdline,
        "CurrentDirectory": f"C:\\Users\\{user}\\"
        if "\\" not in user
        else "C:\\Windows\\system32\\",
        "User": f"{ctx.org.domain}\\{user}",
        "LogonGuid": ctx.guid(host, user, "logon"),
        "LogonId": ctx.logon_id(),
        "TerminalSessionId": "1",
        "IntegrityLevel": integrity,
        "Hashes": f"SHA256={ctx.sha256(image).upper()}",
        "ParentProcessGuid": ctx.guid(host, ppid),
        "ParentProcessId": str(ppid),
        "ParentImage": parent_image,
        "ParentCommandLine": parent_cmdline,
        "RuleName": "-",
    }


def sysmon_network(
    ctx: NoiseContext,
    ts: datetime,
    host: str,
    user: str,
    image: str,
    src_ip: str,
    dst_ip: str,
    dst_port: int,
    proto: str = "tcp",
) -> dict[str, Any]:
    return {
        "@timestamp": ts.isoformat(),
        "Channel": SYSMON,
        "SourceName": "Microsoft-Windows-Sysmon",
        "EventID": 3,
        "Hostname": host,
        "UtcTime": _ts(ts),
        "ProcessGuid": ctx.guid(host, image),
        "ProcessId": str(ctx.pid()),
        "Image": image,
        "User": f"{ctx.org.domain}\\{user}",
        "Protocol": proto,
        "Initiated": "true",
        "SourceIp": src_ip,
        "SourceHostname": host,
        "SourcePort": str(ctx.rng.randint(49152, 65535)),
        "DestinationIp": dst_ip,
        "DestinationPort": str(dst_port),
        "RuleName": "-",
    }


def sysmon_process_access(
    ctx: NoiseContext, ts: datetime, host: str, source_image: str, target_image: str, access: str
) -> dict[str, Any]:
    return {
        "@timestamp": ts.isoformat(),
        "Channel": SYSMON,
        "SourceName": "Microsoft-Windows-Sysmon",
        "EventID": 10,
        "Hostname": host,
        "UtcTime": _ts(ts),
        "SourceProcessGUID": ctx.guid(host, source_image),
        "SourceProcessId": str(ctx.pid()),
        "SourceThreadId": str(ctx.rng.randint(100, 9000)),
        "SourceImage": source_image,
        "TargetProcessGUID": ctx.guid(host, target_image),
        "TargetProcessId": str(ctx.pid()),
        "TargetImage": target_image,
        "GrantedAccess": access,
        "CallTrace": (
            r"C:\Windows\SYSTEM32\ntdll.dll+9d234|"
            r"C:\Windows\System32\KERNELBASE.dll+2c0fe"
        ),
        "RuleName": "-",
    }


def sysmon_file(
    ctx: NoiseContext, ts: datetime, host: str, image: str, target: str
) -> dict[str, Any]:
    return {
        "@timestamp": ts.isoformat(),
        "Channel": SYSMON,
        "SourceName": "Microsoft-Windows-Sysmon",
        "EventID": 11,
        "Hostname": host,
        "UtcTime": _ts(ts),
        "ProcessGuid": ctx.guid(host, image),
        "ProcessId": str(ctx.pid()),
        "Image": image,
        "TargetFilename": target,
        "CreationUtcTime": _ts(ts),
        "RuleName": "-",
    }


def security_logon(
    ctx: NoiseContext,
    ts: datetime,
    host: str,
    user: str,
    logon_type: int,
    src_ip: str,
    success: bool,
    process: str = "C:\\Windows\\System32\\svchost.exe",
) -> dict[str, Any]:
    ev: dict[str, Any] = {
        "@timestamp": ts.isoformat(),
        "Channel": SECURITY,
        "SourceName": "Microsoft-Windows-Security-Auditing",
        "EventID": 4624 if success else 4625,
        "Hostname": host,
        "TimeCreated": _ts(ts),
        "SubjectUserSid": "S-1-0-0",
        "SubjectUserName": "-",
        "SubjectDomainName": "-",
        "SubjectLogonId": "0x0",
        "TargetUserName": user,
        "TargetDomainName": ctx.org.domain,
        "LogonType": str(logon_type),
        "LogonProcessName": "NtLmSsp " if logon_type == 3 else "User32 ",
        "AuthenticationPackageName": "NTLM" if logon_type == 3 else "Negotiate",
        "WorkstationName": host,
        "IpAddress": src_ip,
        "IpPort": str(ctx.rng.randint(49152, 65535)),
        "ProcessName": process,
    }
    if success:
        ev["TargetLogonId"] = ctx.logon_id()
        ev["TargetUserSid"] = (
            f"S-1-5-21-1004336348-1177238915-682003330-{ctx.rng.randint(1100, 1300)}"
        )
    else:
        ev["Status"] = "0xc000006d"
        ev["SubStatus"] = "0xc000006a"  # bad password
        ev["FailureReason"] = "%%2313"
    return ev


def system_service_install(
    ctx: NoiseContext, ts: datetime, host: str, name: str, path: str, account: str = "LocalSystem"
) -> dict[str, Any]:
    return {
        "@timestamp": ts.isoformat(),
        "Channel": SYSTEM,
        "SourceName": "Service Control Manager",
        "EventID": 7045,
        "Hostname": host,
        "TimeCreated": _ts(ts),
        "ServiceName": name,
        "ImagePath": path,
        "ServiceType": "user mode service",
        "StartType": "demand start",
        "AccountName": account,
    }


def ps_scriptblock(
    ctx: NoiseContext, ts: datetime, host: str, user: str, text: str, path: str
) -> dict[str, Any]:
    return {
        "@timestamp": ts.isoformat(),
        "Channel": POWERSHELL,
        "SourceName": "Microsoft-Windows-PowerShell",
        "EventID": 4104,
        "Hostname": host,
        "TimeCreated": _ts(ts),
        "User": f"{ctx.org.domain}\\{user}",
        "MessageNumber": "1",
        "MessageTotal": "1",
        "ScriptBlockText": text,
        "ScriptBlockId": ctx.guid(text, ts),
        "Path": path,
    }


Episode = tuple[str, list[dict[str, Any]], dict[str, Any]]  # fp_type, events, window attrs


# ------------------------------------------------------------------------------------------------
# Generators. Each returns (fp_type, events, {"host","user","notes"}) for ONE episode.
# ------------------------------------------------------------------------------------------------
def gen_admin_powershell(ctx: NoiseContext, day: int) -> Episode:
    admin = ctx.rng.choice(ctx.org.users_by(role="sysadmin"))["name"]
    host = ctx.rng.choice(ctx.org.hosts_by_role("domain-controller", "file-server", "database"))
    ts = ctx.business_time(day)
    ps = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
    cmds = [
        f"{ps} -NoProfile -ExecutionPolicy Bypass "
        rf"-File C:\Scripts\Get-StaleComputers.ps1 -Days 90",
        f'{ps} -NonInteractive -Command "Get-ADUser -Filter * -Properties LastLogonDate | '
        'Export-Csv C:\\Reports\\ad-users.csv"',
        f"{ps} -EncodedCommand {_b64_like(ctx, 'Get-Service | Where Status -eq Stopped')}",
        f'{ps} -Command "Invoke-Command -ComputerName {host["name"]} -ScriptBlock '
        '{ Get-EventLog -LogName System -Newest 50 }"',
    ]
    events = [
        sysmon_process(
            ctx,
            ts + timedelta(seconds=i * 7),
            host["name"],
            admin,
            ps,
            c,
            "C:\\Windows\\System32\\cmd.exe",
            '"C:\\Windows\\System32\\cmd.exe" ',
        )
        for i, c in enumerate(ctx.rng.sample(cmds, 2))
    ]
    events.append(
        ps_scriptblock(
            ctx,
            ts + timedelta(seconds=3),
            host["name"],
            admin,
            "Get-ADUser -Filter * -Properties LastLogonDate | Export-Csv C:\\Reports\\ad-users.csv",
            "C:\\Scripts\\Get-StaleComputers.ps1",
        )
    )
    return (
        "admin_powershell",
        events,
        {"host": host["name"], "user": admin, "notes": "sysadmin scripted AD housekeeping"},
    )


def gen_psexec_admin(ctx: NoiseContext, day: int) -> Episode:
    admin = ctx.rng.choice(ctx.org.users_by(role="sysadmin"))["name"]
    src = ctx.org.host("WS-HELPDESK")
    target = ctx.rng.choice(ctx.org.hosts_by_role("file-server", "database", "software-deploy"))
    ts = ctx.business_time(day)
    events = [
        sysmon_process(
            ctx,
            ts,
            src["name"],
            admin,
            "C:\\Tools\\PsExec64.exe",
            f'PsExec64.exe \\\\{target["name"]} -s cmd /c "sc query wuauserv"',
            "C:\\Windows\\System32\\cmd.exe",
            '"C:\\Windows\\System32\\cmd.exe" ',
        ),
        sysmon_network(
            ctx,
            ts + timedelta(seconds=1),
            src["name"],
            admin,
            "C:\\Tools\\PsExec64.exe",
            src["ip"],
            target["ip"],
            445,
        ),
        security_logon(ctx, ts + timedelta(seconds=1), target["name"], admin, 3, src["ip"], True),
        system_service_install(
            ctx, ts + timedelta(seconds=2), target["name"], "PSEXESVC", "%SystemRoot%\\PSEXESVC.exe"
        ),
        sysmon_process(
            ctx,
            ts + timedelta(seconds=2),
            target["name"],
            "SYSTEM",
            "C:\\Windows\\PSEXESVC.exe",
            "C:\\Windows\\PSEXESVC.exe",
            "C:\\Windows\\System32\\services.exe",
            "C:\\Windows\\system32\\services.exe",
            "System",
        ),
        sysmon_process(
            ctx,
            ts + timedelta(seconds=3),
            target["name"],
            "SYSTEM",
            "C:\\Windows\\System32\\cmd.exe",
            'cmd /c "sc query wuauserv"',
            "C:\\Windows\\PSEXESVC.exe",
            "C:\\Windows\\PSEXESVC.exe",
            "System",
        ),
    ]
    return (
        "psexec_admin",
        events,
        {"host": target["name"], "user": admin, "notes": "helpdesk PsExec remote service check"},
    )


def gen_vuln_scanner(ctx: NoiseContext, day: int) -> Episode:
    scanner = ctx.org.host("SCAN01")
    svc = "svc_scanner"
    target = ctx.rng.choice([h for h in ctx.org.hosts if h["os"] == "windows"])
    ts = ctx.off_hours_time(day)
    events: list[dict[str, Any]] = []
    # authenticated scan: many logons + WMI/SMB, then a handful of failed logons for local accounts
    for i in range(6):
        events.append(
            security_logon(
                ctx, ts + timedelta(seconds=i * 2), target["name"], svc, 3, scanner["ip"], True
            )
        )
    for i in range(3):
        events.append(
            security_logon(
                ctx,
                ts + timedelta(seconds=20 + i),
                target["name"],
                ctx.rng.choice(["Administrator", "Guest", "admin"]),
                3,
                scanner["ip"],
                False,
            )
        )
    events.append(
        sysmon_process(
            ctx,
            ts + timedelta(seconds=30),
            target["name"],
            svc,
            "C:\\Windows\\System32\\wbem\\WmiPrvSE.exe",
            "C:\\Windows\\system32\\wbem\\wmiprvse.exe -secured -Embedding",
            "C:\\Windows\\System32\\svchost.exe",
            "C:\\Windows\\system32\\svchost.exe -k DcomLaunch -p",
            "System",
        )
    )
    events.append(
        sysmon_process(
            ctx,
            ts + timedelta(seconds=31),
            target["name"],
            svc,
            "C:\\Windows\\System32\\cmd.exe",
            "cmd.exe /c reg query HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
            "C:\\Windows\\System32\\wbem\\WmiPrvSE.exe",
            "C:\\Windows\\system32\\wbem\\wmiprvse.exe -secured -Embedding",
        )
    )
    return (
        "vuln_scanner",
        events,
        {
            "host": target["name"],
            "user": svc,
            "notes": "scheduled Nessus authenticated scan from SCAN01",
        },
    )


def gen_backup_agent(ctx: NoiseContext, day: int) -> Episode:
    backup = ctx.org.host("BACKUP01")
    target = ctx.rng.choice(ctx.org.hosts_by_role("file-server", "database", "domain-controller"))
    ts = ctx.off_hours_time(day)
    svc = "svc_backup"
    agent = "C:\\Program Files\\Veeam\\Backup and Replication\\Backup\\VeeamAgent.exe"
    events = [
        security_logon(ctx, ts, target["name"], svc, 3, backup["ip"], True),
        sysmon_process(
            ctx,
            ts + timedelta(seconds=2),
            target["name"],
            svc,
            agent,
            f'"{agent}" -job nightly-{target["name"].lower()}',
            "C:\\Windows\\System32\\services.exe",
            "C:\\Windows\\system32\\services.exe",
            "System",
        ),
        sysmon_process(
            ctx,
            ts + timedelta(seconds=5),
            target["name"],
            svc,
            "C:\\Windows\\System32\\vssadmin.exe",
            "vssadmin list shadows",
            agent,
            f'"{agent}" -job nightly-{target["name"].lower()}',
            "System",
        ),
        sysmon_process(
            ctx,
            ts + timedelta(seconds=6),
            target["name"],
            svc,
            "C:\\Windows\\System32\\wbem\\WMIC.exe",
            "wmic shadowcopy call create Volume='C:\\'",
            agent,
            f'"{agent}" -job nightly-{target["name"].lower()}',
            "System",
        ),
        sysmon_network(
            ctx,
            ts + timedelta(seconds=8),
            target["name"],
            svc,
            agent,
            target["ip"],
            backup["ip"],
            2500,
        ),
    ]
    if target["role"] == "domain-controller":
        events.append(
            sysmon_file(
                ctx,
                ts + timedelta(seconds=9),
                target["name"],
                agent,
                "C:\\Windows\\Temp\\VeeamBackup\\ntds.dit.tmp",
            )
        )
    return (
        "backup_agent",
        events,
        {
            "host": target["name"],
            "user": svc,
            "notes": "nightly Veeam job (VSS snapshot, ntds copy on DC)",
        },
    )


def gen_software_deployment(ctx: NoiseContext, day: int) -> Episode:
    sccm = ctx.org.host("SCCM01")
    target = ctx.rng.choice(ctx.org.hosts_by_role("workstation", "dev-workstation"))
    ts = ctx.business_time(day)
    svc = "svc_sccm"
    pkg = ctx.rng.choice(
        [
            "7z2409-x64.msi",
            "GoogleChromeStandaloneEnterprise64.msi",
            "vlc-3.0.21-win64.msi",
            "Zoom.msi",
        ]
    )
    events = [
        security_logon(ctx, ts, target["name"], svc, 3, sccm["ip"], True),
        sysmon_process(
            ctx,
            ts + timedelta(seconds=3),
            target["name"],
            "SYSTEM",
            "C:\\Windows\\CCM\\CcmExec.exe",
            "C:\\Windows\\CCM\\CcmExec.exe",
            "C:\\Windows\\System32\\services.exe",
            "C:\\Windows\\system32\\services.exe",
            "System",
        ),
        sysmon_file(
            ctx,
            ts + timedelta(seconds=4),
            target["name"],
            "C:\\Windows\\CCM\\CcmExec.exe",
            f"C:\\Windows\\ccmcache\\1a\\{pkg}",
        ),
        sysmon_process(
            ctx,
            ts + timedelta(seconds=6),
            target["name"],
            "SYSTEM",
            "C:\\Windows\\System32\\msiexec.exe",
            f"msiexec.exe /i C:\\Windows\\ccmcache\\1a\\{pkg} /qn /norestart",
            "C:\\Windows\\CCM\\CcmExec.exe",
            "C:\\Windows\\CCM\\CcmExec.exe",
            "System",
        ),
        sysmon_process(
            ctx,
            ts + timedelta(seconds=9),
            target["name"],
            "SYSTEM",
            "C:\\Windows\\System32\\schtasks.exe",
            'schtasks /Create /TN "Microsoft\\Configuration Manager\\Configuration Manager '
            'Health Evaluation" /XML C:\\Windows\\CCM\\ccmeval.xml /F',
            "C:\\Windows\\CCM\\CcmExec.exe",
            "C:\\Windows\\CCM\\CcmExec.exe",
            "System",
        ),
    ]
    return (
        "software_deployment",
        events,
        {"host": target["name"], "user": svc, "notes": f"SCCM push of {pkg}"},
    )


def gen_dev_procdump(ctx: NoiseContext, day: int) -> Episode:
    dev = ctx.rng.choice(ctx.org.users_by(role="software-engineer"))
    host = ctx.org.host("WS-DEV1" if dev["name"] == "dev.kumar" else "WS-DEV2")
    ts = ctx.business_time(day)
    app = ctx.rng.choice(["MyService.exe", "OrderApi.exe", "dotnet.exe", "node.exe"])
    pd = "C:\\Tools\\Sysinternals\\procdump64.exe"
    events = [
        sysmon_process(
            ctx,
            ts,
            host["name"],
            dev["name"],
            "C:\\Program Files\\Microsoft VS Code\\Code.exe",
            '"C:\\Program Files\\Microsoft VS Code\\Code.exe"',
            "C:\\Windows\\explorer.exe",
            "C:\\Windows\\Explorer.EXE",
            "Medium",
        ),
        sysmon_process(
            ctx,
            ts + timedelta(minutes=12),
            host["name"],
            dev["name"],
            pd,
            f"procdump64.exe -accepteula -ma {app} C:\\dumps\\{app}.dmp",
            "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            "powershell.exe",
            "Medium",
        ),
        sysmon_process_access(
            ctx,
            ts + timedelta(minutes=12, seconds=1),
            host["name"],
            pd,
            f"C:\\Projects\\{app.split('.')[0]}\\bin\\Debug\\{app}",
            "0x1FFFFF",
        ),
        sysmon_file(
            ctx, ts + timedelta(minutes=12, seconds=4), host["name"], pd, f"C:\\dumps\\{app}.dmp"
        ),
    ]
    return (
        "dev_procdump",
        events,
        {
            "host": host["name"],
            "user": dev["name"],
            "notes": f"developer memory dump of own {app} for debugging",
        },
    )


def gen_service_account_lockout(ctx: NoiseContext, day: int) -> Episode:
    """Misconfigured legacy app retries a stale password -> looks like a password spray."""
    dc = ctx.org.host("DC01")
    app_host = ctx.org.host("SQL01")
    ts = ctx.business_time(day)
    events: list[dict[str, Any]] = []
    for i in range(ctx.rng.randint(12, 25)):
        events.append(
            security_logon(
                ctx,
                ts + timedelta(seconds=i * 30),
                dc["name"],
                "svc_legacyapp",
                3,
                app_host["ip"],
                False,
            )
        )
    events.append(
        {
            "@timestamp": (ts + timedelta(minutes=13)).isoformat(),
            "Channel": SECURITY,
            "SourceName": "Microsoft-Windows-Security-Auditing",
            "EventID": 4740,
            "Hostname": dc["name"],
            "TimeCreated": _ts(ts + timedelta(minutes=13)),
            "TargetUserName": "svc_legacyapp",
            "TargetDomainName": app_host["name"],
            "SubjectUserName": f"{dc['name']}$",
            "SubjectDomainName": ctx.org.domain,
        }
    )
    return (
        "service_account_lockout",
        events,
        {
            "host": dc["name"],
            "user": "svc_legacyapp",
            "notes": "legacy ERP retrying rotated password",
        },
    )


def gen_redteam_tool_name_benign(ctx: NoiseContext, day: int) -> Episode:
    """Legitimate binaries whose names/paths collide with detection keywords."""
    dev = ctx.rng.choice(ctx.org.users_by(role="software-engineer"))
    host = ctx.org.host("WS-DEV1" if dev["name"] == "dev.kumar" else "WS-DEV2")
    ts = ctx.business_time(day)
    choice = ctx.rng.choice(["mimikatz_docs", "nc_test", "psexec_in_repo", "rubeus_folder"])
    if choice == "mimikatz_docs":
        events = [
            sysmon_process(
                ctx,
                ts,
                host["name"],
                dev["name"],
                "C:\\Program Files\\Microsoft VS Code\\Code.exe",
                '"C:\\Program Files\\Microsoft VS Code\\Code.exe" '
                "C:\\Projects\\detections\\docs\\mimikatz-detection-notes.md",
                "C:\\Windows\\explorer.exe",
                "C:\\Windows\\Explorer.EXE",
                "Medium",
            )
        ]
        notes = "detection-engineering notes file named after a tool"
    elif choice == "nc_test":
        events = [
            sysmon_process(
                ctx,
                ts,
                host["name"],
                dev["name"],
                "C:\\Program Files\\Git\\usr\\bin\\nc.exe",
                "nc -zv 10.10.1.30 1433",
                "C:\\Program Files\\Git\\usr\\bin\\bash.exe",
                "bash",
                "Medium",
            ),
            sysmon_network(
                ctx,
                ts + timedelta(seconds=1),
                host["name"],
                dev["name"],
                "C:\\Program Files\\Git\\usr\\bin\\nc.exe",
                host["ip"],
                ctx.org.host("SQL01")["ip"],
                1433,
            ),
        ]
        notes = "developer port check with Git-for-Windows netcat"
    elif choice == "psexec_in_repo":
        events = [
            sysmon_file(
                ctx,
                ts,
                host["name"],
                "C:\\Program Files\\Git\\cmd\\git.exe",
                "C:\\Projects\\infra-tools\\vendor\\sysinternals\\PsExec.exe",
            )
        ]
        notes = "git clone of internal repo vendoring Sysinternals"
    else:
        events = [
            sysmon_process(
                ctx,
                ts,
                host["name"],
                dev["name"],
                "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
                'powershell.exe -Command "Get-ChildItem C:\\Projects\\Rubeus-Docs '
                '-Recurse | Measure-Object"',
                "C:\\Windows\\explorer.exe",
                "C:\\Windows\\Explorer.EXE",
                "Medium",
            )
        ]
        notes = "folder named after a tool in a documentation repo"
    return (
        "redteam_tool_name_benign",
        events,
        {"host": host["name"], "user": dev["name"], "notes": notes},
    )


def gen_scheduled_task_maintenance(ctx: NoiseContext, day: int) -> Episode:
    host = ctx.rng.choice([h for h in ctx.org.hosts if h["os"] == "windows"])
    ts = ctx.off_hours_time(day)
    events = [
        sysmon_process(
            ctx,
            ts,
            host["name"],
            "SYSTEM",
            "C:\\Windows\\System32\\svchost.exe",
            "C:\\Windows\\system32\\svchost.exe -k netsvcs -p -s Schedule",
            "C:\\Windows\\System32\\services.exe",
            "C:\\Windows\\system32\\services.exe",
            "System",
        ),
        sysmon_process(
            ctx,
            ts + timedelta(seconds=1),
            host["name"],
            "SYSTEM",
            "C:\\Windows\\System32\\cmd.exe",
            "cmd.exe /c C:\\Windows\\Temp\\cleanup.bat",
            "C:\\Windows\\System32\\svchost.exe",
            "C:\\Windows\\system32\\svchost.exe -k netsvcs -p -s Schedule",
            "System",
        ),
        sysmon_process(
            ctx,
            ts + timedelta(seconds=2),
            host["name"],
            "SYSTEM",
            "C:\\Windows\\System32\\forfiles.exe",
            'forfiles /p C:\\Logs /s /m *.log /d -30 /c "cmd /c del @path"',
            "C:\\Windows\\System32\\cmd.exe",
            "cmd.exe /c C:\\Windows\\Temp\\cleanup.bat",
            "System",
        ),
    ]
    return (
        "scheduled_task_maintenance",
        events,
        {"host": host["name"], "user": "SYSTEM", "notes": "log rotation task via forfiles"},
    )


def gen_helpdesk_remote_support(ctx: NoiseContext, day: int) -> Episode:
    hd = "hd.singh"
    src = ctx.org.host("WS-HELPDESK")
    target = ctx.rng.choice(ctx.org.hosts_by_role("workstation"))
    ts = ctx.business_time(day)
    events = [
        security_logon(
            ctx, ts, target["name"], hd, 10, src["ip"], True, "C:\\Windows\\System32\\winlogon.exe"
        ),
        sysmon_process(
            ctx,
            ts + timedelta(seconds=20),
            target["name"],
            hd,
            "C:\\Windows\\System32\\net.exe",
            "net localgroup administrators",
            "C:\\Windows\\System32\\cmd.exe",
            '"C:\\Windows\\system32\\cmd.exe" ',
        ),
        sysmon_process(
            ctx,
            ts + timedelta(seconds=40),
            target["name"],
            hd,
            "C:\\Windows\\System32\\whoami.exe",
            "whoami /groups",
            "C:\\Windows\\System32\\cmd.exe",
            '"C:\\Windows\\system32\\cmd.exe" ',
        ),
        sysmon_process(
            ctx,
            ts + timedelta(seconds=70),
            target["name"],
            hd,
            "C:\\Windows\\System32\\gpupdate.exe",
            "gpupdate /force",
            "C:\\Windows\\System32\\cmd.exe",
            '"C:\\Windows\\system32\\cmd.exe" ',
        ),
    ]
    return (
        "helpdesk_remote_support",
        events,
        {
            "host": target["name"],
            "user": hd,
            "notes": "RDP support session with discovery-like cmds",
        },
    )


GENERATORS: dict[str, Callable[[NoiseContext, int], Episode]] = {
    "admin_powershell": gen_admin_powershell,
    "psexec_admin": gen_psexec_admin,
    "vuln_scanner": gen_vuln_scanner,
    "backup_agent": gen_backup_agent,
    "software_deployment": gen_software_deployment,
    "dev_procdump": gen_dev_procdump,
    "service_account_lockout": gen_service_account_lockout,
    "redteam_tool_name_benign": gen_redteam_tool_name_benign,
    "scheduled_task_maintenance": gen_scheduled_task_maintenance,
    "helpdesk_remote_support": gen_helpdesk_remote_support,
}


def _b64_like(ctx: NoiseContext, cmd: str) -> str:
    import base64

    return base64.b64encode(cmd.encode("utf-16-le")).decode()


def generate(
    *,
    seed: int,
    days: int,
    episodes_per_day: int,
    start: datetime | None = None,
    fp_types: tuple[str, ...] = FP_TYPES,
    org_path: Path = ORG_YAML,
) -> Iterator[tuple[list[EcsEvent], GroundTruthWindow]]:
    """Yield (events, fp window) per episode. Deterministic for a given seed."""
    org = Org(org_path)
    start = start or datetime(2025, 1, 6, tzinfo=UTC)  # a Monday
    ctx = NoiseContext(seed, start, org)
    run_ref = f"noise-s{seed}"
    n = 0
    for day in range(days):
        for _ in range(episodes_per_day):
            fp_type = ctx.rng.choice(fp_types)
            fp, flat_events, attrs = GENERATORS[fp_type](ctx, day)
            n += 1
            events: list[EcsEvent] = []
            for fe in flat_events:
                ev = map_windows_event(
                    fe, dataset="noise", dataset_ref=run_ref, tags=[f"noise:{fp}", f"episode:{n}"]
                )
                if ev is not None:
                    events.append(ev)
            if not events:
                continue
            window = GroundTruthWindow(
                window_id=f"noise:{run_ref}:{n:05d}",
                scenario_id=f"noise:{fp}",
                step=n,
                label="fp",
                host=attrs["host"],
                user=None if attrs["user"] in ("SYSTEM",) else attrs["user"],
                start_ts=min(e.timestamp for e in events) - timedelta(seconds=1),
                end_ts=max(e.timestamp for e in events) + timedelta(seconds=1),
                dataset="noise",
                dataset_ref=run_ref,
                fp_type=fp,
                source="noise_generator",
                notes=attrs["notes"],
            )
            yield events, window
