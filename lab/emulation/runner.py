"""Atomic Red Team scenario runner with ground-truth recording (SPEC §5.2).

For each scenario step the runner:

1. records ``start_ts`` (UTC, from the *target host's* clock via the executor);
2. invokes the published atomic test through **Invoke-AtomicRedTeam**
   (``Invoke-AtomicTest <T#> -TestGuids <guid> [-InputArgs ...]``) on Windows, or the ART
   ``sh``/``bash`` executor via ``Invoke-AtomicTest`` under PowerShell 7 on Linux;
3. runs the atomic's own cleanup (``-Cleanup``) unless disabled;
4. records ``end_ts`` and appends a ``GroundTruthWindow`` (label ``tp``, technique, tactic, host,
   user) to ``data/ground_truth/windows.jsonl``;
5. sleeps ``gap_seconds`` so consecutive windows never overlap.

Transports (``--transport``):
* ``local``   - run on this machine (use *inside* a lab VM; never on a workstation you care about);
* ``ssh``     - ``ssh <user>@<host> pwsh -NoProfile -Command ...`` (OpenSSH server on the VM);
* ``vagrant`` - ``vagrant winrm|ssh <machine> -c ...`` from ``lab/vms``;
* ``dry-run`` - print the exact commands, execute nothing, write windows with ``notes="dry-run"``
  to a *separate* file so they never pollute real ground truth.

The runner only ever invokes tests that already exist in the pinned ART index (§9.2: the agent and
this repo never author attack tooling). Scenarios are validated before anything runs.
"""

from __future__ import annotations

import json
import logging
import shlex
import subprocess
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

import yaml
from lab.emulation.ground_truth import GroundTruthTable, GroundTruthWindow
from lab.emulation.scenario import (
    ART_TACTIC_TO_ID,
    ArtTest,
    Scenario,
    load_art_index,
    validate_scenarios,
)

log = logging.getLogger(__name__)

Transport = Literal["local", "ssh", "vagrant", "dry-run"]
LAB_HOSTS_YAML = Path(__file__).with_name("hosts.yaml")


@dataclass
class LabHost:
    name: str
    os: str  # windows | linux
    address: str  # ip/dns for ssh
    vagrant_name: str
    ssh_user: str
    default_user: str  # account the atomics run as (for ground truth)


def load_hosts(path: Path = LAB_HOSTS_YAML) -> dict[str, LabHost]:
    doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    return {h["name"]: LabHost(**h) for h in doc["hosts"]}


@dataclass
class StepResult:
    scenario_id: str
    step: int
    technique: str
    test_guid: str
    host: str
    start_ts: datetime
    end_ts: datetime
    exit_code: int
    stdout_tail: str
    stderr_tail: str
    command: str


class Executor:
    """Builds and runs the per-host command for one transport."""

    def __init__(self, transport: Transport, vms_dir: Path, hosts: dict[str, LabHost]) -> None:
        self.transport = transport
        self.vms_dir = vms_dir
        self.hosts = hosts

    @staticmethod
    def atomic_command(
        test: ArtTest, step_args: dict[str, str], cleanup: bool, timeout_s: int
    ) -> str:
        """PowerShell one-liner invoking Invoke-AtomicRedTeam for one published test."""
        args = ""
        if step_args:
            kv = "; ".join(f"'{k}'='{_ps_escape(v)}'" for k, v in step_args.items())
            args = f" -InputArgs @{{{kv}}}"
        base = (
            f"Import-Module Invoke-AtomicRedTeam -Force; "
            f"Invoke-AtomicTest {test.technique} -TestGuids {test.test_guid} "
            f"-GetPrereqs -TimeoutSeconds {timeout_s}{args}; "
            f"Invoke-AtomicTest {test.technique} -TestGuids {test.test_guid} "
            f"-TimeoutSeconds {timeout_s}{args} -ExecutionLogPath "
            f"$env:TEMP/aegis-atomic-log.csv"
        )
        if cleanup:
            base += (
                f"; Invoke-AtomicTest {test.technique} -TestGuids {test.test_guid} -Cleanup{args}"
            )
        return base

    def wrap(self, host: LabHost, ps_command: str) -> list[str]:
        shell = "powershell" if host.os == "windows" else "pwsh"
        if self.transport in ("local", "dry-run"):
            return [shell, "-NoProfile", "-NonInteractive", "-Command", ps_command]
        if self.transport == "ssh":
            remote = f"{shell} -NoProfile -NonInteractive -Command {shlex.quote(ps_command)}"
            return ["ssh", "-o", "BatchMode=yes", f"{host.ssh_user}@{host.address}", remote]
        if self.transport == "vagrant":
            sub = "winrm" if host.os == "windows" else "ssh"
            inner = (
                ps_command
                if sub == "winrm"
                else f"{shell} -NoProfile -NonInteractive -Command {shlex.quote(ps_command)}"
            )
            return ["vagrant", sub, host.vagrant_name, "-c", inner]
        raise ValueError(self.transport)

    def clock(self, host: LabHost) -> datetime:
        """Target host's UTC time so windows line up with the telemetry it emits."""
        if self.transport == "dry-run":
            return datetime.now(tz=UTC)
        cmd = self.wrap(host, "[DateTime]::UtcNow.ToString('o')")
        out = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
            cwd=self.vms_dir if self.transport == "vagrant" else None,
        )
        try:
            return datetime.fromisoformat(out.stdout.strip().replace("Z", "+00:00")).astimezone(UTC)
        except ValueError:
            log.warning(
                "could not read clock on %s (%s); using local UTC",
                host.name,
                out.stderr.strip()[:200],
            )
            return datetime.now(tz=UTC)

    def run(self, host: LabHost, ps_command: str, timeout_s: int) -> tuple[int, str, str, str]:
        cmd = self.wrap(host, ps_command)
        printable = " ".join(shlex.quote(c) for c in cmd)
        if self.transport == "dry-run":
            return 0, "", "", printable
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout_s + 120,
            check=False,
            cwd=self.vms_dir if self.transport == "vagrant" else None,
        )
        return proc.returncode, proc.stdout[-2000:], proc.stderr[-2000:], printable


def _ps_escape(s: str) -> str:
    return s.replace("'", "''")


def run_scenario(
    scenario: Scenario,
    *,
    transport: Transport,
    data_root: Path,
    vms_dir: Path,
    hosts: dict[str, LabHost] | None = None,
    index: dict[str, ArtTest] | None = None,
    only_steps: set[int] | None = None,
    on_step: Callable[[StepResult], None] | None = None,
) -> list[StepResult]:
    hosts = hosts or load_hosts()
    index = index or load_art_index()
    problems, _ = validate_scenarios([scenario], index, {n: h.os for n, h in hosts.items()})
    if problems:
        raise ValueError("scenario invalid:\n  " + "\n  ".join(problems))

    gt_root = data_root / ("ground_truth_dryrun" if transport == "dry-run" else "ground_truth")
    table = GroundTruthTable(gt_root)
    log_path = gt_root / "runner_log.jsonl"
    execu = Executor(transport, vms_dir, hosts)
    results: list[StepResult] = []

    for i, step in enumerate(scenario.steps, 1):
        if only_steps and i not in only_steps:
            continue
        host = hosts[step.host]
        test = index[step.test_guid]
        ps = execu.atomic_command(test, step.input_args, step.cleanup, step.timeout_s)
        start = execu.clock(host)
        code, out, err, printable = execu.run(host, ps, step.timeout_s)
        end = execu.clock(host)
        res = StepResult(
            scenario.id,
            i,
            step.technique,
            step.test_guid,
            host.name,
            start,
            end,
            code,
            out,
            err,
            printable,
        )
        results.append(res)
        tactic = step.tactic or ART_TACTIC_TO_ID.get(test.tactic, "")
        window = GroundTruthWindow(
            window_id=f"art:{scenario.id}:{i:02d}:{start.strftime('%Y%m%dT%H%M%S')}",
            scenario_id=f"art:{scenario.id}",
            step=i,
            label="tp",
            techniques=[step.technique],
            tactics=[tactic] if tactic else [],
            host=host.name,
            user=step.user or host.default_user,
            start_ts=start,
            end_ts=end,
            dataset="lab_emulation",
            dataset_ref=scenario.id,
            source="art_runner",
            notes=(
                f"{test.test_name} (exit {code})"
                if transport != "dry-run"
                else f"dry-run: {test.test_name}"
            ),
        )
        table.append([window])
        with log_path.open("a", encoding="utf-8") as f:
            f.write(
                json.dumps(
                    {**res.__dict__, "start_ts": start.isoformat(), "end_ts": end.isoformat()}
                )
                + "\n"
            )
        if on_step:
            on_step(res)
        if code != 0 and transport != "dry-run":
            log.warning("%s step %d exit %d: %s", scenario.id, i, code, err[-300:])
        if transport != "dry-run" and i < len(scenario.steps):
            time.sleep(scenario.gap_seconds)
    return results


def scenario_summary(results: list[StepResult]) -> dict[str, Any]:
    return {
        "steps": len(results),
        "ok": sum(r.exit_code == 0 for r in results),
        "failed": [r.step for r in results if r.exit_code != 0],
        "techniques": sorted({r.technique for r in results}),
    }
