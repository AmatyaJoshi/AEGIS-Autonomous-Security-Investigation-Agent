"""Scenario schema + validation against the Atomic Red Team index.

A scenario (``lab/emulation/scenarios/*.yaml``) is an ordered list of Atomic Red Team tests with a
narrative. Validation checks that every ``technique``/``test_guid`` pair exists in the ART index
(``lab/emulation/art_index.csv``, a pinned copy of
``atomics/Indexes/Indexes-CSV/index.csv`` from redcanaryco/atomic-red-team) and that the executor
is one the target OS supports. Nothing here executes anything.
"""

from __future__ import annotations

import csv
from collections import Counter
from pathlib import Path
from typing import Any, Literal

import yaml
from lab.emulation.ground_truth import TACTIC_IDS, TACTIC_NAMES
from pydantic import BaseModel, ConfigDict, Field, field_validator

ART_INDEX_CSV = Path(__file__).with_name("art_index.csv")
SCENARIOS_DIR = Path(__file__).with_name("scenarios")

# ART index "Tactic" column uses its own vocabulary; map to ATT&CK tactic ids.
ART_TACTIC_TO_ID: dict[str, str] = {
    "reconnaissance": "TA0043",
    "resource-development": "TA0042",
    "initial-access": "TA0001",
    "execution": "TA0002",
    "persistence": "TA0003",
    "privilege-escalation": "TA0004",
    "defense-evasion": "TA0005",
    "stealth": "TA0005",
    "credential-access": "TA0006",
    "discovery": "TA0007",
    "lateral-movement": "TA0008",
    "collection": "TA0009",
    "command-and-control": "TA0011",
    "exfiltration": "TA0010",
    "impact": "TA0040",
}


class ArtTest(BaseModel):
    tactic: str
    technique: str
    technique_name: str
    test_number: int
    test_name: str
    test_guid: str
    executor: str


def load_art_index(path: Path = ART_INDEX_CSV) -> dict[str, ArtTest]:
    out: dict[str, ArtTest] = {}
    with path.open(encoding="utf-8", newline="") as f:
        for row in csv.DictReader(f):
            t = ArtTest(
                tactic=row["Tactic"].strip(),
                technique=row["Technique #"].strip().upper(),
                technique_name=row["Technique Name"].strip(),
                test_number=int(row["Test #"]),
                test_name=row["Test Name"].strip(),
                test_guid=row["Test GUID"].strip().lower(),
                executor=row["Executor Name"].strip(),
            )
            out[t.test_guid] = t
    return out


class ScenarioStep(BaseModel):
    model_config = ConfigDict(extra="forbid")

    technique: str
    test_guid: str
    host: str  # lab host name (DC01 / WS01 / LNX01)
    user: str | None = None  # run-as (defaults to the runner's account)
    tactic: str | None = None  # override; else from ART index
    note: str | None = None
    timeout_s: int = 120
    cleanup: bool = True
    input_args: dict[str, str] = Field(default_factory=dict)

    @field_validator("technique")
    @classmethod
    def _norm(cls, v: str) -> str:
        return v.strip().upper()

    @field_validator("test_guid")
    @classmethod
    def _lower(cls, v: str) -> str:
        return v.strip().lower()


class Scenario(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str
    title: str
    narrative: str
    platform: Literal["windows", "linux", "mixed"]
    steps: list[ScenarioStep]
    gap_seconds: int = 90  # pause between steps so windows do not overlap
    tags: list[str] = Field(default_factory=list)

    def techniques(self) -> list[str]:
        out: list[str] = []
        for s in self.steps:
            if s.technique not in out:
                out.append(s.technique)
        return out


def load_scenarios(directory: Path = SCENARIOS_DIR) -> list[Scenario]:
    out: list[Scenario] = []
    for p in sorted(directory.glob("*.yaml")):
        doc = yaml.safe_load(p.read_text(encoding="utf-8"))
        out.append(Scenario.model_validate(doc))
    return out


def validate_scenarios(
    scenarios: list[Scenario], index: dict[str, ArtTest], hosts: dict[str, str]
) -> tuple[list[str], dict[str, Any]]:
    """Return (problems, coverage). ``hosts`` maps lab host name -> os ("windows"/"linux")."""
    problems: list[str] = []
    techniques: set[str] = set()
    tactics: set[str] = set()
    per_scenario: dict[str, dict[str, int]] = {}
    for sc in scenarios:
        seen_ids: set[str] = set()
        for i, step in enumerate(sc.steps, 1):
            where = f"{sc.id} step {i}"
            test = index.get(step.test_guid)
            if test is None:
                problems.append(f"{where}: unknown ART test guid {step.test_guid}")
                continue
            if test.technique != step.technique:
                problems.append(f"{where}: guid belongs to {test.technique}, not {step.technique}")
            if step.host not in hosts:
                problems.append(f"{where}: unknown host {step.host}")
            else:
                os_ = hosts[step.host]
                win_exec = test.executor in ("powershell", "command_prompt")
                nix_exec = test.executor in ("sh", "bash")
                if os_ == "windows" and not win_exec:
                    problems.append(f"{where}: executor {test.executor} not runnable on Windows")
                if os_ == "linux" and not nix_exec:
                    problems.append(f"{where}: executor {test.executor} not runnable on Linux")
            tactic = step.tactic or ART_TACTIC_TO_ID.get(test.tactic, "")
            if tactic and tactic not in TACTIC_NAMES:
                tactic = TACTIC_IDS.get(tactic, tactic)
            if not tactic:
                problems.append(f"{where}: cannot resolve tactic for ART tactic {test.tactic!r}")
            techniques.add(step.technique)
            if tactic:
                tactics.add(tactic)
            seen_ids.add(step.test_guid)
        per_scenario[sc.id] = {"steps": len(sc.steps), "techniques": len(sc.techniques())}
    parents = {t.split(".")[0] for t in techniques}
    coverage = {
        "scenarios": len(scenarios),
        "steps": sum(len(s.steps) for s in scenarios),
        "techniques": sorted(techniques),
        "technique_count": len(techniques),
        "parent_technique_count": len(parents),
        "tactics": sorted(tactics),
        "tactic_count": len(tactics),
        "tactic_names": sorted(TACTIC_NAMES[t] for t in tactics if t in TACTIC_NAMES),
        "per_scenario": per_scenario,
        "executors": dict(
            Counter(
                index[s.test_guid].executor
                for sc in scenarios
                for s in sc.steps
                if s.test_guid in index
            )
        ),
    }
    return problems, coverage
