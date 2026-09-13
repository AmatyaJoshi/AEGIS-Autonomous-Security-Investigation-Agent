"""Shared fixtures. No test makes live LLM or external API calls (CLAUDE.md)."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture(scope="session")
def sysmon_lsass_event() -> dict:
    return json.loads((FIXTURES / "sysmon_procdump_lsass.json").read_text(encoding="utf-8"))


@pytest.fixture(scope="session")
def security_4624_event() -> dict:
    return json.loads((FIXTURES / "security_4624_logon.json").read_text(encoding="utf-8"))


@pytest.fixture
def start_ts() -> datetime:
    return datetime(2025, 1, 6, tzinfo=UTC)
