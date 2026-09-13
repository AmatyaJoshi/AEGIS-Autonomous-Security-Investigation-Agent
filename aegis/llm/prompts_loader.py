"""Load versioned prompt templates from ``aegis/llm/prompts/*.md``."""

from __future__ import annotations

import re
from functools import lru_cache
from pathlib import Path

_DIR = Path(__file__).parent / "prompts"
_VERSION_RE = re.compile(r"<!--\s*version:\s*(\d+)\s*-->")


@lru_cache(maxsize=16)
def load_prompt(name: str) -> str:
    return (_DIR / f"{name}.md").read_text(encoding="utf-8")


@lru_cache(maxsize=16)
def prompt_version(name: str) -> int:
    m = _VERSION_RE.search(load_prompt(name))
    return int(m.group(1)) if m else 0


def prompt_versions() -> dict[str, int]:
    return {p.stem: prompt_version(p.stem) for p in _DIR.glob("*.md")}
