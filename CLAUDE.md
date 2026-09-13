# AEGIS — conventions for Claude Code
- Read SPEC.md first. §9 guardrails are inviolable: no tool may mutate systems; SIEM credentials are read-only; no offensive content in prompts, code or data generators.
- Python 3.12, uv, ruff (100 cols), mypy --strict on aegis/. TS strict in web/.
- All alerts/events are OCSF Pydantic models; never pass raw dicts between nodes.
- Every LLM output validates against a schema in aegis/llm/schemas.py. Prompts live in aegis/llm/prompts/*.md and are versioned.
- Every tool wraps its output in a <data> envelope and is unit-tested with recorded fixtures; no live LLM or external API calls in tests.
- Generated SIEM queries must pass aegis/siem/validator before execution — no exceptions, no bypass flags.
- Benchmark manifests are frozen; changing one requires a new version file and a RESULTS.md entry.
- No metric appears in README without a training/results or bench/results file.
- One phase = one PR; conventional commits; ask before adding dependencies.
