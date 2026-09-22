# DECISIONS.md — running log (append only)

## 2026-09-21 — Phase 0 verification
- **Zero-cost policy adopted** (see COST.md). Supersedes the original brief where they conflict: no paid
  Anthropic run; LLM reasoner moves to Ollama (default) with Groq/Gemini free tiers as cloud fallback;
  Phase 2 hosting on Oracle Cloud Always Free or Render free, not Fly.io; analytics via self-hosted
  Umami or PostHog free, not Plausible.
- **Phase 0 step 4 (LLM run) deferred to Phase 1**: no key, no Ollama, policy forbids paid calls, and
  `anthropic`/`openai` are not even declared dependencies (STATUS.md §4).
- **Proposed, awaiting approval (dependency changes per CLAUDE.md):** pin `pyparsing<3.3.3`
  (pysigma 1.5.0 breaks on 3.3.3); add `lightgbm` + `scikit-learn` to a `[train]` extra.
- **Benchmark numbers will be regenerated, not hand-edited.** Committed RESULTS.md predates code
  changes; the next commit that touches numbers also commits `bench/results/<date>_<sha>_*.json`.
- Frozen manifest is reproducible (content-identical to 13 Sep except `created`); `bench build` will
  be changed to refuse rewriting an unchanged manifest rather than bumping the timestamp.

## 2026-09-22 — Phase 0 fixes (B1–B3), Frist24 working process adopted
- Process: same as Frist24 — verify here with venv/npm, Docker + Ollama on the user's second laptop,
  commit per step locally, never push without being asked, ask only when blocking.
- B1: `pyparsing<3.3.3` pinned in core deps (a constraint on an existing transitive dep, not a new
  dependency). `lab rules` now exits 2 when either backend converts < 90% of rules
  (`--min-conversion`, default 0.9; the healthy pack is 97%/100%).
- B2: `lightgbm` added to core deps rather than a `[train]` extra because `aegis/models/triage.py`
  (inference, used by `bench run --triage` and the graph fast-path) imports it; CPU wheel, ~3 MB.
  `scikit-learn` turned out not to be imported anywhere — not added.
- B3: `bench build` writes the frozen manifest only when `manifest_hash` changes; an unchanged
  rebuild leaves the committed file byte-identical, a changed one raises and asks for a new
  BENCH_VERSION + RESULTS.md entry.

## 2026-09-22 — B5 zero-cost LLM path
- Providers are raw httpx calls (Ollama `/api/chat` JSON mode, Groq/OpenAI-compatible, Gemini
  `generateContent`), no vendor SDKs: removes the undeclared `anthropic`/`openai` imports and keeps
  the dependency list unchanged. Paid endpoints stay in the file but are refused unless
  `AEGIS_ALLOW_PAID_PROVIDERS=1`.
- `auto` order is Ollama → Groq → Gemini. Ollama is probed once per router with a 2 s `/api/tags`
  call; the result is cached so `/health` polling does not hammer it.
- Budget caps default to 60 LLM calls per run (an investigation makes ~5–8) and 300k tokens per
  day, persisted in `data/budget.json`. A cap or a provider outage raises `DegradedError`, which
  `LLMReasoner` turns into a deterministic answer and counts in `reasoner.fallbacks`.
- Pulse docs (fetched 2026-09-22) expose `create_schema`, `insert_data`, `select_data`,
  `update_data`, `delete_data`, `chat` with `Authorization: Bearer` and a `data_payload` body — not
  the `bulk_insert`/`upsert_data`/`count`/`analytics` verbs in the brief. Phase 1 client implements
  the documented verbs and composes the rest (batched inserts, select+update upsert, select+len
  count, `chat` for analytics). Flagged to the owner in the Phase 1 report.
