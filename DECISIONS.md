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
