# TODO.md — deferred items and cuts

## Deferred (not cut)
- LLM-reasoner benchmark numbers: run `aegis bench run --split test --reasoner llm --limit 20` on the
  Docker laptop (Ollama) or with a Groq/Gemini key, then `bench report`; add the second block to README.
- Live Pulse integration test (`pytest -m network tests/test_memory.py`) once the key arrives.
- Browser walk-through of the review UI (queue → case → approve → Memory panel) on the Docker laptop.
- Route auth audit: `/api/queue`, `/api/metrics`, `/api/memory`, `/api/investigations/{id}` are
  readable without a token; decide before the public deploy whether viewers need to log in.
- Deploy to the Oracle Always Free VM per docs/DEPLOY.md and record the link in DEVPOST.md.
- Record the 3-minute video (script in docs/DEVPOST.md).

## Cuts
- Real Pulse `bulk_insert`/`upsert_data`/`count`/`analytics` verbs: not in the documented API;
  composed from documented verbs instead (DECISIONS.md 2026-09-22).
- Plausible analytics and Fly.io hosting from the original brief: replaced by self-hosted Umami and
  Oracle/Render per the zero-cost policy.

## Cuts
- None yet.
