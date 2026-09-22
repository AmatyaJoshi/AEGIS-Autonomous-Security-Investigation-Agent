# COST.md — zero-cost policy for AEGIS

This project must cost the team **$0**. Every external service, hosted dependency, model API, domain or
analytics tool is listed here with its free-tier limit, the in-code guard that keeps us under it, and
what happens when the limit is hit. Anything not on this list is not allowed to make an outbound call.

Status legend: **live** = in the code today · **planned** = scheduled for the phase named · **not used**.

| Service | Purpose | Free-tier limit | In-code guard | When the limit is hit | Status |
|---|---|---|---|---|---|
| GitHub (public repo) | Source, CI (GitHub Actions) | 2,000 min/month Actions on public repos is unlimited; keep jobs <10 min | CI workflow runs lint + tests + offline smoke only | CI fails to run; nothing else | live |
| GitHub raw / codeload | One-time download of OTRF Security-Datasets and EVTX-ATTACK-SAMPLES (~140 MB) | Unauthenticated: 60 API req/h for the tree call; raw downloads unmetered | Tree response cached in `data/raw/otrf/_tree.json`; `lab load --no-download` reuses the cache | Loader logs a warning and continues with cached files | live |
| SigmaHQ release bundle | `lab rules` downloads `sigma_core++.zip` once | Unmetered | Cached under `data/raw/sigma` | Same | live |
| MITRE ATT&CK STIX | `attack_kb` | Unmetered, compacted copy under `data/` | Offline compacted KB | n/a | live |
| Evorozen Neural Pulse | Case memory + priors + one cached `analytics` answer (Phase 1) | Free tier ~50 calls; quota requested | `BUDGET_PULSE_CALLS_PER_DAY` (default 40); one `bulk_insert` per investigation batch, priors read cached for 10 min, `analytics` cached per day; `AEGIS_MEMORY_BACKEND=auto` | Falls back to `LocalStore` (SQLite), UI shows "memory: local", `/health` reports `cost_mode: degraded` | planned (Phase 1) |
| Ollama (local, Docker host) | LLM reasoner, default provider (`AEGIS_OLLAMA_URL`) | Free (own compute) | `BUDGET_LLM_CALLS_PER_RUN` (60), `BUDGET_LLM_TOKENS_PER_DAY` (300k), 2 s liveness probe, 180 s call timeout, content-hash cache | Router raises `DegradedError`; `LLMReasoner` answers with the deterministic reasoner; `/health.cost_mode=degraded` | live (`aegis/llm/router.py`, `tests/test_llm_router.py`) |
| Groq / Google Gemini free tier | Cloud LLM fallback only, no card on file (`GROQ_API_KEY`, `GEMINI_API_KEY`) | Groq: ~14,400 req/day on small models; Gemini: 1,500 req/day on Flash (verify at time of use) | Same `BUDGET_LLM_*` guards; `AEGIS_LLM_PROVIDER=auto` tries Ollama → Groq → Gemini; plain httpx, no SDKs | Same degraded fallback; never a paid retry | live |
| Anthropic / OpenAI API | Kept in the router for completeness | **Paid** | Refused unless `AEGIS_ALLOW_PAID_PROVIDERS=1` is set explicitly *and* a key exists; nothing in the repo sets it (`test_paid_providers_disabled_by_default`) | n/a | disabled |
| Oracle Cloud Always Free ARM VM | Host API + UI for the judge (Phase 2) | 4 OCPU / 24 GB always free | Docker Compose only; no paid shapes; snapshot data only | Render free tier as backup (accept sleep) | planned (Phase 2) |
| Vercel Hobby or Cloudflare Pages | Next.js frontend (Phase 2, optional) | Hobby: non-commercial, 100 GB bandwidth | Static build | Serve UI from the VM instead | planned (Phase 2) |
| Umami (self-hosted) or PostHog free | Basic traffic analytics (Phase 2) | Self-hosted: free; PostHog: 1M events/month | Page-view events only | Disable the script | planned (Phase 2) |
| DuckDNS + Caddy (Let's Encrypt) | TLS on a free subdomain | Free | n/a | Use the VM's IP | planned (Phase 2) |
| Elasticsearch / Kibana / Postgres / Redis | Optional full lab via Docker Compose | Free, self-hosted | Not needed for the demo (`--source offline`) | n/a | optional |

## Rules enforced

- No payment card is attached to any account used by this project.
- Every outbound host must appear in this table and in `OUTBOUND_ALLOWLIST` (`aegis/llm/budget.py`).
  `aegis serve` and `aegis investigate` log the list at startup; a request to any other host raises
  before a socket opens (`test_outbound_allowlist_fails_closed`).
- `/health` exposes `cost_mode: normal|degraded`; the UI shows a badge when degraded.
- Tests assert that each guard trips into degraded mode rather than raising or retrying against a paid
  provider.
- End of every build step: a one-line cost check (services touched, calls made, credits used, risk of
  crossing a limit before Wed 30 Sep 2026).

## Cost log

| Date | Step | Services touched | Calls | Credits used | Risk |
|---|---|---|---|---|---|
| 2026-09-21 | Phase 0 verification | GitHub raw (dataset download, one fresh clone) | ~1 tree call + ~150 raw downloads | 0 | none |
| 2026-09-22 | B5 zero-cost LLM path | none (all tests use httpx.MockTransport) | 0 | 0 | none |
