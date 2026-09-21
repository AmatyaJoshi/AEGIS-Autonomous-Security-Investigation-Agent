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
| Ollama (local, Docker host) | LLM reasoner, default provider | Free (own compute) | `BUDGET_LLM_CALLS_PER_RUN`, `BUDGET_LLM_TOKENS_PER_DAY` | Router switches to the deterministic `HeuristicReasoner`, UI shows DEGRADED | planned (Phase 1) |
| Groq / Google Gemini free tier | Cloud LLM fallback only, no card on file | Groq: ~14,400 req/day on small models; Gemini: 1,500 req/day on Flash (verify at time of use) | Same `BUDGET_LLM_*` guards; provider chosen by `AEGIS_LLM_PROVIDER` | Same DEGRADED fallback; never a paid retry | planned (Phase 1) |
| Anthropic / OpenAI API | Previously wired in `aegis/llm/router.py` | **Paid** | Not to be used without an explicit stop-and-ask; no key is set in any environment | n/a | not used |
| Oracle Cloud Always Free ARM VM | Host API + UI for the judge (Phase 2) | 4 OCPU / 24 GB always free | Docker Compose only; no paid shapes; snapshot data only | Render free tier as backup (accept sleep) | planned (Phase 2) |
| Vercel Hobby or Cloudflare Pages | Next.js frontend (Phase 2, optional) | Hobby: non-commercial, 100 GB bandwidth | Static build | Serve UI from the VM instead | planned (Phase 2) |
| Umami (self-hosted) or PostHog free | Basic traffic analytics (Phase 2) | Self-hosted: free; PostHog: 1M events/month | Page-view events only | Disable the script | planned (Phase 2) |
| DuckDNS + Caddy (Let's Encrypt) | TLS on a free subdomain | Free | n/a | Use the VM's IP | planned (Phase 2) |
| Elasticsearch / Kibana / Postgres / Redis | Optional full lab via Docker Compose | Free, self-hosted | Not needed for the demo (`--source offline`) | n/a | optional |

## Rules enforced

- No payment card is attached to any account used by this project.
- Every outbound host must appear in this table. Phase 1 adds a startup log that lists the outbound
  allow-list and fails closed on anything else.
- `/health` exposes `cost_mode: normal|degraded`; the UI shows a badge when degraded.
- Tests assert that each guard trips into degraded mode rather than raising or retrying against a paid
  provider.
- End of every build step: a one-line cost check (services touched, calls made, credits used, risk of
  crossing a limit before Wed 30 Sep 2026).

## Cost log

| Date | Step | Services touched | Calls | Credits used | Risk |
|---|---|---|---|---|---|
| 2026-09-21 | Phase 0 verification | GitHub raw (dataset download, one fresh clone) | ~1 tree call + ~150 raw downloads | 0 | none |
