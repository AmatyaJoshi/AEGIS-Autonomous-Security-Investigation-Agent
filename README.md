# AEGIS — the SOC analyst that cites every claim

AEGIS is an autonomous Tier-1/Tier-2 SOC investigation agent. It ingests security alerts from a SIEM,
normalises them to OCSF, and for each alert does what a human analyst would: gathers context from
logs, identity and asset systems, enriches indicators with threat intelligence, forms competing
hypotheses, queries the log store to confirm or refute each one, reconstructs the attack timeline,
maps behaviour to MITRE ATT&CK, issues a verdict (true positive / false positive / escalate) with a
calibrated confidence, and writes an incident report in which **every factual claim cites the exact
log events it relies on**. Humans handle only escalations.

**Response actions are recommended, never executed.** AEGIS augments analysts and escalates
containment decisions to people. It is measured on a 420-alert, ATT&CK-stratified, labelled benchmark
against four comparison arms, hardened by an adversarial log-injection track, and instrumented with
OpenTelemetry.

> **Status (22 Sep 2026):** every phase in [SPEC.md](SPEC.md) is built and green; a fresh-clone
> verification pass with what runs, what does not and what changed is in [STATUS.md](STATUS.md).
> Every number below has a committed results file and a command that regenerates it
> ([RESULTS.md](RESULTS.md)). The whole pipeline runs **offline for $0**: no GPU, no paid API. See
> [COST.md](COST.md).

---

## Run it in 3 commands

```bash
make install      # uv venv + Python deps + web deps  (Python 3.12, uv, Node 22)
make data         # public datasets -> Parquet snapshot -> 420-alert benchmark -> triage model (~25 min, once)
make demo         # reset -> investigate 1 TP + 3 FP + 1 ambiguous -> prints the case URL to open
```

Then `make api` and `make web` in two terminals and open http://localhost:3000 (login
`analyst@aegis.local` / `aegis1234`). Approve the ambiguous case; the **Metrics › Case memory** panel
updates. Docker instead: `make up` (api + web + Ollama). No `make`? Every target is a one-line
`python -m aegis.cli …` command listed in the [Makefile](Makefile).

---

## Why this is autonomous B2B SaaS

A SOC's Tier-1 job is a department: thousands of alerts a day, most false positives, each needing the
same 20-minute investigation. AEGIS runs that department. It takes the alert queue end to end and
returns a verdict, a cited report and a recommended playbook, and it **learns** from every analyst
decision through a case memory that feeds the next triage. Humans see only what is escalated or what
they choose to review. Auditability is built in: every claim cites a log event id, every verdict stores
its hypotheses, queries, evidence ids and model/prompt versions, and no tool can change a system.

Who pays and how: MSSPs and mid-market SOCs drowning in Tier-1 volume; priced per alert investigated
plus a platform fee; distributed through SIEM marketplaces (Elastic, Splunk) where the alerts already
live. Details and the pilot offer are in [docs/DEVPOST.md](docs/DEVPOST.md).

---

## How the AI layer works

Three models, one deterministic graph, and a hard rule that AI output is never trusted unchecked.

| Layer | What it does | How it is kept honest |
|---|---|---|
| **Reasoner** (LangGraph `hypothesize → evidence → verdict → report`) | Forms competing hypotheses, chooses which scoped SIEM queries to run, weighs evidence, decides, writes the report | Every output validates against a Pydantic schema (`aegis/llm/schemas.py`); prompts are versioned (`aegis/llm/prompts/*.md`); the **citation post-processor** rejects any report sentence without a `[E:<event_id>]` that resolves to a real event and falls back to an always-cited deterministic renderer. Tool output arrives in `<data>` envelopes the system prompt treats as data, and an **injection guard** scans every attacker-influenceable field and forces `escalate` on a hit. |
| **Triage classifier** (LightGBM, trained on CPU from the benchmark's train split) | Gives `p_tp / p_fp / p_escalate` before the investigation; fast-paths obvious false positives; blended into the final malicious score | Trained, evaluated and integrated with a model card (`training/MODEL_CARDS/triage_classifier.md`); AUROC 1.00, ECE 0.002 on the held-out test split. Its `p_tp` is blended with the **case-memory prior** at weight n/(n+20) and both numbers are logged on the OTel span and shown in the UI. |
| **NL→SIEM query generator** (template generator offline; Qwen2.5-Coder LoRA when a GPU is available) | Turns an investigative intent into a scoped ES\|QL / SPL / SQL query | **Every generated query must pass `aegis/siem/validator`** (read-only, scoped, single statement, no bypass flag) before it executes. Evaluated by execution equivalence on the DuckDB snapshot, not string match: 100% on the curated set. |

**Which LLM, and what it costs:** the reasoner talks to a local **Ollama** (`llama3.1:8b` by default) or
the **Groq** / **Gemini** free tiers over plain HTTP; paid providers are refused unless explicitly
enabled. Every call passes a budget guard (`BUDGET_LLM_CALLS_PER_RUN`, `BUDGET_LLM_TOKENS_PER_DAY`) and
an outbound host allow-list. When no provider is reachable, or a cap is hit, the same graph runs the
deterministic `HeuristicReasoner`, `/health` reports `cost_mode: degraded` and the UI header says
**DEGRADED · deterministic**. Nothing is silently faked.

---

## How Evorozen Neural Pulse is used

Pulse is AEGIS's **case memory and analytics layer, not the reasoner**. After every investigation AEGIS
writes one metadata-only case record (`aegis_cases`); after every analyst approve/override it writes
one feedback record (`aegis_feedback`); once per batch it upserts learned **priors** per ATT&CK
technique and alert source (`aegis_priors`: n, tp_rate, escalate_rate, analyst_override_rate). The
read path is visible: `triage_pre` blends the LightGBM `p_tp` with the prior's `tp_rate` at weight
n/(n+20), and the review UI's **Memory** panel shows TP-rate by technique, the analyst-override rate,
`priors source: pulse|local`, and one cached Pulse `analytics` answer ("Which techniques most often end
as false positives this month?"). Pulse calls are capped per day and cached; if Pulse is unreachable or
the key is unset the same interface writes to a local SQLite table and the UI shows **memory: local**.

> **Pulse receives metadata only.** Each case record contains: a salted hash of the tenant id, ATT&CK
> technique ids, the alert source name, input severity, verdict, confidence, escalation flag, the
> triage model probability, reasoner kind, model name, prompt versions, counts of hypotheses / queries
> / evidence, duration and cost. Analyst feedback records contain the case id, the analyst verdict, an
> agreed flag and a reason code. **Never sent:** raw log events, hostnames, usernames, IP addresses,
> alert titles or text, command lines, or report bodies. The record builder
> (`aegis/memory/store.py::CaseRecord`) has no access to those fields and `tests/test_memory.py`
> asserts that nothing identifying survives serialisation. Hostnames and usernames that must appear in
> prompts to an external LLM go through the pseudonymiser first (`aegis/security/redaction.py`).

Configuration: `AEGIS_PULSE_API_KEY`, `AEGIS_PULSE_BASE_URL`, `AEGIS_MEMORY_BACKEND=auto|pulse|local`,
`BUDGET_PULSE_CALLS_PER_DAY` (default 40). Request contract verified against the Pulse docs
(`POST /api/neural`, Bearer auth, `{action_type, prompt, data_payload}`); see
[SECURITY.md](SECURITY.md) and `aegis/memory/pulse_client.py`.

---

## Benchmark results (held-out test split, 104 alerts)

### Deterministic reasoner (offline, $0)

| Arm | Verdict accuracy | Macro-F1 | FP-suppression @ ≤2% missed-TP | Escalation precision | Citations |
|---|---:|---:|---:|---:|---:|
| Rules only | 45% | 0.23 | 31% | 100% | 100% |
| Single-shot reasoner (alert only, no context) | 52% | 0.26 | 62% | 0% | 100% |
| AEGIS (no triage model) | **89%** | **0.88** | 29% | 100% | 100% |
| **AEGIS full (+ triage model)** | **89%** | **0.88** | **90%** | 71% | 100% |

Source: [`bench/results/20260922_1737a3e_bench_test_heuristic.json`](bench/results/20260922_1737a3e_bench_test_heuristic.json).
Regenerate: `aegis bench run --split test --triage training/triage/artifacts/model.txt && aegis bench report --split test`.

- The **triage classifier** lifts false-positive suppression from 29% to **90%** at 0% missed
  true-positives, clearing the ≥60% target. 9 of 10 fp_types are fully suppressed;
  `service_account_lockout` is the hard class.
- AEGIS beats rules-only by **+44 points** of accuracy and the single-shot arm by **+37 points**:
  context and investigation drive the result, not just the model.
- **100% of factual claims are cited** to a real log event in every report.

### LLM reasoner (Ollama / Groq / Gemini, $0 tiers)

**Not yet measured.** The LLM path is wired, budget-guarded and unit-tested against recorded
responses, but no free provider was reachable on the verification machine, so no number is claimed.
Measure it on a machine with Ollama (or a Groq/Gemini key) with:

```bash
aegis bench run --split test --reasoner llm --limit 20 --triage training/triage/artifacts/model.txt
aegis bench report --split test      # archives bench/results/<date>_<sha>_bench_test_llm.json
```

The report will land next to the deterministic one and this table gets a second block. Until then the
README makes no LLM-accuracy claim.

### Adversarial injection track (75 variants, 5 categories)

| Metric | Guard OFF | Guard ON |
|---|---:|---:|
| Verdict-flip rate (TP → auto-closed FP) | 0% | 0% |
| Injection detection rate | 0% | **100%** |
| Report contamination rate | 0% | 0% |

Source: [`bench/results/20260922_1737a3e_adversarial.json`](bench/results/20260922_1737a3e_adversarial.json).
The deterministic reasoner scores from real indicators, so it does not flip even with the guard off;
the guard is defence-in-depth for the LLM path.

### Lens gate (40 alerts): report faithfulness 100%, tool-call correctness 100%, verdict accuracy 90%

Source: [`bench/results/20260922_1737a3e_lens_ci.json`](bench/results/20260922_1737a3e_lens_ci.json). `aegis lens ci` fails CI on a breach.

---

## Architecture

```
 LAB DATA PLANE (reproducible)                    AEGIS CORE (LangGraph)
 ─────────────────────────────                    ─────────────────────
 OTRF / EVTX / BOTS / CIC-IDS ─┐                   normalize ─▶ context ─▶ triage_pre ◀── priors (Pulse | local)
 Atomic Red Team scenarios ────┼─▶ ground-truth      │ (asset/identity/TI/sigma)   │ blend p_tp, fast-path
 Benign-noise generators ──────┘   windows            ▼                            ▼
        │                                          hypothesize ─▶ evidence ─▶ timeline
        ▼  (Sigma-match)                              │ (siem_query, validated)     │
   OCSF detection_finding ────────────────────────▶ attack_map ─▶ verdict ─▶ report ─▶ playbook
        │                                                 │ (blend triage p_tp)  │ (cited)  (recommend)
  Parquet snapshot ◀── DuckDB (offline SIEM)              ▼                     ▼
                                                    Review queue (FastAPI + Next.js) ─▶ analyst approve/override
 Triage model (LightGBM) ─┐                              │                                  │
 NL→query model (Qwen LoRA)┼─ served ────────────────────┘                                  ▼
 LLM: Ollama | Groq | Gemini (budget-guarded, degrades to deterministic)     case memory: Pulse (metadata) | local
                          OpenTelemetry ─▶ Lens (report faithfulness, tool correctness, calibration)
```

---

## Full Quickstart (what `make data` and `make demo` run)

```bash
uv venv --python 3.12 && uv pip install -e ".[dev]"

# 1) Lab data plane -> immutable snapshot
python -m aegis.cli lab load  --datasets otrf,evtx    # public datasets -> Parquet + ground truth
python -m aegis.cli lab noise --days 14 --per-day 12  # benign false-positive telemetry
python -m aegis.cli lab rules                          # Sigma pack -> ES|QL + SPL (fails <90% conversion)
python -m aegis.cli bench prepare                      # materialise benchmark noise + ambiguous
python -m aegis.cli lab snapshot --name dev            # hashed Parquet snapshot for --offline

# 2) Investigate alerts end-to-end (LLM if reachable, else deterministic; memory: pulse|local)
python -m aegis.cli investigate --source offline --limit 5

# 3) Build the benchmark, then train the triage model (LightGBM, CPU)
python -m aegis.cli bench build
python -m training.triage.build_dataset --snapshot dev
python -m training.triage.train
python -m training.triage.eval

# 4) Run 4 arms, score, report.html; results archived to bench/results/
python -m aegis.cli bench run --split test --triage training/triage/artifacts/model.txt
python -m aegis.cli bench report --split test
python -m aegis.cli bench adversarial

# 5) NL->query corpus + execution-equivalence eval
python -m training.query_gen.build_pairs --n-intent 8000
python -m training.query_gen.eval_exec --snapshot dev

# 6) Lens metrics + CI gate
python -m aegis.cli lens ci --limit 40

# 7) Demo + review UI
python -m aegis.cli demo
python -m aegis.cli serve                               # API on :8000
cd web && npm install && npm run dev                    # UI on :3000
python -m aegis.cli memory show                         # priors + analytics answer
```

Environment: `.env.example` lists every variable. LLM: `AEGIS_LLM_PROVIDER=auto|ollama|groq|gemini`,
`AEGIS_OLLAMA_URL`, `GROQ_API_KEY`, `GEMINI_API_KEY`. Memory: `AEGIS_PULSE_API_KEY`,
`AEGIS_MEMORY_BACKEND`. Budgets: `BUDGET_*`. Deployment for $0: [docs/DEPLOY.md](docs/DEPLOY.md).

---

## Guardrails (SPEC §9 — enforced in code, not just documented)

1. **Recommend-only.** No tool can mutate the environment. The offline SIEM adapter and the query
   validator reject every `INSERT`/`UPDATE`/`DELETE`/`DROP`/multi-statement query with no bypass flag
   (`tests/test_validator.py`, `tests/test_duckdb_siem.py`). Playbooks are text with `requires_approval`.
2. **Separate credentials.** The agent uses a read-only Elasticsearch key; only `lab/` loaders use a writer key.
3. **No offensive content.** Lab attack telemetry comes from published Atomic Red Team tests and public
   datasets; a scanner asserts generated telemetry contains no payload markers.
4. **Injection guard.** Every attacker-influenceable free-text field is scanned; flagged content is
   redacted and forces `escalate`. Tool output is wrapped in `<data>` envelopes. Measured end-to-end.
5. **Evidence or silence.** Reports with uncited claims are rejected by the post-processor.
6. **Full audit trail.** Every verdict stores hypotheses, queries, evidence ids, model + prompt versions.
7. **Zero cost, fail closed.** Outbound hosts are allow-listed and logged at startup; budget caps trip
   into a visible degraded mode, never a paid retry ([COST.md](COST.md), `tests/test_llm_router.py`).
8. **Metadata-only memory.** See the Pulse boundary above ([SECURITY.md](SECURITY.md)).

---

## Limitations (honest list)

- LLM-reasoner benchmark numbers are not yet measured (command above); all headline numbers are the
  deterministic reasoner.
- Ambiguous alerts are author-labelled; no independent co-labeller, so Cohen's kappa is not computed.
- Technique-F1 is low (~0.06) because a TP alert reports the detecting rule's technique, which often
  differs from the dataset window's label.
- `service_account_lockout` false positives (password-spray look-alikes) are still called true positive.
- The Qwen2.5-Coder LoRA and the DeBERTa triage alternative need a GPU to train; the offline template
  generator and LightGBM are what is measured.
- Pulse's documented API has no bulk/upsert/count/analytics verbs; the client composes them from
  `insert_data`, `select_data`, `update_data` and `chat`, one call each, inside the daily cap.
- Live SIEM ingestion (Elastic/Splunk) is wired but the demo uses the offline snapshot.

---

## Repository layout

| Path | What |
|---|---|
| `aegis/schema/` | OCSF 1.3 models + source normalisers (Sigma / Elastic / Splunk) |
| `aegis/siem/` | Read-only SIEM adapters + the query validator (no bypass) |
| `aegis/tools/` | siem_query, ti_lookup, asset/identity_lookup, attack_kb, sigma_match, geoip, py_stats |
| `aegis/graph/` | LangGraph state, nodes, reasoners (deterministic + LLM), citation post-processor, runner |
| `aegis/llm/` | Router (Ollama / Groq / Gemini over httpx), budget guard + allow-list, versioned prompts, schemas |
| `aegis/memory/` | Case memory: Pulse client, local SQLite store, priors + triage blend |
| `aegis/models/` | Triage + NL→query inference wrappers |
| `aegis/security/` | Injection guard + `<data>` envelopes, PII pseudonymiser |
| `aegis/api/` | FastAPI review backend, auth, `/api/memory`, `/health` with `cost_mode` |
| `aegis/lens/` | Lens-style eval metrics + `lens ci` gate |
| `aegis/demo.py` | The three-minute demo (`aegis demo`) |
| `lab/` | Telemetry loaders, Atomic Red Team scenarios/runner, noise generators, Sigma pack, snapshots |
| `bench/` | Benchmark build/run/score, `report.html`, adversarial track, `results/` archive |
| `training/` | Triage (LightGBM/DeBERTa) and NL→query (Qwen LoRA) pipelines + model cards + results |
| `web/` | Next.js 15 review UI (queue, investigation, metrics + Memory panel, copilot) |
| `docs/` | `DEVPOST.md` (pitch, GTM, video script), `DEPLOY.md` ($0 hosting) |

## Development

```bash
make test        # ruff, ruff format --check, mypy --strict (aegis/), pytest, tsc
```

CI (`.github/workflows/ci.yml`) runs the same gates plus an offline smoke test and the `lens ci` gate.
No test makes a live LLM or external API call; the one live Pulse test is `network`-marked and skipped
without a key.

## Data provenance & licensing

AEGIS indexes third-party datasets under their own licences: OTRF Security-Datasets (Microsoft),
EVTX-ATTACK-SAMPLES (@sbousseaden), Splunk BOTS, CIC-IDS2017 (UNB), Sigma (SigmaHQ, DRL-1.1), Atomic
Red Team (Red Canary, MIT), MITRE ATT&CK (Apache-2.0). Raw datasets and generated artefacts are not
committed; loaders fetch or expect a local copy. AEGIS's own code is Apache-2.0.
