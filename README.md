# AEGIS — Autonomous SOC Investigation Agent

AEGIS is a LangGraph-based autonomous Tier-1/Tier-2 SOC analyst. It ingests security alerts from a
SIEM, normalises them to the OCSF schema, and for each alert performs the investigation a human
analyst would: it gathers context from logs, identity and asset systems, enriches indicators with
threat intelligence, forms competing hypotheses, queries the log store to confirm or refute each
one, reconstructs the attack timeline, maps behaviour to MITRE ATT&CK, issues a verdict
(true positive / false positive / escalate) with a calibrated confidence, and writes an incident
report in which **every claim cites the exact log events it relies on**.

**Response actions are recommended, never executed.** AEGIS augments analysts and escalates
containment decisions to humans. It is measured on a 420-alert, ATT&CK-stratified, labelled
benchmark against four comparison arms, and instrumented end-to-end with OpenTelemetry.

> **Status:** Phases 0–8 are built and green. See [RESULTS.md](RESULTS.md) for every measured number
> with the command that regenerates it. Nothing here needs a GPU or API key: the whole pipeline runs
> offline with a deterministic reasoner; with an `ANTHROPIC_API_KEY` the same graph uses an LLM
> reasoner, and with a GPU the two fine-tuned models train.

---

## Headline results (held-out test split, offline)

| Arm | Verdict accuracy | FP-suppression @ ≤2% missed-TP | Escalation precision | Citations |
|---|---:|---:|---:|---:|
| Rules only | 45% | 31% | 100% | 100% |
| Single-shot LLM (alert only) | 52% | 62% | 0% | 100% |
| AEGIS (no triage model) | **88%** | 31% | 100% | 100% |
| **AEGIS full (+ triage model)** | **88%** | **90%** | 60% | 100% |

- The **triage classifier** (LightGBM, AUROC 1.00) lifts false-positive suppression from 31% to
  **90%** at 0% missed true-positives — clearing the ≥60% target.
- AEGIS beats rules-only by **+43%** accuracy and single-shot LLM by **+36%**: context and
  investigation drive the result, not just the model.
- Every incident report passes the citation post-processor: **100% of factual claims are cited** to a
  real log event.
- **Adversarial injection track:** the guard detects **100%** of a 60-variant, 5-category injection
  corpus and reports are never contaminated; the deterministic reasoner shows a 0% verdict-flip rate.
- **NL→SIEM query generator:** 100% execution-equivalence on curated cases; 18,976 Sigma-derived +
  investigative training pairs for the Qwen2.5-Coder LoRA.

---

## Architecture

```
 LAB DATA PLANE (reproducible)                    AEGIS CORE (LangGraph)
 ─────────────────────────────                    ─────────────────────
 OTRF / EVTX / BOTS / CIC-IDS ─┐                   normalize ─▶ context ─▶ triage_pre
 Atomic Red Team scenarios ────┼─▶ ground-truth      │ (asset/identity/TI/sigma)   │ fast-path
 Benign-noise generators ──────┘   windows            ▼                            ▼
        │                                          hypothesize ─▶ evidence ─▶ timeline
        ▼  (Sigma-match)                              │ (siem_query, validated)     │
   OCSF detection_finding ────────────────────────▶ attack_map ─▶ verdict ─▶ report ─▶ playbook
        │                                                 │ (blend triage p_tp)  │ (cited)  (recommend)
  Parquet snapshot ◀── DuckDB (offline SIEM)              ▼
                                                    Review queue (FastAPI + Next.js)
 Triage model (LightGBM) ─┐                              │
 NL→query model (Qwen LoRA)┼─ served ────────────────────┘
                          OpenTelemetry ─▶ Lens (report faithfulness, tool correctness, calibration)
```

---

## Quickstart (offline, no external services)

Requires Python 3.12 and [uv](https://docs.astral.sh/uv/).

```bash
uv venv --python 3.12 && uv pip install -e ".[dev]"

# 1) Lab data plane -> immutable snapshot
python -m aegis.cli lab load  --datasets otrf,evtx    # public datasets -> Parquet + ground truth
python -m aegis.cli lab noise --days 14 --per-day 12  # benign false-positive telemetry
python -m aegis.cli lab rules                          # Sigma pack -> ES|QL + SPL
python -m aegis.cli bench prepare                      # materialise benchmark noise + ambiguous
python -m aegis.cli lab snapshot --name dev            # hashed Parquet snapshot for --offline

# 2) Investigate alerts end-to-end
python -m aegis.cli investigate --source offline --limit 5

# 3) Benchmark: build, run 4 arms, score, report.html
python -m aegis.cli bench build
python -m aegis.cli bench run --split test
python -m aegis.cli bench report --split test          # -> data/benchmark/results/report.html
python -m aegis.cli bench adversarial                  # injection track, guard off vs on

# 4) Train + integrate the triage model (LightGBM, CPU)
python -m training.triage.build_dataset --snapshot dev
python -m training.triage.train
python -m training.triage.eval
python -m aegis.cli bench run --split test --triage training/triage/artifacts/model.txt

# 5) NL->query model corpus + execution-equivalence eval
python -m training.query_gen.build_pairs --n-intent 8000
python -m training.query_gen.eval_exec --snapshot dev

# 6) Lens metrics + CI gate
python -m aegis.cli lens ci --limit 40

# 7) Review UI
python -m aegis.cli serve                               # API on :8000
cd web && npm install && npm run dev                    # UI on :3000
```

The lab SIEM (Elasticsearch/Kibana) and VMs are optional; see the "Full lab" section in
[SPEC.md](SPEC.md) §5. `docker compose -f docker-compose.yml -f docker-compose.lab.yml up -d` brings
up Postgres, Redis, Elasticsearch and Kibana.

---

## Guardrails (§9 — enforced in code, not just documented)

1. **Recommend-only.** No tool can mutate the environment. The offline SIEM adapter and the query
   validator reject every `INSERT`/`UPDATE`/`DELETE`/`DROP`/multi-statement query with no bypass
   flag (`tests/test_validator.py`, `tests/test_duckdb_siem.py`). Playbooks are text with
   `requires_approval` flags.
2. **Separate credentials.** The agent uses a read-only Elasticsearch key; only `lab/` loaders use a
   writer key.
3. **No offensive content.** Lab attack telemetry comes from published Atomic Red Team tests and
   public datasets; a scanner asserts generated telemetry contains no payload markers.
4. **Injection guard.** Every attacker-influenceable free-text field is scanned; flagged content is
   redacted and forces `escalate`. Tool output is wrapped in `<data>` envelopes that the system
   prompt treats as data, never instructions. The adversarial track measures this end-to-end.
5. **Evidence or silence.** Reports with uncited claims are rejected by the post-processor;
   `EvidenceRef`s must resolve to a real document id.
6. **Full audit trail.** Every verdict stores its hypotheses, queries, evidence ids, and model +
   prompt versions (persisted by the review store).

---

## Repository layout

| Path | What |
|---|---|
| `aegis/schema/` | OCSF 1.3 models + source normalisers (Sigma / Elastic / Splunk) |
| `aegis/siem/` | Read-only SIEM adapters + the query validator (no bypass) |
| `aegis/tools/` | siem_query, ti_lookup, asset/identity_lookup, attack_kb, sigma_match, geoip, py_stats |
| `aegis/graph/` | LangGraph state, nodes, reasoners (heuristic + LLM), citation post-processor, runner |
| `aegis/attack/` | MITRE ATT&CK KB (compacted STIX, TF-IDF search) |
| `aegis/models/` | Triage + NL→query inference wrappers |
| `aegis/llm/` | Router (Claude/OpenAI, caching, cost), versioned prompts, output schemas |
| `aegis/security/` | Injection guard + `<data>` envelopes, PII pseudonymiser |
| `aegis/api/` | FastAPI review backend + WebSocket |
| `aegis/lens/` | Lens-style eval metrics + `lens ci` gate |
| `lab/` | Telemetry loaders, Atomic Red Team scenarios/runner, noise generators, Sigma pack, snapshots |
| `bench/` | Benchmark build/run/score, `report.html`, adversarial track |
| `training/` | Triage (LightGBM/DeBERTa) and NL→query (Qwen LoRA) pipelines + model cards |
| `web/` | Next.js 15 review UI |

---

## Development

```bash
ruff check aegis lab bench training tests && ruff format --check aegis lab bench training tests
mypy                       # strict, aegis/ only (CLAUDE.md)
pytest                     # no live LLM or external API calls
```

CI (`.github/workflows/ci.yml`) runs the same gates plus an offline smoke test (noise → snapshot →
verify) and the `lens ci` gate.

## Data provenance & licensing

AEGIS indexes third-party datasets under their own licences: OTRF Security-Datasets (Microsoft),
EVTX-ATTACK-SAMPLES (@sbousseaden), Splunk BOTS, CIC-IDS2017 (UNB), Sigma (SigmaHQ, DRL-1.1), Atomic
Red Team (Red Canary, MIT), MITRE ATT&CK (Apache-2.0). Raw datasets and generated artefacts are not
committed (`.gitignore`); loaders fetch or expect a local copy. AEGIS's own code is Apache-2.0.
