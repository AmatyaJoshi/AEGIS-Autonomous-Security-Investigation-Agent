# AEGIS — Autonomous SOC Investigation Agent

AEGIS is a LangGraph-based autonomous Tier-1/Tier-2 SOC analyst. It ingests security alerts from a
SIEM, normalises them to the OCSF schema, and for each alert performs the investigation a human
analyst would: it gathers context from logs, identity and asset systems, enriches indicators with
threat intelligence, forms competing hypotheses, queries the log store to confirm or refute each
one, reconstructs the attack timeline, maps behaviour to MITRE ATT&CK, issues a verdict
(true positive / false positive / escalate) with a calibrated confidence, and writes an incident
report in which **every claim cites the exact log events it relies on**.

**Response actions are recommended, never executed.** AEGIS augments analysts and escalates
containment decisions to humans. It is positioned as autonomous L1/L2 *investigation*, not a
replacement for analysts.

It is measured on a 400+ alert, ATT&CK-stratified, human-labelled benchmark built from public
adversary-emulation datasets and a reproducible lab, and instrumented end-to-end with OpenTelemetry.

> **Status:** Phases 0 and 1 are built and green (skeleton + the full lab data plane). Phases 2–8
> (OCSF ingestion, the investigation graph, review UI, benchmark, the two fine-tuned models, the
> adversarial track and Lens integration) are specified in [SPEC.md](SPEC.md) §11 and not yet built.
> See [RESULTS.md](RESULTS.md) for every measured number. This README states only what is real.

---

## What is built today

```
┌──────────────────────── LAB DATA PLANE (Phase 1, built) ────────────────────────┐
│  Public datasets ─┐                                                              │
│   OTRF / Mordor   │   loaders ──▶ ECS events ──┐                                 │
│   EVTX-ATTACK     │   (winevent mapper)         │                                │
│   BOTS / CIC-IDS  │                             ├─▶ Parquet staging ─▶ snapshot  │
│  Atomic Red Team ─┤   runner ──▶ ground-truth ──┤    (DuckDB, hashed, --offline) │
│   scenarios       │              windows        │                                │
│  Benign-noise ────┘   generators ──▶ FP events ─┘                                │
│                                       + fp_type labels                           │
│  Sigma pack ──▶ ES|QL + SPL conversions (NL→query training corpus, §7.2)         │
└──────────────────────────────────────────────────────────────────────────────────┘
        │ (Phases 2+)                                     Elastic (optional, docker-compose.lab)
        ▼
   OCSF normalise ─▶ LangGraph investigation graph ─▶ verdict + cited report + playbook
```

Concretely, Phase 1 delivers a reproducible ground-truth pipeline:

- **768,994 events** normalised to ECS from OTRF Security-Datasets and EVTX-ATTACK-SAMPLES plus a
  benign-noise generator, indexed to Parquet and re-openable offline through a read-only DuckDB SIEM
  adapter.
- **543 ground-truth windows** (375 true-positive, 168 false-positive) spanning 59 techniques and 10
  false-positive types, derived only from the datasets' *published* labels and the noise generators
  — never invented.
- **6 Atomic Red Team scenarios / 58 steps** covering **56 techniques across all 12 tactics**, each
  step validated against a pinned ART index. A runner records a ground-truth window per atomic; a
  `dry-run` transport prints the exact commands and executes nothing.
- **377 Sigma rules** (320 core + 57 held-out) converted to ES|QL and SPL as aligned NL→query pairs.

Numbers and the commands that regenerate them are in [RESULTS.md](RESULTS.md).

---

## Quickstart (offline, no external services)

Requires Python 3.12 and [uv](https://docs.astral.sh/uv/). Nothing here needs Docker, Elasticsearch,
a GPU or the internet once the raw datasets are cached.

```bash
uv venv --python 3.12
uv pip install -e ".[dev]"

# Validate the emulation scenarios and print ATT&CK coverage
python -m aegis.cli lab scenarios

# Generate benign / false-positive telemetry (deterministic)
python -m aegis.cli lab noise --days 14 --per-day 12

# Build and verify an offline snapshot from whatever is staged in data/parquet
python -m aegis.cli lab snapshot --name dev --source parquet
python -m aegis.cli lab verify   --name dev

# Ground-truth coverage
python -m aegis.cli lab coverage
```

To ingest the public datasets you first fetch them (loaders cache under `data/raw/`):

```bash
python -m aegis.cli lab load  --datasets otrf,evtx      # downloads on first run
python -m aegis.cli lab rules                            # Sigma bundle -> ES|QL + SPL pack
```

BOTS and CIC-IDS2017 require a manual export / registration; see the docstrings in
`lab/datasets/bots.py` and `lab/datasets/cicids.py`.

### Full lab with the Elastic SIEM (optional, ~16 GB RAM)

```bash
docker compose -f docker-compose.yml -f docker-compose.lab.yml up -d   # Postgres, Redis, ES, Kibana
python -m aegis.cli lab load  --datasets otrf,evtx --to-elastic
cd lab/vms && vagrant up                                                # DC01, WS01, LNX01 with telemetry
python -m aegis.cli lab emulate win_intrusion_full --transport vagrant  # runs Atomic Red Team, records ground truth
```

If you cannot run VMs, ignore this section — the offline Parquet path is the primary benchmark
source by design.

---

## Repository layout

| Path | What |
|---|---|
| `aegis/schema/ocsf.py` | Hand-curated OCSF 1.3 Pydantic models (`detection_finding`, `security_finding` + objects) |
| `aegis/siem/` | Read-only SIEM adapters; `duckdb.py` powers `--offline` and rejects any mutating query |
| `aegis/security/` | Prompt-injection guard + `<data>` envelopes; reversible PII pseudonymiser |
| `aegis/db/` | SQLAlchemy models for the review queue and audit trail |
| `aegis/cli.py` | `aegis` CLI (the `lab` group is implemented; other verbs are later phases) |
| `lab/common/` | ECS event model, Windows-event mapper, Parquet/Elastic sinks |
| `lab/datasets/` | OTRF, EVTX-ATTACK, BOTS, CIC-IDS loaders (published labels only) |
| `lab/emulation/` | Atomic Red Team scenarios, validator, runner, ground-truth table |
| `lab/noise/` | Benign-activity / false-positive generators + mock CMDB/IdP (`org.yaml`) |
| `lab/rules/` | Sigma pack curation + ES\|QL/SPL conversion |
| `lab/snapshot.py` | Immutable, hashed Parquet snapshots for offline mode |
| `bench/`, `training/`, `web/` | Benchmark, model training, review UI (later phases) |

---

## Guardrails (§9 of the spec — enforced in code, not just documented)

1. **Recommend-only.** No tool can mutate the environment. The SIEM adapters expose no write path;
   the offline adapter rejects `INSERT`/`UPDATE`/`DELETE`/`DROP`/`COPY`/multi-statement queries
   (`tests/test_duckdb_siem.py`). Playbooks are text with `requires_approval` flags.
2. **Separate credentials.** The agent uses a read-only Elasticsearch key; only `lab/` loaders use a
   writer key, and never hand it to a tool.
3. **No offensive content.** Lab attack telemetry comes from published Atomic Red Team tests and
   public datasets executed by the runner — never authored here. A scanner asserts generated
   telemetry contains no payload/exploit markers.
4. **Injection guard.** Every attacker-influenceable free-text field is scanned; flagged content is
   redacted and (in later phases) forces `escalate`. All tool output is wrapped in `<data>`
   envelopes that the system prompt treats as data, never instructions.
5. **Evidence or silence.** Reports with uncited claims are rejected (post-processor, Phase 3);
   `EvidenceRef`s must resolve to a real document id.
6. **Full audit trail.** Every investigation stores hypotheses, queries, evidence ids, and model +
   prompt versions.

---

## Development

```bash
ruff check aegis lab bench training tests
ruff format --check aegis lab bench training tests
mypy                       # strict, aegis/ only (CLAUDE.md)
pytest                     # no live LLM or external API calls
```

CI (`.github/workflows/ci.yml`) runs the same gates plus an offline smoke test that generates noise,
builds a snapshot and verifies it with zero external services.

## Data provenance & licensing

AEGIS indexes third-party datasets under their own licences: OTRF Security-Datasets, Microsoft;
EVTX-ATTACK-SAMPLES (@sbousseaden); Splunk Boss of the SOC; CIC-IDS2017 (University of New
Brunswick); Sigma rules (SigmaHQ, DRL-1.1); Atomic Red Team (Red Canary, MIT). Raw datasets are not
committed (`.gitignore`); loaders fetch or expect a local copy. AEGIS's own code is Apache-2.0.
