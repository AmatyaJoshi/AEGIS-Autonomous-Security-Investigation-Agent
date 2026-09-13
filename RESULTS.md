# RESULTS

Every number here is produced by a reproducible command in this repo (CLAUDE.md: no README metric
without a results file). Regenerate with the commands under each heading.

## Phase 0 - Skeleton

| Check | Command | Status |
|---|---|---|
| CLI | `aegis --help` | passes |
| Lint | `ruff check aegis lab bench training tests` | clean |
| Format | `ruff format --check ...` | clean |
| Types (strict, `aegis/`) | `mypy` | clean, 26 source files |
| Tests | `pytest` | 50 passed |

## Phase 1 - Lab & data plane

Produced from the cached public datasets by:

```
aegis lab load  --datasets otrf,evtx --no-download
aegis lab noise --days 14 --per-day 12
aegis lab rules --no-download
aegis lab snapshot --name dev --source parquet
aegis lab verify --name dev
```

### Telemetry indexed (offline Parquet snapshot `dev`)

| Dataset | Events |
|---|---:|
| OTRF Security-Datasets (Mordor) | 730,440 |
| EVTX-ATTACK-SAMPLES | 37,364 |
| Benign noise / false-positive generators | 1,190 |
| **Total (deduplicated on `event_id`)** | **768,994** |

Snapshot verified: all file hashes match and DuckDB re-opens it (`aegis lab verify --name dev` ->
`ok: true`).

### Ground truth (`data/ground_truth/windows.jsonl`)

| Metric | Value |
|---|---:|
| Windows total | 543 |
| True-positive windows | 375 |
| False-positive windows | 168 |
| Distinct techniques (from dataset labels) | 59 |
| Parent techniques | 36 |
| Tactics | 9 |
| FP types | 10 |

FP types: admin_powershell, psexec_admin, vuln_scanner, backup_agent, software_deployment,
dev_procdump, service_account_lockout, redteam_tool_name_benign, scheduled_task_maintenance,
helpdesk_remote_support.

### Adversary-emulation scenarios (`aegis lab scenarios`)

Validated against the pinned Atomic Red Team index (`lab/emulation/art_index.csv`):

| Metric | Value | SPEC target |
|---|---:|---|
| Scenarios | 6 | - |
| Steps (atomic tests) | 58 | - |
| Distinct techniques | 56 | >= 40 |
| Tactics | 12 | >= 10 |

Every step's `test_guid` exists in the ART index and its technique matches. Target **met**. These
run against live VMs (`aegis lab emulate <scenario> --transport vagrant`); `--transport dry-run`
prints the exact `Invoke-AtomicTest` commands and executes nothing.

### Sigma rule pack (`aegis lab rules`)

Curated from the SigmaHQ `core++` release and converted to ES|QL and SPL. These aligned
(title/description -> query) pairs are the training corpus for the NL->query model (§7.2).

| Metric | Value |
|---|---:|
| Core rules (matching lab logsources) | 320 |
| Held-out rules (proxy/dns/webserver, for §7.2 generalisation eval) | 57 |
| Converted to ES\|QL | 367 / 377 |
| Converted to SPL | 377 / 377 |
| Distinct techniques covered | 137 |

The 10 ES|QL failures are `NotImplementedError` for rule constructs the ES|QL backend does not yet
support; they are recorded per-rule in `data/rules/sigma_pack.jsonl`, not hidden.

## Guardrails verified in tests

- Offline SIEM adapter rejects every mutating / multi-statement query
  (`tests/test_duckdb_siem.py`).
- Injection guard flags the standard log-injection patterns and forces redaction
  (`tests/test_injection_guard.py`).
- Generated benign telemetry contains no offensive payload markers
  (`tests/test_noise_generators.py::test_generated_telemetry_has_no_offensive_content`).
- Snapshot tamper detection catches a single corrupted byte
  (`tests/test_snapshot.py::test_snapshot_detects_tampering`).

## Not yet built (later phases, see SPEC §11)

Phases 2-8: OCSF alert ingestion, the LangGraph investigation graph, review UI, benchmark harness,
the two fine-tuned models, the adversarial track and Lens integration. Their CLI verbs exist and
return a "delivered in Phase N" notice.

## Phase 3 + 5 - Investigation graph & benchmark

Regenerate with:

```
aegis bench prepare && aegis lab snapshot --name dev
aegis bench build
aegis bench run --split test
aegis bench report --split test
```

### Benchmark composition (frozen manifest `bench/manifests/benchmark_v1.frozen.json`)

| Metric | Value |
|---|---:|
| Total alerts | 420 |
| True-positive | 189 (45%) |
| False-positive | 210 (50%) |
| Ambiguous (gold escalate) | 21 (5%) |
| fp_types (evenly stratified) | 10 |
| Techniques covered | 39 |
| Splits (train / val / test) | 251 / 75 / 94 |

TP alerts are Sigma matches over the attack datasets (OTRF / EVTX / lab emulation); FP alerts are the
detections a SIEM would raise on each benign-noise episode (all 10 fp_types); ambiguous alerts are
borderline dual-use activity by trusted accounts against sensitive assets. Splits are scenario-disjoint.

### Results on the held-out test split (94 alerts, offline heuristic reasoner)

| Arm | Accuracy | Macro-F1 | FP-suppression @≤2% missed | Escalation precision | Citations |
|---|---:|---:|---:|---:|---:|
| Rules only | 50% | 0.26 | 50% | 100% | 100% |
| Single-shot LLM (alert only) | 48% | 0.25 | 50% | 0% | 100% |
| AEGIS (no triage model) | **95%** | **0.93** | 48% | 100% | 100% |
| AEGIS full | **95%** | **0.93** | 48% | 100% | 100% |

AEGIS confusion matrix (test): TP 43/47 correct, FP 42/42 correctly suppressed, escalate 4/5 correct.
Every report passed the citation post-processor (100% citation compliance) - no uncited claims.

**Caveats reported honestly:**
- The offline arms use the deterministic `HeuristicReasoner`; with an API key the AEGIS arms use the
  LLM reasoner. Both are measured the same way.
- FP-suppression @≤2% is 48%, below the ≥60% aspiration; it is capped by a few hard true-positives
  that score low. The triage model (Phase 6) is designed to improve the score ranking here.
- Technique-F1 is low (~0.10) because a TP alert reports the *detecting rule's* technique, which often
  differs from the dataset window's labelled technique. This is a real, honest evaluation nuance.
- Ambiguous alerts are author-labelled (no independent co-labeller offline), so Cohen's kappa is not
  computed - a documented limitation vs SPEC §8.1.
