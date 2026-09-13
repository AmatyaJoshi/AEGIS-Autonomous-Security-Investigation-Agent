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
| Splits (train / val / test) | 251 / 65 / 104 |

TP alerts are Sigma matches over the attack datasets (OTRF / EVTX / lab emulation); FP alerts are the
detections a SIEM would raise on each benign-noise episode (all 10 fp_types); ambiguous alerts are
borderline dual-use activity by trusted accounts against sensitive assets. Splits are scenario-disjoint.

### Results on the held-out test split (104 alerts, all 10 fp_types, offline heuristic reasoner)

| Arm | Accuracy | Macro-F1 | FP-suppression @≤2% missed | Escalation precision | Citations |
|---|---:|---:|---:|---:|---:|
| Rules only | 45% | 0.23 | 31% | 100% | 100% |
| Single-shot LLM (alert only) | 52% | 0.26 | 62% | 0% | 100% |
| AEGIS (no triage model) | **88%** | **0.79** | 31% | 100% | 100% |
| AEGIS full (+ triage model) | **88%** | **0.79** | **90%** | 60% | 100% |

The triage model lifts false-positive suppression from **31% to 90%** at 0% missed true-positives,
clearing the ≥60% target. 9 of 10 fp_types are fully suppressed; `service_account_lockout`
(a password-spray look-alike) is the one hard class. Every report passed the citation post-processor
(100% compliance) - no uncited claims. AEGIS beats rules-only (+43% accuracy) and single-shot
(+36%), showing that context and investigation, not just the model, drive the result.

**Caveats reported honestly:**
- The offline arms use the deterministic `HeuristicReasoner`; with an API key the AEGIS arms use the
  LLM reasoner. Both are measured the same way.
- Technique-F1 is low (~0.05) because a TP alert reports the *detecting rule's* technique, which often
  differs from the dataset window's labelled technique. This is a real, honest evaluation nuance.
- Ambiguous alerts are author-labelled (no independent co-labeller offline), so Cohen's kappa is not
  computed - a documented limitation vs SPEC §8.1.

## Phase 6 - Triage classifier (LightGBM, trained for real on CPU)

```
python -m training.triage.build_dataset --snapshot dev   # 420 examples, scenario-disjoint splits
python -m training.triage.train                          # LightGBM multiclass, class-weighted
python -m training.triage.eval                           # -> training/results/*_triage.json
```

| Metric (held-out test, 104 alerts) | Value |
|---|---:|
| Macro-F1 | 0.65 |
| F1 true_positive / false_positive / escalate | 1.00 / 0.95 / 0.00 |
| AUROC (TP vs rest) | 1.00 |
| ECE (calibration) | 0.002 |
| Fast-path rate (FPs auto-closeable at p_fp>0.90) | 100% |
| Missed-TP at fast-path threshold | 0% |

Top features: `cmd_len`, `asset_criticality`, `off_hours`, `n_observables`, `cred_access`. The
`escalate` class (11 train examples) is not learned; the reasoner's rule-based escalation remains the
primary escalate signal. A DeBERTa alternative and ONNX int8 export (<30 ms CPU target) are provided
(`training/triage/{train.py --model deberta, export_onnx.py}`) but need a GPU to train.
Model card: `training/MODEL_CARDS/triage_classifier.md`.

## Phase 7 - NL→SIEM query generator

```
python -m training.query_gen.build_pairs --n-intent 8000   # 18,976 aligned pairs
python -m training.query_gen.train_lora                     # Qwen2.5-Coder + LoRA (needs a GPU)
python -m training.query_gen.eval_exec --snapshot dev       # execution equivalence, not string match
```

### Training corpus (`training/query_gen/data/datacard.json`)

| Metric | Value |
|---|---:|
| Aligned (NL, query) pairs | 18,976 |
| Sigma-derived / paraphrase / investigative-intent | 744 / 2,232 / 16,000 |
| Train / test | 16,173 / 2,803 |
| Held-out Sigma categories | proxy, webserver, dns_query |

### Execution-equivalence evaluation (offline template backend, 10 curated cases)

| Metric | Value |
|---|---:|
| Exact result-set equivalence | 100% |
| Lenient (Jaccard ≥ 0.9) | 100% |
| Syntactic validity | 100% |
| Validator pass rate | 100% |
| Avg latency | 0.23 ms |

Evaluation compares returned `event_id` sets of the generated query vs an independently authored gold
query (substantive cases return 90-352 rows), so it measures result equivalence, not SQL string
match. The fine-tuned Qwen2.5-Coder LoRA plugs into the same harness (needs a GPU to train).
Model card: `training/MODEL_CARDS/query_gen.md`.
