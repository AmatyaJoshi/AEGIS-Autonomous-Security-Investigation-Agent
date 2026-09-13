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
