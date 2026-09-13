# Model card — AEGIS triage classifier

## Overview
- **Task:** classify a SOC alert (with enriched context) as `false_positive`, `true_positive`, or
  `escalate`, and emit `p(FP)` for the fast-path and `p(TP)` for the verdict-score blend (SPEC §7.1).
- **Default model:** LightGBM multiclass gradient-boosted trees on 19 engineered features. CPU,
  trains in seconds. A DeBERTa-v3-base text classifier is provided as an optional alternative for the
  serialised-text representation.
- **Where used:** the graph's `triage_pre` fast-path node and the `verdict` node's score blend
  (`malicious = 0.6·reasoner + 0.4·p_tp`). When absent, the graph skips the fast-path (no dependency).

## Data
- Source: the frozen 420-alert benchmark manifest (`bench/manifests/benchmark_v1.frozen.json`),
  enriched with the same context tools the live graph uses (asset/identity/TI/sigma-rematch).
- Splits inherited from the benchmark (scenario-disjoint for attacks, per-episode for benign FPs):
  train 251 / val 65 / test 104.
- Class-weighted training to counter the escalate minority (11 train examples).

## Features (LightGBM)
`severity, asset_criticality, asset_known, identity_privileged, identity_service_account,
identity_known, ti_max_score, ti_malicious, n_ti_hits, off_hours, recent_alert_count,
n_observables, n_techniques, cred_access, destructive, cmd_len, cmd_has_encoded, cmd_has_lsass,
n_sigma_rematch`.

Top importances: `cmd_len`, `asset_criticality`, `off_hours`, `n_observables`, `cred_access`.

## Metrics (held-out test split, 104 alerts)
| Metric | Value |
|---|---:|
| Macro-F1 | 0.65 |
| F1 false_positive | 0.95 |
| F1 true_positive | 1.00 |
| F1 escalate | 0.00 |
| AUROC (TP vs rest) | 1.00 |
| ECE (calibration) | 0.002 |
| Fast-path rate (FPs auto-closeable at p_fp>0.90) | 100% |
| Missed-TP at fast-path threshold | 0% |

Integrated effect (benchmark arm d vs c): **false-positive suppression @≤2% missed-TP rises from
31% to 90%**, at 0% missed true-positives.

## Limitations
- The `escalate` class has too few examples (11 train) to learn; the model routes ambiguous cases to
  FP, and the reasoner's rule-based escalation logic remains the primary escalate signal. More
  co-labelled ambiguous data would fix this.
- One fp_type (`service_account_lockout`, a password-spray look-alike) is not suppressed; it is the
  hardest benign class and a candidate for targeted features.
- Trained and evaluated on lab + public-dataset-derived alerts; real-SOC distribution will differ.

## Reproduce
```
python -m training.triage.build_dataset --snapshot dev
python -m training.triage.train
python -m training.triage.eval
python -m training.triage.export_onnx   # optional, ONNX int8, <30 ms CPU target
```
