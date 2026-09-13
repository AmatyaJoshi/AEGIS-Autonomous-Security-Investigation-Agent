# Model card — NL→SIEM query generator

## Overview
- **Task:** translate an investigative intent in English (+ entities + time window) into a valid,
  scoped SIEM query in ES|QL (primary) or SPL (SPEC §7.2).
- **Model:** `Qwen2.5-Coder-1.5B-Instruct` + LoRA (r=16, α=32, all linear layers), `trl` SFT.
  Serving via vLLM (or transformers), grammar-constrained ES|QL decoding optional.
- **Where used:** the `siem_query` tool's `QueryGenerator`. The fine-tuned model is opt-in
  (`AEGIS_QUERYGEN_MODEL`); the deterministic `TemplateQueryBuilder` is the always-available fallback
  and the offline default. Every generated query passes `aegis/siem/validator` before execution.

## Data (the clever part)
Three aligned sources, **18,976 pairs** (16,173 train / 2,803 test):
- **Sigma-derived (744):** each curated rule's title+description → its `sigma-cli` ES|QL / SPL
  conversion.
- **Paraphrase augmentation (2,232):** 3 deterministic paraphrases per rule (model paraphrases with
  an API key) to teach intent variation.
- **Investigative-intent (16,000):** parametric intents instantiated on the lab's real entities,
  paired with the programmatically-generated DuckDB query.

Held-out **Sigma categories** (`proxy`, `webserver`, `dns_query`) form part of the test split to
measure generalisation to rule families never seen in training.

## Evaluation — execution equivalence, not string match (`eval_exec.py`)
Generated and gold queries run against the snapshot; we compare returned `event_id` sets.

| Metric (10 curated cases on the offline template backend) | Value |
|---|---:|
| Exact result-set equivalence | 100% |
| Lenient equivalence (Jaccard ≥ 0.9) | 100% |
| Syntactic validity | 100% |
| Validator pass rate | 100% |
| Avg latency | 0.23 ms |

The strong cases return 90–352 matching rows; the metric measures whether the generated query returns
the same rows as an independently authored gold query, not identical SQL. The fine-tuned model plugs
into the same harness for a head-to-head vs the template and a frontier zero-shot baseline (needs a
GPU / API key to run).

## Limitations
- The offline number is for the template builder (what ships without a GPU). The LoRA numbers require
  training on a GPU; the pipeline (`build_pairs`, `train_lora`, `eval_exec`, `export`) is complete and
  runnable there.
- A few eval cases return 0 rows on the current snapshot (weak tests); the substantive cases dominate.
- SPL conversions exist for all rules but are evaluated only structurally offline (no Splunk instance).

## Reproduce
```
python -m training.query_gen.build_pairs --n-intent 8000
python -m training.query_gen.train_lora        # needs a GPU
python -m training.query_gen.eval_exec --snapshot dev
```
