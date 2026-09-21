# STATUS.md — Phase 0 verification (Mon 21 Sep 2026)

Method: fresh `git clone` into an empty directory, `uv venv --python 3.12 && uv pip install -e ".[dev]"`,
then README Quickstart steps 1–7 exactly as written, each command logged with exit code and duration.
Gates (`ruff`, `ruff format --check`, `mypy`, `pytest`) run on the working tree at commit `0c9e7c6`.
Committed numbers (README / RESULTS.md) were re-derived by rerunning the cited commands.

## 1. Gates

| Gate | Result |
|---|---|
| `ruff check aegis lab bench training tests` | clean |
| `ruff format --check` | 136 files, clean |
| `mypy` (strict, `aegis/`) | clean, 75 source files |
| `pytest` | **82 passed, 0 failed, 0 skipped, 0 xfail** (28 s) |
| `web/`: `npm install`, `tsc --noEmit`, `next build` | all pass, 19 routes |
| First commit date | 14 Sep 2026 (≥ 17 Jul 2026 cutoff) — OK |

What the tests mock: nothing via `unittest.mock`. Two test files `monkeypatch` only the SQLite DSN env
var. The three end-to-end graph tests use the real `HeuristicReasoner` and a real DuckDB snapshot built
in `tmp_path`. The SIEM is never mocked (5 files exercise DuckDB directly). The LLM router and
`LLMReasoner` have **zero test coverage** (no test imports them). No `TODO|FIXME|NotImplemented|xfail|
skip|hardcoded` hits in code; `placeholder` hits are docstrings, SQL `?` params and HTML input hints.

## 2. Fresh-clone Quickstart, step by step

| README step | Command | Fresh clone | Time |
|---|---|---|---|
| 0 | `uv venv` + `uv pip install -e ".[dev]"` | ok | ~3 min |
| 1 | `lab load --datasets otrf,evtx` (downloads ~140 MB) | ok | 11 min |
| 1 | `lab noise --days 14 --per-day 12` | ok | 12 s |
| 1 | `lab rules` | **exit 0 but degraded** — see B1 | 51 s |
| 1 | `bench prepare` | ok | 42 s |
| 1 | `lab snapshot --name dev` | ok | 47 s |
| 2 | `investigate --source offline --limit 5` | ok, 5 cited reports | 31 s |
| 3 | `bench build` | ok but **rewrites the frozen manifest** — see B3 | 3.5 min |
| 3 | `bench run --split test` | ok | 60 s |
| 3 | `bench report --split test` | ok | 10 s |
| 3 | `bench adversarial` | ok | 50 s |
| 4 | `training.triage.build_dataset` | ok | 10 s |
| 4 | `training.triage.train` | **FAIL** `ModuleNotFoundError: lightgbm` — see B2 | — |
| 4 | `training.triage.eval` | **FAIL** same | — |
| 4 | `bench run --triage .../model.txt` | **FAIL** same | — |
| 5 | `query_gen.build_pairs --n-intent 8000` | ok, 17,192 pairs (README says 18,976) — consequence of B1 | 4 s |
| 5 | `query_gen.eval_exec --snapshot dev` | ok, 100% equivalence | 7 s |
| 6 | `lens ci --limit 40` | ok, all 3 gates pass | 65 s |
| 7 | `aegis serve` → `/health`, `/docs`, `/api/queue` | 200 in 3 s | — |
| 7 | `npm run dev` | not run interactively; production build passes | — |

Total wall clock, clone to `lens ci`: about 25 minutes, 11 of them dataset download.

## 3. Reproducing RESULTS.md (held-out test split, 104 alerts)

The frozen benchmark manifest is byte-identical to the committed one except its `created` timestamp,
so the 420 alerts and splits are reproducible. The **AEGIS numbers moved** because code changed after
the results were generated on 13–14 Sep and RESULTS.md was never regenerated.

| Arm / metric | Committed (README, RESULTS.md) | Rerun today (working tree + fresh clone) |
|---|---:|---:|
| rules_only — acc / F1 / FP-supp / escP | 45% / 0.23 / 31% / 100% | same |
| single_shot_llm — acc / F1 / FP-supp / escP | 52% / 0.26 / 62% / 0% | same |
| aegis_no_triage — acc / F1 / FP-supp / escP | 88% / 0.79 / 31% / 100% | **89% / 0.88 / 29% / 100%** |
| aegis_full — acc / F1 / FP-supp / escP | 88% / 0.79 / 90% / 60% | **89% / 0.88 / 90% / 71%** |
| Adversarial corpus size | 60 variants | **75 variants** (30 seed TPs), rates unchanged (0% flip, 100% detect, 0% contamination) |
| NL→query pairs | 18,976 | 17,192 in the fresh clone (B1); needs recount after the pin |
| Lens gates (40 alerts) | 100% / 100% / 90% | same |

The headline scores file (`data/benchmark/results/scores.json`) is **gitignored**, so the README table
has no committed `bench/results` file behind it, which CLAUDE.md requires.

## 4. LLM reasoner run (Phase 0 step 4) — BLOCKED

Not run. Three independent blockers:

1. No `ANTHROPIC_API_KEY`/`OPENAI_API_KEY` in this environment, no Ollama, Docker daemon down.
2. The zero-cost policy forbids the paid Anthropic run the brief asked for.
3. Even with a key the path would crash: `anthropic` and `openai` are imported by
   `aegis/llm/router.py` but are **not declared in `pyproject.toml`** and are not installed.

The router has no Ollama, Groq or Gemini provider and no budget guard. The `single_shot_llm` arm is,
offline, the heuristic reasoner with context removed; the name overstates what was measured.

## 5. Broken / stale items and hours to fix

| # | Item | Severity | Fix | Hours |
|---|---|---|---|---:|
| B1 | `pyparsing 3.3.3` (resolved by a fresh install) breaks pysigma 1.5.0 condition parsing: 337/377 SPL and 114/377 ES\|QL conversions fail with `TypeError: 'str' object is not callable`. Local venv has 3.3.2 and converts 377/367. Silent: exit code 0. | high | pin `pyparsing<3.3.3` (needs your OK: dependency change); make `lab rules` exit non-zero when conversion rate drops below a floor; add a test | 0.5 |
| B2 | `lightgbm` and `scikit-learn` are used by `training/triage/*` and the `--triage` arm but not declared; fresh clone cannot train or run the headline arm | high | add to a `[train]` extra (needs your OK); README step 4 installs it | 0.5 |
| B3 | `bench build` rewrites `bench/manifests/benchmark_v1.frozen.json` (timestamp) on every run; "frozen" is not enforced | medium | write only if `manifest_hash` differs, else refuse and print the diff | 0.5 |
| B4 | RESULTS.md / README numbers stale (acc, F1, escalation precision, adversarial size, pair count); `scores.json` not committed under `bench/results/` | high | regenerate, copy scores + adversarial + lens into `bench/results/<date>_<sha>.json`, rewrite tables | 1.5 |
| B5 | LLM path: undeclared `anthropic`/`openai`, no free provider, no budget guard, zero tests | high for the demo story | Phase 1: OpenAI-compatible provider (Ollama/Groq), Gemini provider, `BUDGET_*` guards, DEGRADED mode, recorded-fixture tests | 4 |
| B6 | Fresh-clone README order runs `bench report` before the triage model exists, so the first `report.html` shows `aegis_full == aegis_no_triage` | low | reorder README steps or have `bench report` label the arm "no model loaded" | 0.5 |
| B7 | `/api/queue` answers 200 without a token; confirm which routes are meant to be public before deploying | low | audit `aegis/api/app.py` route deps | 0.5 |
| B8 | Review UI never exercised in a browser during Phase 0 (build only) | unknown | run `npm run dev` against `aegis serve` and click every page | 1 |

Total to make the README literally true from a fresh clone: **about 5 hours** (B1–B4, B6), plus **4
hours** for a zero-cost LLM reasoner path (B5).

## 6. Verdict

**Ready for a live demo: yes, for the offline deterministic pipeline** (fresh clone reproduces
investigate, benchmark, adversarial track, Lens gate and the API in ~25 minutes; every report cites
its evidence). **No, for anything described as an LLM reasoner** until B5 lands on a free provider,
and not with the current README numbers until B1–B4 are fixed.
