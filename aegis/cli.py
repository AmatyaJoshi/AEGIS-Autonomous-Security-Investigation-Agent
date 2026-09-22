"""AEGIS command-line interface (SPEC §2.2).

Phase 0/1 implement the ``lab`` command group (the data plane) and stubs for the phases still to
come. Every later phase fills in its verb:

    aegis investigate ...   # Phase 3  - run the investigation graph over live/offline alerts
    aegis ingest ...        # Phase 2  - normalise source alerts to OCSF
    aegis bench ...         # Phase 5  - build/run/score the benchmark
    aegis lab ...           # Phase 1  - lab data plane (implemented here)
    aegis serve ...         # Phase 4  - FastAPI + review UI backend
    aegis replay ...        # Phase 3  - replay a checkpointed investigation
    aegis label ...         # Phase 4  - apply analyst labels

Design: the CLI never talks to Elasticsearch unless a command needs it; ``--offline`` and the
Parquet path work with zero external services so the whole Phase-1 pipeline runs on a laptop or CI.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import TYPE_CHECKING, Any

import typer
from rich.console import Console
from rich.table import Table

from aegis import __version__
from aegis.config import get_settings

if TYPE_CHECKING:
    from lab.common.sink import EventSink

app = typer.Typer(
    add_completion=False,
    no_args_is_help=True,
    help="AEGIS - autonomous SOC investigation agent (recommend-only). See SPEC.md.",
)
lab_app = typer.Typer(no_args_is_help=True, help="Lab data plane: telemetry, ground truth, rules.")
app.add_typer(lab_app, name="lab")
console = Console()


def _setup_logging(level: str) -> None:
    logging.basicConfig(
        level=level.upper(), format="%(asctime)s %(levelname)-7s %(name)s: %(message)s"
    )


def _archive_result(kind: str, payload: dict[str, Any]) -> Path:
    """Copy a measured result into the committed ``bench/results/`` directory.

    CLAUDE.md: no metric appears in README without a ``bench/results`` or ``training/results`` file.
    ``data/`` is gitignored, so every scored run also lands here as
    ``<YYYYMMDD>_<git sha>_<kind>.json`` and the README/RESULTS tables cite that file.
    """
    import datetime as _dt
    import subprocess

    try:
        sha = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"], capture_output=True, text=True, check=True
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        sha = "nogit"
    out_dir = Path(__file__).resolve().parents[1] / "bench" / "results"
    out_dir.mkdir(parents=True, exist_ok=True)
    out = out_dir / f"{_dt.date.today():%Y%m%d}_{sha}_{kind}.json"
    out.write_text(json.dumps(payload, indent=1), encoding="utf-8")
    return out


@app.callback()
def main(log_level: str = typer.Option("INFO", "--log-level", envvar="AEGIS_LOG_LEVEL")) -> None:
    _setup_logging(log_level)


@app.command()
def version() -> None:
    """Print the AEGIS version."""
    console.print(f"AEGIS {__version__}")


@app.command()
def investigate(
    source: str = typer.Option("offline", help="offline | elastic | splunk"),
    snapshot: str = typer.Option("dev", help="snapshot name for offline source"),
    limit: int = typer.Option(5, help="number of alerts to investigate"),
    seed: int = typer.Option(1337),
    review: bool = typer.Option(False, help="interrupt before playbook for human review"),
    out: Path | None = typer.Option(None, help="write reports to this directory"),
    reasoner_kind: str = typer.Option(
        "auto", "--reasoner", help="auto | llm | heuristic (llm needs Ollama/Groq/Gemini, COST.md)"
    ),
    triage: str | None = typer.Option(
        "training/triage/artifacts/model.txt", help="triage model path (skipped if missing)"
    ),
) -> None:
    """Run the investigation graph over alerts (Phase 3). Offline uses the DuckDB snapshot."""
    from aegis.graph.deps import Deps
    from aegis.graph.reasoner import HeuristicReasoner
    from aegis.graph.runner import run_investigation
    from aegis.ingest.generate import generate_alerts
    from aegis.llm.router import LLMRouter
    from aegis.siem.duckdb import DuckDBSiem

    if source != "offline":
        console.print(
            "[yellow]Live Elastic/Splunk ingestion needs a running SIEM; use "
            "--source offline for the snapshot path.[/]"
        )
        raise typer.Exit(2)
    settings = get_settings()
    snap = settings.data.snapshots / snapshot
    siem = DuckDBSiem(snap)
    from aegis.llm.budget import log_allowlist

    log_allowlist()
    router = LLMRouter()
    reasoner: Any
    if reasoner_kind != "heuristic" and router.available:
        from aegis.graph.llm_reasoner import LLMReasoner

        reasoner = LLMReasoner(router)
        d = router.describe()
        console.print(f"[green]Using LLM reasoner via {d['provider']} ({d['model']}), $0 tier[/]")
    else:
        reasoner = HeuristicReasoner()
        if reasoner_kind == "llm":
            console.print("[red]--reasoner llm requested but no free provider is reachable.[/]")
            raise typer.Exit(2)
        console.print(
            "[cyan]No free LLM provider reachable (Ollama/Groq/Gemini); "
            "using the deterministic heuristic reasoner.[/]"
        )
    from aegis.memory.store import open_memory

    memory = open_memory()
    console.print(f"[dim]memory: {memory.status()['backend']}[/]")
    tri = None
    if triage and Path(triage).exists():
        from aegis.models.triage import load_triage

        tri = load_triage(triage)
    deps = Deps(
        siem=siem,
        reasoner=reasoner,
        review_mode=review,
        pack_path=str(snap / "rules" / "sigma_pack.jsonl"),
        memory=memory,
        triage=tri,
    )
    if out:
        out.mkdir(parents=True, exist_ok=True)
    table = Table(title="Investigations")
    for col in ("alert", "verdict", "conf", "sev", "techniques", "cited"):
        table.add_column(col)
    for n, rec in enumerate(
        generate_alerts(snap, pack_path=snap / "rules" / "sigma_pack.jsonl", seed=seed)
    ):
        res = run_investigation(rec.alert, deps)
        v = res.verdict
        assert v is not None
        table.add_row(
            rec.alert.finding_info.title[:32],
            v.label,
            f"{v.confidence:.2f}",
            v.severity,
            ",".join(v.techniques[:3]),
            "yes" if (res.report_json or {}).get("citations_ok") else "no",
        )
        if out and res.report_md:
            (out / f"{rec.alert.alert_id}.md").write_text(res.report_md, encoding="utf-8")
        if n + 1 >= limit:
            break
    siem.close()
    if hasattr(memory, "flush_priors"):
        console.print(f"[dim]memory: priors flushed to Pulse ({memory.flush_priors()} keys)[/]")
    console.print(table)
    d = router.describe()
    console.print(
        f"[dim]llm provider={d['provider'] or 'none'} calls={d['calls']} "
        f"tokens={d['total_tokens']} cost_usd={d['total_cost_usd']} cost_mode={d['cost_mode']}[/]"
    )


@app.command()
def ingest(
    path: Path = typer.Argument(..., help="JSON file: an Elastic alert or Splunk notable"),
    source: str = typer.Option("elastic", help="elastic | splunk"),
) -> None:
    """Normalise a source alert file to OCSF and print the detection_finding (Phase 2)."""
    doc = json.loads(path.read_text(encoding="utf-8"))
    if source == "elastic":
        from aegis.schema.normalize.elastic import finding_from_elastic

        finding = finding_from_elastic(doc)
    elif source == "splunk":
        from aegis.schema.normalize.splunk import finding_from_splunk

        finding = finding_from_splunk(doc)
    else:
        console.print(f"[red]unknown source {source}[/]")
        raise typer.Exit(2)
    console.print_json(finding.model_dump_json())


@app.command()
def bench(
    action: str = typer.Argument(..., help="prepare | build | run | score | report | all | small"),
    snapshot: str = typer.Option("dev"),
    split: str = typer.Option("test", help="split to run/score (train|val|test|all)"),
    total: int = typer.Option(420, help="benchmark size for build"),
    triage: Path | None = typer.Option(None, help="triage model path for aegis_full arm"),
    reasoner_kind: str = typer.Option(
        "heuristic", "--reasoner", help="heuristic | llm (llm needs Ollama/Groq/Gemini, COST.md)"
    ),
    limit: int | None = typer.Option(None, help="cap alerts per arm (LLM runs on a laptop)"),
) -> None:
    """Build, run and score the benchmark (SPEC §8)."""
    import datetime as _dt
    import json as _json

    from bench.build_benchmark import build_benchmark
    from bench.report import render_report
    from bench.run_bench import ARMS, run_benchmark
    from bench.score import score_all

    settings = get_settings()
    snap = settings.data.snapshots / snapshot
    bench_dir = settings.data.root / "benchmark"
    results_dir = bench_dir / "results"
    real_split = None if split == "all" else split

    def _prepare() -> None:
        from bench.prepare import prepare_bench_events

        rep = prepare_bench_events(settings.data.root)
        console.print_json(_json.dumps(rep))
        console.print(
            "[cyan]Now run `aegis lab snapshot --name "
            f"{snapshot}` to fold these events into the snapshot.[/]"
        )

    def _build() -> None:
        console.print_json(_json.dumps(build_benchmark(snap, bench_dir, total=total)))

    def _run() -> None:
        tri = None
        if triage:
            from aegis.models.triage import load_triage

            tri = load_triage(triage)
        reasoner: Any = None
        if reasoner_kind == "llm":
            from aegis.graph.llm_reasoner import LLMReasoner
            from aegis.llm.budget import log_allowlist
            from aegis.llm.router import LLMRouter

            log_allowlist()
            router = LLMRouter()
            if not router.available:
                console.print("[red]--reasoner llm: no free provider reachable (COST.md).[/]")
                raise typer.Exit(2)
            reasoner = LLMReasoner(router)
            console.print(f"[green]LLM reasoner via {router.describe()['provider']}[/]")
        rep = run_benchmark(
            snap,
            bench_dir,
            results_dir,
            split=real_split,
            triage_model=tri,
            limit=limit,
            reasoner=reasoner,
        )
        (results_dir / "run_meta.json").write_text(_json.dumps(rep), encoding="utf-8")
        console.print_json(_json.dumps(rep))

    def _score_and_report() -> None:
        scores = score_all(results_dir, ARMS)
        (results_dir / "scores.json").write_text(_json.dumps(scores, indent=1), encoding="utf-8")
        n = next((s["n"] for s in scores.values()), 0)
        meta = {
            "split": split,
            "n": n,
            "generated": _dt.datetime.now().isoformat(timespec="seconds"),
        }
        try:
            frozen = _json.loads((Path("bench/manifests/benchmark_v1.frozen.json")).read_text())
            meta["manifest_hash"] = frozen.get("manifest_hash")
        except FileNotFoundError:
            pass
        kind = "heuristic"
        try:
            run_meta = _json.loads((results_dir / "run_meta.json").read_text(encoding="utf-8"))
            kind = str(run_meta.get("reasoner", kind))
            meta["reasoner"] = kind
            meta["n_run"] = run_meta.get("n")
        except (FileNotFoundError, ValueError):
            meta["reasoner"] = kind
        out = render_report(scores, meta, results_dir / "report.html", roc_dir=results_dir)
        console.print(f"[green]report -> {out}[/]")
        arch = _archive_result(f"bench_{split}_{kind}", {"meta": meta, "scores": scores})
        console.print(f"[green]archived -> {arch}[/]")
        table = Table(title=f"Benchmark ({split})")
        for c in ("arm", "acc", "F1", "FPsupp@2%", "escP", "techF1", "cite"):
            table.add_column(c)
        for arm in ARMS:
            if arm in scores:
                s = scores[arm]
                table.add_row(
                    arm,
                    f"{s['accuracy']:.2f}",
                    f"{s['macro_f1']:.2f}",
                    f"{s['fp_suppression_at_2pct_missed']:.2f}",
                    f"{s['escalation_precision']:.2f}",
                    f"{s['technique_f1']:.2f}",
                    f"{s['citation_rate']:.2f}",
                )
        console.print(table)

    def _adversarial() -> None:
        from bench.adversarial.run import run_adversarial

        rep = run_adversarial(snap, bench_dir, results_dir, limit=30)
        console.print_json(_json.dumps(rep))
        console.print(f"[green]archived -> {_archive_result('adversarial', rep)}[/]")
        off, on = rep["guard_off"], rep["guard_on"]
        console.print(f"[bold]Adversarial injection track[/] ({rep['n_variants']} variants)")
        console.print(
            f"  verdict-flip rate:  guard off {off['verdict_flip_rate']:.0%} -> "
            f"guard on {on['verdict_flip_rate']:.0%}"
        )
        console.print(f"  injection detection (guard on): {on['injection_detection_rate']:.0%}")
        console.print(f"  report contamination: {on['report_contamination_rate']:.0%}")

    if action == "prepare":
        _prepare()
    elif action == "build":
        _build()
    elif action == "run":
        _run()
    elif action == "adversarial":
        _adversarial()
    elif action in ("score", "report"):
        _score_and_report()
    elif action == "all":
        _build()
        _run()
        _score_and_report()
    elif action == "small":
        global_total = 60
        console.print_json(_json.dumps(build_benchmark(snap, bench_dir, total=global_total)))
        run_benchmark(snap, bench_dir, results_dir, split="test")
        _score_and_report()
    else:
        console.print(f"[red]unknown action {action}[/]")
        raise typer.Exit(2)


@app.command()
def demo(
    snapshot: str = typer.Option("dev"),
    reset: bool = typer.Option(True, help="clear the review queue and case memory first"),
    reasoner_kind: str = typer.Option("auto", "--reasoner", help="auto | llm | heuristic"),
    triage: Path = typer.Option(Path("training/triage/artifacts/model.txt")),
    ui_url: str = typer.Option("http://localhost:3000", envvar="AEGIS_UI_URL"),
) -> None:
    """Three-minute live demo: reset, investigate 1 TP + 3 FP + 1 ambiguous, print the URL."""
    from aegis.demo import DemoCase, run_demo

    settings = get_settings()
    snap = settings.data.snapshots / snapshot
    bench_dir = settings.data.root / "benchmark"
    if not snap.exists() or not (bench_dir / "benchmark_v1.json").exists():
        console.print(
            "[red]Need the snapshot and the benchmark first: "
            "run `make data` (or README Quickstart steps 1 and 3).[/]"
        )
        raise typer.Exit(2)
    table = Table(title="AEGIS demo - 5 alerts")
    for c in ("gold", "fp_type", "verdict", "conf", "cited", "s", "prior"):
        table.add_column(c)

    def on_case(c: DemoCase) -> None:
        prior = c.memory_prior or {}
        table.add_row(
            c.gold_label,
            c.fp_type or "-",
            c.verdict or "-",
            f"{c.confidence:.2f}" if c.confidence is not None else "-",
            "yes" if c.cited else "NO",
            f"{c.seconds:.1f}",
            f"{prior.get('key')} w={prior.get('weight', 0):.2f}" if prior.get("key") else "-",
        )
        console.print(f"[dim]{c.gold_label:14} -> {c.verdict} ({c.seconds:.1f}s)[/]")

    rep = run_demo(
        snapshot=snap,
        bench_dir=bench_dir,
        reset=reset,
        reasoner_kind=reasoner_kind,
        triage_path=triage,
        ui_url=ui_url,
        on_case=on_case,
    )
    console.print(table)
    llm = rep["llm"]
    console.print(
        f"reasoner={rep['reasoner']} provider={llm['provider'] or 'none'} "
        f"cost_mode={llm['cost_mode']} fallbacks={rep['fallbacks']} "
        f"memory={rep['memory']['backend']} ({rep['memory']['priors_source']}) "
        f"total={rep['seconds']}s"
    )
    console.print(f"[bold green]Open the ambiguous case:[/] {rep['open']}")
    console.print(
        "[dim]Login: analyst@aegis.local / aegis1234 - approve it, "
        "then watch Metrics > Case memory.[/]"
    )


memory_app = typer.Typer(no_args_is_help=True, help="Case memory (Phase 1): Pulse mirror / local.")
app.add_typer(memory_app, name="memory")


@memory_app.command("show")
def memory_show() -> None:
    """Print memory backend, priors by technique and the cached analytics answer."""
    from aegis.memory.store import open_memory

    mem = open_memory()
    console.print_json(json.dumps(mem.status()))
    table = Table(title="Priors (technique / source)")
    for c in ("key", "n", "tp_rate", "escalate_rate", "override_rate"):
        table.add_column(c)
    for key, p in sorted(mem.priors().items(), key=lambda kv: -kv[1].n)[:25]:
        table.add_row(
            key,
            str(p.n),
            f"{p.tp_rate:.2f}",
            f"{p.escalate_rate:.2f}",
            f"{p.analyst_override_rate:.2f}",
        )
    console.print(table)
    a = mem.analytics()
    console.print(f"[bold]{a['question']}[/] ({a['source']})\n{a['answer']}")


lens_app = typer.Typer(no_args_is_help=True, help="Lens bridge: eval metrics + CI gate (SPEC §10).")
app.add_typer(lens_app, name="lens")


@lens_app.command("ci")
def lens_ci(
    snapshot: str = typer.Option("dev"),
    limit: int = typer.Option(40, help="alerts from the test split to gate on"),
) -> None:
    """Run the small suite + Lens metrics and gate on thresholds (exit non-zero on breach)."""
    from aegis.lens.ci import run_ci

    settings = get_settings()
    report = run_ci(
        settings.data.snapshots / snapshot, settings.data.root / "benchmark", limit=limit
    )
    console.print_json(json.dumps(report))
    console.print(f"[green]archived -> {_archive_result('lens_ci', report)}[/]")
    table = Table(title="Lens CI gates")
    for col in ("gate", "value", "threshold", "ok"):
        table.add_column(col)
    for g in report["gates"]:
        table.add_row(
            g["name"],
            f"{g['value']:.3f}",
            f"{g['direction']} {g['threshold']}",
            "[green]PASS[/]" if g["ok"] else "[red]FAIL[/]",
        )
    console.print(table)
    raise typer.Exit(0 if report["passed"] else 1)


@lens_app.command("metrics")
def lens_metrics(snapshot: str = typer.Option("dev"), limit: int = typer.Option(40)) -> None:
    """Print aggregate Lens metrics (faithfulness, tool correctness, efficiency)."""
    from aegis.lens.ci import run_ci

    settings = get_settings()
    report = run_ci(
        settings.data.snapshots / snapshot, settings.data.root / "benchmark", limit=limit
    )
    console.print_json(json.dumps(report["lens"]))


@app.command()
def serve(host: str = "127.0.0.1", port: int = 8000, reload: bool = False) -> None:
    """Run the FastAPI review backend + WebSocket (Phase 4)."""
    import uvicorn

    uvicorn.run("aegis.api.app:app", host=host, port=port, reload=reload)


@app.command()
def replay(investigation_id: str) -> None:
    """Re-render a stored investigation's report and audit trail (Phase 3)."""
    from aegis.api.store import Store

    inv = Store().get_investigation(investigation_id)
    if inv is None:
        console.print(f"[red]investigation {investigation_id} not found[/]")
        raise typer.Exit(1)
    console.print(f"[bold]{inv['title']}[/] -> {inv['verdict']} ({inv['confidence']})")
    console.print(f"nodes: {' -> '.join(inv['state'].get('node_log', []))}")
    console.print(inv.get("report_md") or "[dim]no report[/]")


@app.command()
def label(
    investigation_id: str,
    verdict: str = typer.Argument(..., help="true_positive | false_positive | escalate"),
    analyst: str = typer.Option("analyst"),
    annotation: str | None = typer.Option(None),
) -> None:
    """Apply an analyst override/label; overrides become training labels (Phase 4)."""
    from aegis.api.store import Store

    try:
        rid = Store().add_review(
            investigation_id, analyst, "override", override_verdict=verdict, annotation=annotation
        )
    except KeyError:
        console.print(f"[red]investigation {investigation_id} not found[/]")
        raise typer.Exit(1) from None
    console.print(f"[green]recorded review {rid}[/] -> gold label {verdict}")


# ------------------------------------------------------------------------------------------------
# aegis lab ...  (Phase 1)
# ------------------------------------------------------------------------------------------------
@lab_app.command("scenarios")
def lab_scenarios(
    json_out: bool = typer.Option(False, "--json", help="emit coverage as JSON"),
) -> None:
    """Validate emulation scenarios against the ART index and print ATT&CK coverage."""
    from lab.emulation.scenario import load_art_index, load_scenarios, validate_scenarios

    scenarios = load_scenarios()
    index = load_art_index()
    hosts = {"DC01": "windows", "WS01": "windows", "LNX01": "linux"}
    problems, coverage = validate_scenarios(scenarios, index, hosts)
    if json_out:
        console.print_json(json.dumps({"problems": problems, "coverage": coverage}))
        raise typer.Exit(code=1 if problems else 0)
    table = Table(title="Emulation scenarios")
    table.add_column("id")
    table.add_column("steps", justify="right")
    table.add_column("techniques", justify="right")
    for sc in scenarios:
        c = coverage["per_scenario"][sc.id]
        table.add_row(sc.id, str(c["steps"]), str(c["techniques"]))
    console.print(table)
    console.print(
        f"[bold]{coverage['technique_count']}[/] techniques "
        f"({coverage['parent_technique_count']} parent) across "
        f"[bold]{coverage['tactic_count']}[/] tactics: "
        f"{', '.join(coverage['tactic_names'])}"
    )
    ok40 = coverage["technique_count"] >= 40 and coverage["tactic_count"] >= 10
    console.print(
        f"Coverage target (>=40 techniques / >=10 tactics): "
        f"{'[green]met[/]' if ok40 else '[red]not met[/]'}"
    )
    if problems:
        console.print(f"[red]{len(problems)} validation problems:[/]")
        for p in problems:
            console.print(f"  - {p}")
        raise typer.Exit(code=1)


@lab_app.command("rules")
def lab_rules(
    no_download: bool = typer.Option(False, "--no-download"),
    min_conversion: float = typer.Option(
        0.9, "--min-conversion", help="fail (exit 2) if ES|QL or SPL conversion rate drops below"
    ),
) -> None:
    """Download the Sigma bundle, curate the pack and convert to ES|QL + SPL."""
    from lab.rules.convert import build_pack

    settings = get_settings()
    settings.data.raw.mkdir(parents=True, exist_ok=True)
    settings.data.rules.mkdir(parents=True, exist_ok=True)
    if no_download:
        from lab.rules.convert import convert_rules, load_pack_config, select_rules, write_pack

        bundle = settings.data.raw / "sigma" / "sigma_core++.zip"
        if not bundle.exists():
            console.print(f"[red]no cached bundle at {bundle}; drop --no-download[/]")
            raise typer.Exit(1)
        cfg = load_pack_config()
        summary = write_pack(convert_rules(select_rules(bundle, cfg)), settings.data.rules)
    else:
        summary = build_pack(settings.data.raw / "sigma", settings.data.rules)
    console.print_json(json.dumps(summary))
    from lab.rules.convert import conversion_floor_breach

    breach = conversion_floor_breach(summary, min_rate=min_conversion)
    if breach:
        console.print(f"[red]Sigma conversion below floor ({min_conversion:.0%}): {breach}[/]")
        console.print("[red]Check pysigma/pyparsing versions (STATUS.md B1).[/]")
        raise typer.Exit(2)


@lab_app.command("load")
def lab_load(
    datasets: str = typer.Option("otrf,evtx", help="comma list: otrf,evtx,bots,cicids"),
    limit: int | None = typer.Option(None, help="max refs per dataset (for quick runs)"),
    no_download: bool = typer.Option(False, "--no-download", help="use cached raw data only"),
    to_elastic: bool = typer.Option(False, "--to-elastic", help="also index into the lab SIEM"),
) -> None:
    """Load public datasets to Parquet staging (+ optional Elastic) with ground truth."""
    from lab.emulation.ground_truth import GroundTruthTable
    from lab.pipeline import load_evtx, load_otrf, make_sink

    settings = get_settings()
    settings.data.parquet.mkdir(parents=True, exist_ok=True)
    gt = GroundTruthTable(settings.data.ground_truth)
    elastic_sink = _elastic_writer_sink() if to_elastic else None
    sink = make_sink(settings.data.parquet, elastic_sink)
    wanted = {d.strip() for d in datasets.split(",") if d.strip()}
    reports = []
    if "otrf" in wanted:
        reports.append(
            load_otrf(settings.data.raw, sink, gt, limit=limit, download=not no_download)
        )
    if "evtx" in wanted:
        reports.append(
            load_evtx(settings.data.raw, sink, gt, limit=limit, download=not no_download)
        )
    if "bots" in wanted:
        _load_bots(settings, sink, gt, limit, reports)
    if "cicids" in wanted:
        _load_cicids(settings, sink, gt, limit, reports)
    if elastic_sink:
        elastic_sink.close()
    _print_load(reports, gt)


def _load_bots(settings, sink, gt, limit, reports) -> None:  # type: ignore[no-untyped-def]
    from lab.datasets.bots import BotsLoader

    loader = BotsLoader(settings.data.raw / "bots")
    try:
        files = loader.download()
    except FileNotFoundError as e:
        console.print(f"[yellow]bots skipped: {e}[/]")
        return
    from lab.pipeline import LoadReport

    rep = LoadReport("bots")
    for f in files:
        events = list(loader.iter_events(f))
        rep.events += sink.write(events)
        rep.refs += 1
    rep.windows += gt.append(loader.ground_truth())
    reports.append(rep)


def _load_cicids(settings, sink, gt, limit, reports) -> None:  # type: ignore[no-untyped-def]
    from lab.datasets.cicids import CicIdsLoader
    from lab.pipeline import LoadReport

    loader = CicIdsLoader(settings.data.raw / "cicids")
    try:
        files = loader.download()
    except FileNotFoundError as e:
        console.print(f"[yellow]cicids skipped: {e}[/]")
        return
    rep = LoadReport("cicids")
    for f in files[:limit]:
        events = list(loader.iter_events(f))
        rep.events += sink.write(events)
        rep.windows += gt.append(loader.ground_truth(f, events))
        rep.refs += 1
    reports.append(rep)


@lab_app.command("noise")
def lab_noise(
    seed: int = typer.Option(1337),
    days: int = typer.Option(14),
    per_day: int = typer.Option(12, help="benign FP episodes per day"),
    to_elastic: bool = typer.Option(False, "--to-elastic"),
) -> None:
    """Generate realistic benign / false-positive telemetry (SPEC §5.4)."""
    from lab.emulation.ground_truth import GroundTruthTable
    from lab.pipeline import generate_noise, make_sink

    settings = get_settings()
    settings.data.parquet.mkdir(parents=True, exist_ok=True)
    gt = GroundTruthTable(settings.data.ground_truth)
    elastic_sink = _elastic_writer_sink() if to_elastic else None
    sink = make_sink(settings.data.parquet, elastic_sink)
    rep = generate_noise(sink, gt, seed=seed, days=days, episodes_per_day=per_day)
    if elastic_sink:
        elastic_sink.close()
    _print_load([rep], gt)


@lab_app.command("emulate")
def lab_emulate(
    scenario: str = typer.Argument(..., help="scenario id, or 'all'"),
    transport: str = typer.Option("dry-run", help="local | ssh | vagrant | dry-run"),
    steps: str | None = typer.Option(None, help="comma list of step numbers"),
) -> None:
    """Run an Atomic Red Team scenario and record ground truth (SPEC §5.2)."""
    from lab.emulation.runner import run_scenario, scenario_summary
    from lab.emulation.scenario import load_scenarios

    settings = get_settings()
    scenarios = load_scenarios()
    if scenario != "all":
        scenarios = [s for s in scenarios if s.id == scenario]
        if not scenarios:
            console.print(f"[red]unknown scenario {scenario}[/]")
            raise typer.Exit(1)
    valid_transports = {"local", "ssh", "vagrant", "dry-run"}
    if transport not in valid_transports:
        console.print(f"[red]invalid transport {transport}; choose from {valid_transports}[/]")
        raise typer.Exit(2)
    only = {int(s) for s in steps.split(",")} if steps else None
    vms_dir = Path(__file__).resolve().parent.parent / "lab" / "vms"
    for sc in scenarios:
        console.print(f"[bold]{sc.id}[/] ({transport}): {sc.title}")
        results = run_scenario(
            sc,
            transport=transport,  # type: ignore[arg-type]
            data_root=settings.data.root,
            vms_dir=vms_dir,
            only_steps=only,
        )
        console.print_json(json.dumps(scenario_summary(results)))


@lab_app.command("snapshot")
def lab_snapshot(
    name: str = typer.Option("dev", help="snapshot name under data/snapshots/"),
    source: str = typer.Option("parquet", help="parquet | elastic"),
    verify: bool = typer.Option(True, help="verify the snapshot after creating it"),
) -> None:
    """Consolidate staged data into an immutable Parquet snapshot for --offline (SPEC §8.5)."""
    from lab.noise.generators import ORG_YAML
    from lab.snapshot import create_snapshot, verify_snapshot

    settings = get_settings()
    repo_root = Path(__file__).resolve().parent.parent
    dest = create_snapshot(
        name=name,
        data_root=settings.data.root,
        repo_root=repo_root,
        source=source,
        elastic_settings=settings.elastic if source == "elastic" else None,
        org_yaml=ORG_YAML,
    )
    console.print(f"[green]snapshot written[/] -> {dest}")
    if verify:
        report = verify_snapshot(dest)
        console.print_json(json.dumps(report))
        if not report["ok"]:
            raise typer.Exit(1)


@lab_app.command("verify")
def lab_verify(
    name: str = typer.Option("dev"),
) -> None:
    """Verify a snapshot's hashes and re-open it with DuckDB (offline SIEM adapter)."""
    from lab.snapshot import verify_snapshot

    settings = get_settings()
    report = verify_snapshot(settings.data.snapshots / name)
    console.print_json(json.dumps(report))
    raise typer.Exit(0 if report["ok"] else 1)


@lab_app.command("coverage")
def lab_coverage() -> None:
    """Print ground-truth coverage (techniques, tactics, fp_types)."""
    from lab.emulation.ground_truth import GroundTruthTable

    settings = get_settings()
    console.print_json(json.dumps(GroundTruthTable(settings.data.ground_truth).coverage()))


def _elastic_writer_sink() -> EventSink:
    from lab.common.sink import ElasticSink

    return ElasticSink(get_settings().elastic)


def _print_load(reports, gt) -> None:  # type: ignore[no-untyped-def]
    table = Table(title="Lab load")
    for col in ("dataset", "refs", "events", "windows", "errors"):
        table.add_column(col, justify="right" if col != "dataset" else "left")
    for r in reports:
        table.add_row(r.dataset, str(r.refs), str(r.events), str(r.windows), str(len(r.errors)))
    console.print(table)
    cov = gt.coverage()
    console.print(
        f"ground truth: {cov['windows']} windows, {cov['technique_count']} techniques, "
        f"{cov['tactic_count']} tactics, fp_types={len(cov['fp_types'])}"
    )
    for r in reports:
        for e in r.errors[:5]:
            console.print(f"  [yellow]{r.dataset}: {e}[/]")


if __name__ == "__main__":
    app()
