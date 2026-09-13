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


@app.callback()
def main(log_level: str = typer.Option("INFO", "--log-level", envvar="AEGIS_LOG_LEVEL")) -> None:
    _setup_logging(log_level)


@app.command()
def version() -> None:
    """Print the AEGIS version."""
    console.print(f"AEGIS {__version__}")


# ------------------------------------------------------------------------------------------------
# Phase-stub commands (implemented in later phases; present so the CLI surface is stable)
# ------------------------------------------------------------------------------------------------
def _not_yet(phase: str) -> None:
    console.print(f"[yellow]Not implemented yet[/] - delivered in Phase {phase} (see SPEC.md §11).")
    raise typer.Exit(code=2)


@app.command()
def investigate(
    source: str = typer.Option("offline", help="offline | elastic | splunk"),
    snapshot: str = typer.Option("dev", help="snapshot name for offline source"),
    limit: int = typer.Option(5, help="number of alerts to investigate"),
    seed: int = typer.Option(1337),
    review: bool = typer.Option(False, help="interrupt before playbook for human review"),
    out: Path | None = typer.Option(None, help="write reports to this directory"),
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
    router = LLMRouter()
    reasoner: Any
    if router.available:
        from aegis.graph.llm_reasoner import LLMReasoner

        reasoner = LLMReasoner(router)
        console.print(f"[green]Using LLM reasoner ({router.model})[/]")
    else:
        reasoner = HeuristicReasoner()
        console.print("[cyan]No API key; using deterministic heuristic reasoner (offline).[/]")
    deps = Deps(
        siem=siem,
        reasoner=reasoner,
        review_mode=review,
        pack_path=str(snap / "rules" / "sigma_pack.jsonl"),
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
    console.print(table)


@app.command()
def ingest(source: str = typer.Option("elastic"), path: Path | None = None) -> None:
    """Normalise source alerts to OCSF (Phase 2)."""
    _not_yet("2")


@app.command()
def bench(
    action: str = typer.Argument(..., help="prepare | build | run | score | report | all | small"),
    snapshot: str = typer.Option("dev"),
    split: str = typer.Option("test", help="split to run/score (train|val|test|all)"),
    total: int = typer.Option(420, help="benchmark size for build"),
    triage: Path | None = typer.Option(None, help="triage model path for aegis_full arm"),
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
        console.print_json(
            _json.dumps(
                run_benchmark(snap, bench_dir, results_dir, split=real_split, triage_model=tri)
            )
        )

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
        out = render_report(scores, meta, results_dir / "report.html", roc_dir=results_dir)
        console.print(f"[green]report -> {out}[/]")
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

    if action == "prepare":
        _prepare()
    elif action == "build":
        _build()
    elif action == "run":
        _run()
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
def serve(host: str = "127.0.0.1", port: int = 8000) -> None:
    """Run the FastAPI review backend (Phase 4)."""
    _not_yet("4")


@app.command()
def replay(investigation_id: str) -> None:
    """Replay a checkpointed investigation (Phase 3)."""
    _not_yet("3")


@app.command()
def label(investigation_id: str, verdict: str) -> None:
    """Apply an analyst label/override (Phase 4)."""
    _not_yet("4")


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
