"use client";
import useSWR from "swr";
import { fetcher, type Metrics } from "@/lib/api";

function Kpi({ label, value }: { label: string; value: string }) {
  return (
    <div className="border border-slate-800 rounded p-4">
      <div className="text-xs uppercase tracking-wide text-slate-500">{label}</div>
      <div className="text-2xl font-semibold mt-1">{value}</div>
    </div>
  );
}

export default function MetricsPage() {
  const { data } = useSWR<Metrics>("/api/metrics", fetcher, { refreshInterval: 5000 });
  if (!data) return <p className="text-slate-500">Loading…</p>;
  const pct = (v: number | null) => (v == null ? "-" : `${Math.round(v * 100)}%`);
  return (
    <div>
      <h1 className="text-lg font-semibold mb-4">Live metrics</h1>
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-6">
        <Kpi label="Investigations" value={String(data.total)} />
        <Kpi label="Accuracy vs gold" value={pct(data.accuracy_vs_gold)} />
        <Kpi label="Fast-path rate" value={pct(data.fast_path_rate)} />
        <Kpi label="Avg tool calls" value={data.avg_tool_calls.toFixed(1)} />
        <Kpi label="Avg seconds/alert" value={data.avg_seconds.toFixed(2)} />
        <Kpi label="Avg cost/alert" value={`$${data.avg_cost_usd.toFixed(4)}`} />
        <Kpi label="Analyst reviews" value={String(data.reviews)} />
      </div>
      <h2 className="text-sm font-semibold text-sky-400 mb-2">Verdicts</h2>
      <div className="flex gap-3">
        {Object.entries(data.by_verdict).map(([k, v]) => (
          <div key={k} className="border border-slate-800 rounded px-4 py-2 text-sm">
            <span className="text-slate-400">{k}: </span>
            <span className="font-semibold">{v}</span>
          </div>
        ))}
      </div>
      <p className="text-xs text-slate-600 mt-6">
        Lens dashboards (report faithfulness, tool correctness, calibration) embed here in production
        via <code>aegis lens metrics</code>.
      </p>
    </div>
  );
}
