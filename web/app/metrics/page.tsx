"use client";
import useSWR from "swr";
import { fetcher, type Metrics } from "@/lib/api";
import { Card, SectionTitle, Spinner, StatCard } from "@/components/ui";

const VERDICT_COLOR: Record<string, string> = {
  true_positive: "rgb(var(--danger))",
  false_positive: "rgb(var(--success))",
  escalate: "rgb(var(--warning))",
};
const VERDICT_LABEL: Record<string, string> = {
  true_positive: "True positive",
  false_positive: "False positive",
  escalate: "Escalate",
};

export default function MetricsPage() {
  const { data } = useSWR<Metrics>("/api/metrics", fetcher, { refreshInterval: 5000 });
  if (!data) return <Spinner />;
  const pct = (v: number | null) => (v == null ? "—" : `${Math.round(v * 100)}%`);
  const verdicts = Object.entries(data.by_verdict);

  return (
    <div className="animate-in">
      <div className="mb-6">
        <h1 className="text-2xl font-semibold tracking-tight">Metrics</h1>
        <p className="mt-1 text-sm text-muted">Live operational and quality signals across the review queue</p>
      </div>

      <div className="mb-6 grid grid-cols-2 gap-3 lg:grid-cols-4">
        <StatCard label="Investigations" value={String(data.total)} />
        <StatCard label="Accuracy vs gold" value={pct(data.accuracy_vs_gold)} accent />
        <StatCard label="Fast-path rate" value={pct(data.fast_path_rate)} />
        <StatCard label="Analyst reviews" value={String(data.reviews)} />
        <StatCard label="Avg tool calls" value={data.avg_tool_calls.toFixed(1)} sub="per investigation" />
        <StatCard label="Avg latency" value={`${data.avg_seconds.toFixed(2)}s`} sub="per alert" />
        <StatCard label="Avg cost" value={`$${data.avg_cost_usd.toFixed(4)}`} sub="per alert" />
        <StatCard label="Auto-triaged" value={pct(1 - (data.reviews / Math.max(1, data.total)))} sub="no human needed" />
      </div>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-5">
        <Card className="p-5 lg:col-span-2">
          <SectionTitle>Verdict distribution</SectionTitle>
          <div className="flex items-center gap-6">
            <Donut data={verdicts} total={data.total} />
            <div className="space-y-2">
              {verdicts.map(([k, v]) => (
                <div key={k} className="flex items-center gap-2 text-sm">
                  <span className="h-2.5 w-2.5 rounded-sm" style={{ background: VERDICT_COLOR[k] ?? "rgb(var(--info))" }} />
                  <span className="text-muted">{VERDICT_LABEL[k] ?? k}</span>
                  <span className="ml-auto font-semibold tabular-nums text-text">{v}</span>
                </div>
              ))}
            </div>
          </div>
        </Card>

        <Card className="p-5 lg:col-span-3">
          <SectionTitle>Verdicts by volume</SectionTitle>
          <div className="space-y-3">
            {verdicts.map(([k, v]) => {
              const w = data.total ? Math.round((v / data.total) * 100) : 0;
              return (
                <div key={k}>
                  <div className="mb-1 flex justify-between text-sm">
                    <span className="text-muted">{VERDICT_LABEL[k] ?? k}</span>
                    <span className="tabular-nums text-dim">{v} · {w}%</span>
                  </div>
                  <div className="h-2.5 overflow-hidden rounded-full bg-border">
                    <div className="h-full rounded-full" style={{ width: `${w}%`, background: VERDICT_COLOR[k] ?? "rgb(var(--info))" }} />
                  </div>
                </div>
              );
            })}
            {verdicts.length === 0 && <p className="text-sm text-dim">No investigations yet.</p>}
          </div>
        </Card>
      </div>

      <p className="mt-6 text-xs text-dim">
        Lens dashboards (report faithfulness, tool-call correctness, calibration) embed here in
        production via <code className="rounded bg-surface-2 px-1.5 py-0.5">aegis lens metrics</code>.
      </p>
    </div>
  );
}

function Donut({ data, total }: { data: [string, number][]; total: number }) {
  const R = 52;
  const C = 2 * Math.PI * R;
  let offset = 0;
  const segs = data.map(([k, v]) => {
    const frac = total ? v / total : 0;
    const seg = { k, len: frac * C, off: offset };
    offset += frac * C;
    return seg;
  });
  return (
    <div className="relative h-36 w-36 shrink-0">
      <svg viewBox="0 0 128 128" className="h-full w-full -rotate-90">
        <circle cx="64" cy="64" r={R} fill="none" stroke="rgb(var(--border))" strokeWidth="16" />
        {segs.map((s) => (
          <circle
            key={s.k}
            cx="64" cy="64" r={R} fill="none"
            stroke={VERDICT_COLOR[s.k] ?? "rgb(var(--info))"}
            strokeWidth="16"
            strokeDasharray={`${s.len} ${C - s.len}`}
            strokeDashoffset={-s.off}
          />
        ))}
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="text-2xl font-semibold tabular-nums">{total}</span>
        <span className="text-[11px] uppercase tracking-wider text-dim">alerts</span>
      </div>
    </div>
  );
}
