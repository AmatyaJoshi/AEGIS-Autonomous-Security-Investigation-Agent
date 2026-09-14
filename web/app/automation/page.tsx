"use client";
import useSWR from "swr";
import { fetcher, type AutomationData } from "@/lib/api";
import { Card, Icon, PageHeader, SectionTitle, Spinner, StatCard } from "@/components/ui";

const KIND_TONE: Record<string, string> = {
  suppression: "text-success bg-success/10 border-success/25",
  safety: "text-warning bg-warning/10 border-warning/25",
  quality: "text-accent bg-accent/10 border-accent/25",
};

export default function AutomationPage() {
  const { data } = useSWR<AutomationData>("/api/automation", fetcher, { refreshInterval: 5000 });
  if (!data) return <Spinner />;
  const k = data.kpis;
  const pct = (v: number) => `${Math.round(v * 100)}%`;

  return (
    <div className="animate-rise">
      <PageHeader
        title="Automation"
        subtitle="Streamline repetitive triage so analysts focus on complex threats — Agentic AI that plans, executes and verifies"
      />

      <div className="mb-6 grid grid-cols-2 gap-3 lg:grid-cols-4">
        <StatCard label="Auto-triaged" value={pct(k.auto_triaged_rate)} accent sub="no human needed" />
        <StatCard label="Analyst time saved" value={`${(k.analyst_minutes_saved / 60).toFixed(1)}h`} tone="text-success" sub={`${k.analyst_minutes_saved} min`} />
        <StatCard label="Avg latency" value={`${k.avg_latency_s.toFixed(2)}s`} sub="per investigation" />
        <StatCard label="Manual reviews" value={String(k.manual_reviews)} sub={`of ${k.total} total`} />
      </div>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
        <Card className="p-5 lg:col-span-2">
          <SectionTitle>Automation rules</SectionTitle>
          <div className="space-y-3">
            {data.rules.map((r) => (
              <div key={r.name} className="flex items-start gap-3 rounded-xl border border-border bg-surface-2 p-3.5">
                <span className={`mt-0.5 shrink-0 rounded-lg border px-2 py-0.5 text-[10px] font-medium uppercase ${KIND_TONE[r.kind] ?? ""}`}>{r.kind}</span>
                <div className="min-w-0 flex-1">
                  <div className="text-sm font-semibold text-text">{r.name}</div>
                  <p className="mt-0.5 text-xs text-muted"><span className="text-dim">When</span> {r.trigger}</p>
                  <p className="text-xs text-muted"><span className="text-dim">Then</span> {r.action}</p>
                </div>
                <span className="mt-0.5 inline-flex items-center gap-1 rounded-full bg-success/10 px-2 py-0.5 text-[11px] font-medium text-success">
                  <span className="h-1.5 w-1.5 rounded-full bg-success" /> On
                </span>
              </div>
            ))}
          </div>
        </Card>

        <Card className="p-5">
          <SectionTitle>Safety guardrails</SectionTitle>
          <ul className="space-y-3">
            {data.guardrails.map((g) => (
              <li key={g} className="flex items-start gap-2.5 text-sm text-muted">
                <span className="mt-0.5 flex h-5 w-5 shrink-0 items-center justify-center rounded-full bg-success/12 text-success">
                  <Icon.check className="h-3 w-3" />
                </span>
                {g}
              </li>
            ))}
          </ul>
          <div className="mt-5 rounded-xl border border-accent/25 bg-accent/5 p-3.5">
            <div className="text-xs font-semibold uppercase tracking-wider text-accent">Fast-path suppression</div>
            <div className="mt-1 text-2xl font-semibold tabular-nums text-text">{pct(k.fast_path_rate)}</div>
            <p className="mt-0.5 text-xs text-dim">of alerts auto-closed by the triage model, at 0% missed detections</p>
          </div>
        </Card>
      </div>
    </div>
  );
}
