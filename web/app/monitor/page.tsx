"use client";
import { useState } from "react";
import Link from "next/link";
import useSWR from "swr";
import { api, fetcher, type MonitorData } from "@/lib/api";
import { Button, Card, Icon, PageHeader, SectionTitle, StatCard, Spinner, VerdictBadge } from "@/components/ui";

export default function MonitorPage() {
  const { data, mutate } = useSWR<MonitorData>("/api/monitor", fetcher, { refreshInterval: 4000 });
  const [busy, setBusy] = useState(false);

  async function tick() {
    setBusy(true);
    try { await api.investigate(10); await mutate(); } finally { setBusy(false); }
  }

  if (!data) return <Spinner />;
  const p = data.posture;
  const cov = data.coverage;

  return (
    <div className="animate-rise">
      <PageHeader
        title="Continuous Monitoring"
        subtitle="Always-on visibility across cloud, hybrid and on-prem workloads — adapting to ephemeral infrastructure"
        live
        action={<Button onClick={tick} disabled={busy}><Icon.bolt className="h-4 w-4" />{busy ? "Sweeping…" : "Run detection sweep"}</Button>}
      />

      <div className="mb-6 grid grid-cols-2 gap-3 lg:grid-cols-4">
        <StatCard label="Events monitored" value={fmt(cov.events_monitored)} sub={`${cov.hosts} hosts · snapshot ${cov.snapshot}`} />
        <StatCard label="Investigations" value={String(p.total_investigations)} />
        <StatCard label="Open incidents" value={String(p.open_incidents)} tone="text-danger" sub="need analyst action" />
        <StatCard label="Auto-suppressed" value={String(p.auto_suppressed)} tone="text-success" sub="false positives closed" />
      </div>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
        <Card className="p-5 lg:col-span-2">
          <SectionTitle right={<span className="text-xs text-dim">auto-refreshing</span>}>Live activity feed</SectionTitle>
          <div className="divide-y divide-border">
            {data.feed.map((f) => (
              <Link key={f.investigation_id} href={`/investigations/${f.investigation_id}`}
                className="flex items-center gap-3 py-2.5 transition hover:opacity-80">
                <span className={`h-2 w-2 shrink-0 rounded-full ${f.verdict === "true_positive" ? "bg-danger" : f.verdict === "escalate" ? "bg-warning" : "bg-success"}`} />
                <span className="min-w-0 flex-1 truncate text-sm text-text">{f.title}</span>
                {f.injection_flagged && <span className="rounded-md border border-warning/30 bg-warning/10 px-1.5 py-0.5 text-[10px] uppercase text-warning">injection</span>}
                <VerdictBadge v={f.verdict} />
                <span className="w-16 shrink-0 text-right font-mono text-[11px] text-dim">{new Date(f.created_at).toLocaleTimeString()}</span>
              </Link>
            ))}
            {data.feed.length === 0 && <p className="py-8 text-center text-sm text-dim">No activity yet — run a detection sweep.</p>}
          </div>
        </Card>

        <div className="space-y-6">
          <Card className="p-5">
            <SectionTitle>Coverage by source</SectionTitle>
            <div className="space-y-3">
              {Object.entries(cov.datasets).map(([ds, v]) => {
                const w = cov.events_monitored ? (v.events / cov.events_monitored) * 100 : 0;
                return (
                  <div key={ds}>
                    <div className="mb-1 flex justify-between text-sm">
                      <span className="capitalize text-muted">{ds.replace("_", " ")}</span>
                      <span className="tabular-nums text-dim">{fmt(v.events)}</span>
                    </div>
                    <div className="h-2 overflow-hidden rounded-full bg-border">
                      <div className="h-full rounded-full bg-gradient-to-r from-accent to-accent-hover" style={{ width: `${w}%` }} />
                    </div>
                  </div>
                );
              })}
            </div>
          </Card>
          <Card className="p-5">
            <SectionTitle>Posture</SectionTitle>
            <Row label="Avg investigation latency" value={`${p.avg_latency_s.toFixed(2)}s`} />
            <Row label="Injection events" value={String(p.injection_events)} tone={p.injection_events ? "text-warning" : "text-success"} />
            <Row label="True positives" value={String(p.by_verdict.true_positive ?? 0)} tone="text-danger" />
            <Row label="Escalations" value={String(p.by_verdict.escalate ?? 0)} tone="text-warning" />
          </Card>
        </div>
      </div>
    </div>
  );
}

function Row({ label, value, tone }: { label: string; value: string; tone?: string }) {
  return (
    <div className="flex justify-between border-b border-border py-2 text-sm last:border-0">
      <span className="text-muted">{label}</span>
      <span className={`font-medium tabular-nums ${tone ?? "text-text"}`}>{value}</span>
    </div>
  );
}

function fmt(n: number) {
  return n >= 1000 ? `${(n / 1000).toFixed(n >= 10000 ? 0 : 1)}k` : String(n);
}
