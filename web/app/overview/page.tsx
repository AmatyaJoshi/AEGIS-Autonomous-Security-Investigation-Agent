"use client";
import Link from "next/link";
import useSWR from "swr";
import { useAuth } from "@/components/auth";
import { fetcher, type MonitorData, type Metrics } from "@/lib/api";
import { Card, Icon, PageHeader, SectionTitle, Spinner, StatCard, VerdictBadge } from "@/components/ui";

const CAPABILITIES = [
  { href: "/monitor", label: "Continuous Monitoring", desc: "Always-on visibility across cloud & hybrid", icon: Icon.monitor },
  { href: "/logs", label: "Log Analysis", desc: "Correlate decentralized telemetry", icon: Icon.logs },
  { href: "/threats", label: "Threat Detection", desc: "Real-time intel, IoCs & ATT&CK", icon: Icon.radar },
  { href: "/response", label: "Incident Response", desc: "Human-approved playbooks", icon: Icon.response },
  { href: "/automation", label: "Automation", desc: "Auto-triage repetitive work", icon: Icon.automation },
];

export default function OverviewPage() {
  const { user } = useAuth();
  const { data: mon } = useSWR<MonitorData>("/api/monitor", fetcher, { refreshInterval: 5000 });
  const { data: met } = useSWR<Metrics>("/api/metrics", fetcher, { refreshInterval: 5000 });
  if (!mon || !met) return <Spinner />;
  const p = mon.posture;

  return (
    <div className="animate-rise">
      <PageHeader title={`Welcome, ${user?.name.split(" ")[0]}`} subtitle="Your autonomous SOC at a glance" live />

      <div className="mb-6 grid grid-cols-2 gap-3 lg:grid-cols-4">
        <StatCard label="Events monitored" value={fmt(mon.coverage.events_monitored)} sub={`${mon.coverage.hosts} hosts`} accent />
        <StatCard label="Open incidents" value={String(p.open_incidents)} tone="text-danger" sub="need action" />
        <StatCard label="Auto-suppressed" value={String(p.auto_suppressed)} tone="text-success" sub="false positives" />
        <StatCard label="Accuracy vs gold" value={met.accuracy_vs_gold != null ? `${Math.round(met.accuracy_vs_gold * 100)}%` : "—"} />
      </div>

      <SectionTitle>Capabilities</SectionTitle>
      <div className="mb-8 grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3">
        {CAPABILITIES.map((c) => (
          <Link key={c.href} href={c.href}>
            <Card className="group flex items-center gap-4 p-4 transition duration-300 ease-spring hover:-translate-y-0.5 hover:shadow-float">
              <span className="flex h-11 w-11 shrink-0 items-center justify-center rounded-2xl bg-accent/10 text-accent transition group-hover:bg-accent group-hover:text-white">
                <c.icon className="h-6 w-6" />
              </span>
              <div className="min-w-0">
                <div className="font-semibold text-text">{c.label}</div>
                <div className="truncate text-sm text-dim">{c.desc}</div>
              </div>
              <Icon.chevron className="ml-auto h-4 w-4 shrink-0 text-dim transition group-hover:translate-x-0.5 group-hover:text-accent" />
            </Card>
          </Link>
        ))}
      </div>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
        <Card className="p-5 lg:col-span-2">
          <SectionTitle right={<Link href="/" className="text-xs font-medium text-accent hover:underline">View all →</Link>}>Recent activity</SectionTitle>
          <div className="divide-y divide-border">
            {mon.feed.slice(0, 8).map((f) => (
              <Link key={f.investigation_id} href={`/investigations/${f.investigation_id}`} className="flex items-center gap-3 py-2.5 transition hover:opacity-80">
                <span className={`h-2 w-2 shrink-0 rounded-full ${f.verdict === "true_positive" ? "bg-danger" : f.verdict === "escalate" ? "bg-warning" : "bg-success"}`} />
                <span className="min-w-0 flex-1 truncate text-sm">{f.title}</span>
                <VerdictBadge v={f.verdict} />
              </Link>
            ))}
            {mon.feed.length === 0 && <p className="py-8 text-center text-sm text-dim">No activity yet. Open Monitor to run a sweep.</p>}
          </div>
        </Card>

        <Card className="p-5">
          <SectionTitle>Verdicts</SectionTitle>
          <div className="space-y-3">
            {Object.entries(met.by_verdict).map(([k, v]) => {
              const total = met.total || 1;
              const w = Math.round((v / total) * 100);
              const tone = k === "true_positive" ? "bg-danger" : k === "escalate" ? "bg-warning" : "bg-success";
              return (
                <div key={k}>
                  <div className="mb-1 flex justify-between text-sm">
                    <span className="capitalize text-muted">{k.replace("_", " ")}</span>
                    <span className="tabular-nums text-dim">{v}</span>
                  </div>
                  <div className="h-2 overflow-hidden rounded-full bg-border"><div className={`h-full rounded-full ${tone}`} style={{ width: `${w}%` }} /></div>
                </div>
              );
            })}
          </div>
        </Card>
      </div>
    </div>
  );
}

function fmt(n: number) { return n >= 1000 ? `${(n / 1000).toFixed(n >= 10000 ? 0 : 1)}k` : String(n); }
