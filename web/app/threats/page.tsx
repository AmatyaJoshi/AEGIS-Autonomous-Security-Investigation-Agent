"use client";
import Link from "next/link";
import useSWR from "swr";
import { fetcher, type ThreatData } from "@/lib/api";
import { Card, Meter, PageHeader, SectionTitle, SeverityBadge, Spinner, StatCard } from "@/components/ui";

const TYPE_TONE: Record<string, string> = {
  domain: "text-medium bg-medium/10 border-medium/25",
  ip: "text-low bg-low/10 border-low/25",
  hash: "text-critical bg-critical/10 border-critical/25",
};

export default function ThreatsPage() {
  const { data } = useSWR<ThreatData>("/api/threats", fetcher, { refreshInterval: 6000 });
  if (!data) return <Spinner />;
  const maxTech = Math.max(1, ...data.top_techniques.map((t) => t.count));

  return (
    <div className="animate-rise">
      <PageHeader
        title="Threat Detection"
        subtitle="Real-time threat intel and vulnerability signals — spot IoCs, novel tactics and emerging threats with precision"
      />

      <div className="mb-6 grid grid-cols-2 gap-3 lg:grid-cols-4">
        <StatCard label="Active detections" value={String(data.detection_count)} tone="text-danger" />
        <StatCard label="Indicators tracked" value={String(data.intel_feed_size)} />
        <StatCard label="ATT&CK techniques" value={String(data.top_techniques.length)} />
        <StatCard label="Intel feeds" value="4" sub="VT · AbuseIPDB · GreyNoise · OTX" />
      </div>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-5">
        <Card className="p-5 lg:col-span-3">
          <SectionTitle>Recent detections</SectionTitle>
          <div className="divide-y divide-border">
            {data.detections.map((d) => (
              <Link key={d.investigation_id} href={`/investigations/${d.investigation_id}`}
                className="flex items-center gap-3 py-3 transition hover:opacity-80">
                <span className={`h-2 w-2 shrink-0 rounded-full ${d.verdict === "true_positive" ? "bg-danger" : "bg-warning"}`} />
                <div className="min-w-0 flex-1">
                  <div className="truncate text-sm font-medium text-text">{d.title}</div>
                  <div className="mt-0.5 flex flex-wrap gap-1">
                    {d.techniques.slice(0, 4).map((t) => (
                      <span key={t} className="rounded border border-border bg-surface-2 px-1.5 py-0.5 font-mono text-[10px] text-muted">{t}</span>
                    ))}
                  </div>
                </div>
                <SeverityBadge s={d.severity} />
              </Link>
            ))}
            {data.detections.length === 0 && <p className="py-10 text-center text-sm text-dim">No active detections. Run investigations from Monitor.</p>}
          </div>
        </Card>

        <div className="space-y-6 lg:col-span-2">
          <Card className="p-5">
            <SectionTitle>ATT&CK coverage</SectionTitle>
            <div className="space-y-2.5">
              {data.top_techniques.map((t) => (
                <div key={t.technique}>
                  <div className="mb-1 flex items-baseline justify-between gap-2 text-sm">
                    <span className="truncate text-muted"><span className="font-mono text-xs text-dim">{t.technique}</span> {t.name}</span>
                    <span className="tabular-nums text-dim">{t.count}</span>
                  </div>
                  <div className="h-1.5 overflow-hidden rounded-full bg-border">
                    <div className="h-full rounded-full bg-gradient-to-r from-high to-critical" style={{ width: `${(t.count / maxTech) * 100}%` }} />
                  </div>
                </div>
              ))}
            </div>
          </Card>

          <Card className="p-5">
            <SectionTitle right={<span className="text-xs text-dim">cached · offline</span>}>Threat-intel feed (IoCs)</SectionTitle>
            <div className="space-y-2">
              {data.iocs.slice(0, 9).map((i) => (
                <div key={i.indicator} className="flex items-center gap-2">
                  <span className={`shrink-0 rounded-md border px-1.5 py-0.5 text-[10px] font-medium uppercase ${TYPE_TONE[i.type] ?? ""}`}>{i.type}</span>
                  <span className="min-w-0 flex-1 truncate font-mono text-xs text-muted">{i.indicator}</span>
                  <Meter value={i.score} tone={i.score >= 0.7 ? "bg-danger" : "bg-warning"} width="w-10" />
                  <span className="w-8 shrink-0 text-right text-xs tabular-nums text-dim">{i.score.toFixed(2)}</span>
                </div>
              ))}
            </div>
          </Card>
        </div>
      </div>
    </div>
  );
}
