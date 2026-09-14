"use client";
import useSWR from "swr";
import { fetcher, type AssetsData } from "@/lib/api";
import { Card, PageHeader, SectionTitle, Spinner, StatCard } from "@/components/ui";

const CRIT: Record<string, string> = {
  critical: "bg-critical/12 text-critical border-critical/25",
  high: "bg-high/12 text-high border-high/25",
  medium: "bg-medium/14 text-medium border-medium/25",
  low: "bg-low/12 text-low border-low/25",
};

export default function AssetsPage() {
  const { data } = useSWR<AssetsData>("/api/assets", fetcher);
  if (!data) return <Spinner />;
  const crit = data.hosts.filter((h) => h.criticality === "critical").length;
  return (
    <div className="animate-rise">
      <PageHeader title="Assets" subtitle={`Configuration management database · ${data.domain}`} />
      <div className="mb-6 grid grid-cols-2 gap-3 lg:grid-cols-4">
        <StatCard label="Managed hosts" value={String(data.count)} />
        <StatCard label="Critical assets" value={String(crit)} tone="text-critical" />
        <StatCard label="Zones" value={String(data.zones.length)} sub={data.zones.join(", ")} />
        <StatCard label="Domain" value={data.domain} />
      </div>
      <Card className="overflow-hidden">
        <div className="border-b border-border px-5 py-3"><SectionTitle>Inventory</SectionTitle></div>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead><tr className="border-b border-border text-left text-xs uppercase tracking-wider text-dim">
              <th className="px-5 py-2.5 font-medium">Host</th><th className="px-3 py-2.5 font-medium">Role</th>
              <th className="px-3 py-2.5 font-medium">OS</th><th className="px-3 py-2.5 font-medium">Zone</th>
              <th className="px-3 py-2.5 font-medium">Owner</th><th className="px-3 py-2.5 font-medium">IP</th>
              <th className="px-3 py-2.5 font-medium">Criticality</th></tr></thead>
            <tbody>
              {data.hosts.map((h) => (
                <tr key={h.name} className="border-b border-border/60 transition last:border-0 hover:bg-surface-2">
                  <td className="px-5 py-2.5 font-medium text-text">{h.name}</td>
                  <td className="px-3 py-2.5 text-muted">{h.role}</td>
                  <td className="px-3 py-2.5 capitalize text-muted">{h.os}</td>
                  <td className="px-3 py-2.5 text-muted">{h.zone}</td>
                  <td className="px-3 py-2.5 text-muted">{h.owner}</td>
                  <td className="px-3 py-2.5 font-mono text-xs text-dim">{h.ip}</td>
                  <td className="px-3 py-2.5"><span className={`inline-flex rounded-lg border px-2 py-0.5 text-xs font-medium capitalize ${CRIT[h.criticality] ?? "border-border text-dim"}`}>{h.criticality}</span></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>
    </div>
  );
}
