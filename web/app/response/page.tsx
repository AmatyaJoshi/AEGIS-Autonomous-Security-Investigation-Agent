"use client";
import { useState } from "react";
import Link from "next/link";
import useSWR from "swr";
import { fetcher, type ResponseData } from "@/lib/api";
import { Card, Icon, PageHeader, SectionTitle, SeverityBadge, Spinner, StatCard, VerdictBadge } from "@/components/ui";

export default function ResponsePage() {
  const { data } = useSWR<ResponseData>("/api/response", fetcher, { refreshInterval: 6000 });
  const [openPb, setOpenPb] = useState<string | null>(null);
  if (!data) return <Spinner />;

  return (
    <div className="animate-rise">
      <PageHeader
        title="Incident Response"
        subtitle="Prebuilt playbooks and workflows to contain threats fast — AEGIS recommends; a human approves every action"
      />

      <div className="mb-6 grid grid-cols-2 gap-3 lg:grid-cols-4">
        <StatCard label="Open incidents" value={String(data.open_count)} tone="text-danger" />
        <StatCard label="Playbooks" value={String(data.playbooks.length)} />
        <StatCard label="Auto-contained" value="0" sub="human-approved only" tone="text-success" />
        <StatCard label="Mode" value="Recommend" sub="containment stays human" tone="text-accent" />
      </div>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-5">
        <Card className="p-5 lg:col-span-3">
          <SectionTitle>Incidents needing action</SectionTitle>
          <div className="divide-y divide-border">
            {data.incidents.map((i) => (
              <div key={i.investigation_id} className="flex items-center gap-3 py-3">
                <div className="min-w-0 flex-1">
                  <Link href={`/investigations/${i.investigation_id}`} className="truncate text-sm font-medium text-text hover:text-accent">{i.title}</Link>
                  <div className="mt-0.5 text-xs text-dim">{i.playbook ? `→ ${i.playbook}` : "no playbook"}</div>
                </div>
                <SeverityBadge s={i.severity} />
                <VerdictBadge v={i.verdict} />
              </div>
            ))}
            {data.incidents.length === 0 && <p className="py-10 text-center text-sm text-dim">No open incidents.</p>}
          </div>
        </Card>

        <div className="space-y-4 lg:col-span-2">
          <SectionTitle>Response playbooks</SectionTitle>
          {data.playbooks.map((pb) => (
            <Card key={pb.id} className="overflow-hidden">
              <button onClick={() => setOpenPb(openPb === pb.id ? null : pb.id)}
                className="flex w-full items-center gap-3 p-4 text-left transition hover:bg-surface-2">
                <span className="flex h-9 w-9 items-center justify-center rounded-xl bg-accent/10 text-accent"><Icon.response className="h-5 w-5" /></span>
                <div className="min-w-0 flex-1">
                  <div className="truncate text-sm font-semibold text-text">{pb.name}</div>
                  <div className="mt-0.5 flex flex-wrap gap-1">
                    {pb.verdicts.map((v) => <span key={v} className="rounded border border-border bg-surface-2 px-1.5 py-0.5 text-[10px] text-dim">{v}</span>)}
                  </div>
                </div>
                <Icon.chevron className={`h-4 w-4 text-dim transition ${openPb === pb.id ? "rotate-90" : ""}`} />
              </button>
              {openPb === pb.id && (
                <ol className="animate-pop list-decimal space-y-2 border-t border-border px-6 py-4 pl-9 text-sm text-muted">
                  {pb.steps.map((s, i) => (
                    <li key={i}>
                      {s.action}
                      <span className="ml-1.5 inline-flex items-center gap-1">
                        <span className="rounded border border-border bg-surface-2 px-1 py-0.5 text-[10px] text-dim">{s.owner}</span>
                        {s.requires_approval && <span className="rounded border border-warning/30 bg-warning/10 px-1 py-0.5 text-[10px] text-warning">approval</span>}
                      </span>
                    </li>
                  ))}
                </ol>
              )}
            </Card>
          ))}
        </div>
      </div>
    </div>
  );
}
