"use client";
import { Fragment, useState } from "react";
import useSWR from "swr";
import { fetcher, type LogSearch } from "@/lib/api";
import { Card, Icon, PageHeader, SectionTitle, Spinner } from "@/components/ui";

const ACTION_TONE: Record<string, string> = {
  process_created: "text-accent", network_connection: "text-medium", logged_in: "text-success",
  logon_failed: "text-danger", registry_value_set: "text-warning", dns_query: "text-low",
};

export default function LogsPage() {
  const [q, setQ] = useState("");
  const [submitted, setSubmitted] = useState("");
  const [host, setHost] = useState("");
  const [action, setAction] = useState("");
  const params = new URLSearchParams();
  if (submitted) params.set("q", submitted);
  if (host) params.set("host", host);
  if (action) params.set("action", action);
  params.set("limit", "120");
  const { data, isLoading } = useSWR<LogSearch>(`/api/logs/search?${params}`, fetcher);
  const [open, setOpen] = useState<string | null>(null);

  return (
    <div className="animate-rise">
      <PageHeader
        title="Log Collection & Analysis"
        subtitle="Aggregated telemetry across services — correlate signals for intrusion detection, root-cause and attribution"
      />

      <Card className="mb-5 p-4">
        <form onSubmit={(e) => { e.preventDefault(); setSubmitted(q); }} className="flex flex-wrap items-center gap-2">
          <div className="relative min-w-[240px] flex-1">
            <Icon.search className="pointer-events-none absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-dim" />
            <input value={q} onChange={(e) => setQ(e.target.value)}
              placeholder="Search command lines, processes, users, messages…"
              className="w-full rounded-full border border-border bg-surface-2 py-2.5 pl-9 pr-3 text-sm text-text placeholder:text-dim focus:border-accent focus:outline-none focus:ring-2 focus:ring-ring/25" />
          </div>
          <input value={host} onChange={(e) => setHost(e.target.value.toUpperCase())} placeholder="host"
            className="w-28 rounded-full border border-border bg-surface-2 px-3 py-2.5 text-sm focus:border-accent focus:outline-none" />
          <button type="submit" className="rounded-full bg-accent px-4 py-2.5 text-sm font-medium text-white transition hover:bg-accent-hover active:scale-95">Search</button>
        </form>
        {(data?.facets.actions.length ?? 0) > 0 && (
          <div className="mt-3 flex flex-wrap items-center gap-1.5">
            <span className="text-xs text-dim">Actions:</span>
            {data!.facets.actions.map((a) => (
              <button key={a.key} onClick={() => setAction(action === a.key ? "" : a.key)}
                className={`rounded-full border px-2.5 py-1 text-xs transition ${action === a.key ? "border-accent bg-accent/10 text-accent" : "border-border bg-surface-2 text-muted hover:text-text"}`}>
                {a.key} <span className="text-dim">·{a.count}</span>
              </button>
            ))}
          </div>
        )}
      </Card>

      <Card className="overflow-hidden">
        <div className="flex items-center justify-between border-b border-border px-5 py-3">
          <SectionTitle>{data ? `${data.count} events` : "Events"}</SectionTitle>
        </div>
        {isLoading ? <Spinner /> : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border text-left text-xs uppercase tracking-wider text-dim">
                  <th className="px-5 py-2.5 font-medium">Time</th>
                  <th className="px-3 py-2.5 font-medium">Host</th>
                  <th className="px-3 py-2.5 font-medium">User</th>
                  <th className="px-3 py-2.5 font-medium">Action</th>
                  <th className="px-3 py-2.5 font-medium">Detail</th>
                </tr>
              </thead>
              <tbody>
                {(data?.rows ?? []).map((r) => (
                  <Fragment key={r.event_id}>
                    <tr onClick={() => setOpen(open === r.event_id ? null : r.event_id)}
                      className="cursor-pointer border-b border-border/60 transition last:border-0 hover:bg-surface-2">
                      <td className="whitespace-nowrap px-5 py-2.5 font-mono text-[11px] text-dim">{fmtTs(r["@timestamp"])}</td>
                      <td className="px-3 py-2.5 font-medium text-text">{r.host_name ?? "—"}</td>
                      <td className="px-3 py-2.5 text-muted">{r.user_name ?? "—"}</td>
                      <td className={`px-3 py-2.5 font-medium ${ACTION_TONE[r.event_action ?? ""] ?? "text-muted"}`}>{r.event_action ?? "—"}</td>
                      <td className="max-w-md truncate px-3 py-2.5 font-mono text-xs text-muted">
                        {r.process_command_line || r.message || r.process_name || "—"}
                      </td>
                    </tr>
                    {open === r.event_id && (
                      <tr>
                        <td colSpan={5} className="bg-surface-2 px-5 py-3">
                          <pre className="overflow-x-auto whitespace-pre-wrap break-all font-mono text-[11px] leading-relaxed text-muted">{JSON.stringify(r, null, 2)}</pre>
                        </td>
                      </tr>
                    )}
                  </Fragment>
                ))}
              </tbody>
            </table>
            {data && data.count === 0 && <p className="py-14 text-center text-sm text-dim">No matching events.</p>}
          </div>
        )}
      </Card>
    </div>
  );
}

function fmtTs(t: string | null) {
  if (!t) return "—";
  const d = new Date(t);
  return isNaN(+d) ? String(t).slice(0, 19) : d.toISOString().replace("T", " ").slice(0, 19);
}
