"use client";
import { useMemo, useState } from "react";
import Link from "next/link";
import useSWR from "swr";
import { api, fetcher, type Summary } from "@/lib/api";
import { Button, Card, Icon, SeverityBadge, Spinner, VerdictBadge } from "@/components/ui";

const FILTERS = [
  { key: "all", label: "All" },
  { key: "true_positive", label: "True positive" },
  { key: "escalate", label: "Escalate" },
  { key: "false_positive", label: "False positive" },
];

export default function QueuePage() {
  const [filter, setFilter] = useState("all");
  const [q, setQ] = useState("");
  const url = filter === "all" ? "/api/queue" : `/api/queue?verdict=${filter}`;
  const { data, mutate, isLoading } = useSWR<Summary[]>(url, fetcher, { refreshInterval: 5000 });
  const [busy, setBusy] = useState(false);

  const rows = useMemo(
    () => (data ?? []).filter((s) => (s.title + s.alert_id).toLowerCase().includes(q.toLowerCase())),
    [data, q],
  );

  const counts = useMemo(() => {
    const c = { true_positive: 0, false_positive: 0, escalate: 0 } as Record<string, number>;
    (data ?? []).forEach((s) => s.verdict && (c[s.verdict] = (c[s.verdict] ?? 0) + 1));
    return c;
  }, [data]);

  async function runBatch() {
    setBusy(true);
    try {
      await api.investigate(15);
      await mutate();
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="animate-in">
      <div className="mb-6 flex flex-wrap items-end justify-between gap-3">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">Investigation queue</h1>
          <p className="mt-1 text-sm text-muted">
            Autonomous verdicts with calibrated confidence — {data?.length ?? 0} investigations
          </p>
        </div>
        <Button onClick={runBatch} disabled={busy}>
          <Icon.bolt className="h-4 w-4" />
          {busy ? "Investigating…" : "Investigate 15 alerts"}
        </Button>
      </div>

      {/* summary strip */}
      <div className="mb-5 grid grid-cols-2 gap-3 sm:grid-cols-4">
        {[
          { label: "Total", value: data?.length ?? 0, tone: "text-text" },
          { label: "True positives", value: counts.true_positive ?? 0, tone: "text-danger" },
          { label: "Escalations", value: counts.escalate ?? 0, tone: "text-warning" },
          { label: "Suppressed FPs", value: counts.false_positive ?? 0, tone: "text-success" },
        ].map((k) => (
          <Card key={k.label} className="px-4 py-3">
            <div className="text-xs font-medium uppercase tracking-wider text-dim">{k.label}</div>
            <div className={`mt-1 text-xl font-semibold tabular-nums ${k.tone}`}>{k.value}</div>
          </Card>
        ))}
      </div>

      {/* controls */}
      <div className="mb-4 flex flex-wrap items-center gap-2">
        <div className="flex rounded-lg border border-border bg-surface p-0.5">
          {FILTERS.map((f) => (
            <button
              key={f.key}
              onClick={() => setFilter(f.key)}
              className={`rounded-md px-3 py-1.5 text-sm font-medium transition ${
                filter === f.key ? "bg-accent text-white shadow-card" : "text-muted hover:text-text"
              }`}
            >
              {f.label}
            </button>
          ))}
        </div>
        <div className="relative ml-auto">
          <Icon.search className="pointer-events-none absolute left-2.5 top-1/2 h-4 w-4 -translate-y-1/2 text-dim" />
          <input
            value={q}
            onChange={(e) => setQ(e.target.value)}
            placeholder="Search alerts…"
            className="w-56 rounded-lg border border-border bg-surface py-1.5 pl-8 pr-3 text-sm text-text placeholder:text-dim focus:border-accent focus:outline-none focus:ring-2 focus:ring-ring/30"
          />
        </div>
      </div>

      <Card className="overflow-hidden">
        {isLoading ? (
          <Spinner />
        ) : rows.length === 0 ? (
          <div className="py-16 text-center text-sm text-dim">
            No investigations. Click <span className="text-text">“Investigate 15 alerts”</span> to populate the queue.
          </div>
        ) : (
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border text-left text-xs uppercase tracking-wider text-dim">
                <th className="px-5 py-3 font-medium">Alert</th>
                <th className="px-3 py-3 font-medium">Verdict</th>
                <th className="px-3 py-3 font-medium">Confidence</th>
                <th className="px-3 py-3 font-medium">Severity</th>
                <th className="px-3 py-3 font-medium">Techniques</th>
                <th className="px-3 py-3 font-medium">Flags</th>
                <th className="px-3 py-3 font-medium text-right">Latency</th>
                <th className="px-3 py-3" />
              </tr>
            </thead>
            <tbody>
              {rows.map((s) => (
                <tr key={s.investigation_id} className="group border-b border-border/60 transition last:border-0 hover:bg-surface-2">
                  <td className="px-5 py-3.5">
                    <Link href={`/investigations/${s.investigation_id}`} className="font-medium text-text hover:text-accent">
                      {s.title || s.alert_id}
                    </Link>
                    <div className="mt-0.5 font-mono text-[11px] text-dim">{s.alert_id}</div>
                  </td>
                  <td className="px-3 py-3.5"><VerdictBadge v={s.verdict} /></td>
                  <td className="px-3 py-3.5">
                    <Confidence value={s.confidence} verdict={s.verdict} />
                  </td>
                  <td className="px-3 py-3.5"><SeverityBadge s={s.severity} /></td>
                  <td className="px-3 py-3.5 text-muted">{s.techniques.slice(0, 3).join(", ") || "—"}</td>
                  <td className="px-3 py-3.5">
                    <div className="flex gap-1.5">
                      {s.fast_pathed && <span className="rounded border border-border bg-surface-2 px-1.5 py-0.5 text-[10px] uppercase tracking-wide text-dim">Fast</span>}
                      {s.injection_flagged && <span className="rounded border border-warning/30 bg-warning/10 px-1.5 py-0.5 text-[10px] uppercase tracking-wide text-warning">Injection</span>}
                    </div>
                  </td>
                  <td className="px-3 py-3.5 text-right font-mono text-xs text-dim">{s.seconds.toFixed(2)}s</td>
                  <td className="px-3 py-3.5 pr-5 text-right">
                    <Link href={`/investigations/${s.investigation_id}`} className="text-dim opacity-0 transition group-hover:opacity-100">
                      <Icon.chevron className="ml-auto h-4 w-4" />
                    </Link>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </Card>
    </div>
  );
}

function Confidence({ value, verdict }: { value: number | null; verdict: string | null }) {
  if (value == null) return <span className="text-dim">—</span>;
  const pct = Math.round(value * 100);
  const tone = verdict === "false_positive" ? "bg-success" : verdict === "escalate" ? "bg-warning" : "bg-danger";
  return (
    <div className="flex items-center gap-2">
      <div className="h-1.5 w-16 overflow-hidden rounded-full bg-border">
        <div className={`h-full ${tone}`} style={{ width: `${pct}%` }} />
      </div>
      <span className="tabular-nums text-xs text-muted">{pct}%</span>
    </div>
  );
}
