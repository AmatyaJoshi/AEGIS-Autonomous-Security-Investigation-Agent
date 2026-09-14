"use client";
import Link from "next/link";
import useSWR from "swr";
import { fetcher, type Summary } from "@/lib/api";
import { Card, Icon, Spinner, VerdictBadge } from "@/components/ui";

// Analyst overrides recorded here become gold labels feeding the training datasets (SPEC §7).
export default function LabelsPage() {
  const { data, isLoading } = useSWR<Summary[]>("/api/queue?limit=200", fetcher, { refreshInterval: 8000 });

  return (
    <div className="animate-rise">
      <div className="mb-6">
        <h1 className="text-2xl font-semibold tracking-tight">Labels</h1>
        <p className="mt-1 max-w-2xl text-sm text-muted">
          Approve, override or annotate an investigation to record an analyst label. Overrides feed
          the triage and query-generation training datasets — the human-in-the-loop closes the loop.
        </p>
      </div>

      <Card className="overflow-hidden">
        {isLoading ? (
          <Spinner />
        ) : (
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border text-left text-xs uppercase tracking-wider text-dim">
                <th className="px-5 py-3 font-medium">Alert</th>
                <th className="px-3 py-3 font-medium">AEGIS verdict</th>
                <th className="px-3 py-3 font-medium">Confidence</th>
                <th className="px-3 py-3 font-medium text-right" />
              </tr>
            </thead>
            <tbody>
              {(data ?? []).map((s) => (
                <tr key={s.investigation_id} className="group border-b border-border/60 transition last:border-0 hover:bg-surface-2">
                  <td className="px-5 py-3.5">
                    <div className="font-medium text-text">{s.title || s.alert_id}</div>
                    <div className="mt-0.5 font-mono text-[11px] text-dim">{s.alert_id}</div>
                  </td>
                  <td className="px-3 py-3.5"><VerdictBadge v={s.verdict} /></td>
                  <td className="px-3 py-3.5 tabular-nums text-muted">
                    {s.confidence != null ? `${Math.round(s.confidence * 100)}%` : "—"}
                  </td>
                  <td className="px-3 py-3.5 pr-5 text-right">
                    <Link
                      href={`/investigations/${s.investigation_id}`}
                      className="inline-flex items-center gap-1 text-xs font-medium text-accent hover:underline"
                    >
                      Review <Icon.chevron className="h-3.5 w-3.5" />
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
