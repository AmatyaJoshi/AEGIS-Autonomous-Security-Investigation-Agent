"use client";
import Link from "next/link";
import useSWR from "swr";
import { fetcher, type Summary } from "@/lib/api";
import { VerdictBadge } from "@/components/VerdictBadge";

// Analyst overrides recorded here become gold labels feeding the §7 training datasets.
export default function LabelsPage() {
  const { data } = useSWR<Summary[]>("/api/queue?limit=200", fetcher, { refreshInterval: 8000 });
  return (
    <div>
      <h1 className="text-lg font-semibold mb-2">Labels</h1>
      <p className="text-sm text-slate-500 mb-4">
        Overrides and annotations become training labels for the triage and query models. Open an
        investigation to approve, override or annotate.
      </p>
      <table className="w-full text-sm">
        <thead className="text-slate-500 text-left">
          <tr className="border-b border-slate-800">
            <th className="py-2">Alert</th><th>AEGIS verdict</th><th>Confidence</th><th></th>
          </tr>
        </thead>
        <tbody>
          {(data ?? []).map((s) => (
            <tr key={s.investigation_id} className="border-b border-slate-900">
              <td className="py-2">{s.title || s.alert_id}</td>
              <td><VerdictBadge v={s.verdict} /></td>
              <td>{s.confidence != null ? `${Math.round(s.confidence * 100)}%` : "-"}</td>
              <td className="text-right">
                <Link href={`/investigations/${s.investigation_id}`} className="text-sky-300 hover:underline text-xs">
                  review →
                </Link>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
