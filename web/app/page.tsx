"use client";
import { useState } from "react";
import Link from "next/link";
import useSWR from "swr";
import { api, fetcher, type Summary } from "@/lib/api";
import { VerdictBadge } from "@/components/VerdictBadge";

const FILTERS = ["all", "true_positive", "false_positive", "escalate"];

export default function QueuePage() {
  const [filter, setFilter] = useState("all");
  const url = filter === "all" ? "/api/queue" : `/api/queue?verdict=${filter}`;
  const { data, mutate, isLoading } = useSWR<Summary[]>(url, fetcher, { refreshInterval: 5000 });
  const [busy, setBusy] = useState(false);

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
    <div>
      <div className="flex items-center gap-3 mb-4">
        <h1 className="text-lg font-semibold">Investigation queue</h1>
        <div className="ml-auto flex gap-2">
          {FILTERS.map((f) => (
            <button
              key={f}
              onClick={() => setFilter(f)}
              className={`px-2 py-1 rounded text-xs border ${
                filter === f ? "border-sky-500 text-sky-300" : "border-slate-700 text-slate-400"
              }`}
            >
              {f}
            </button>
          ))}
          <button
            onClick={runBatch}
            disabled={busy}
            className="px-3 py-1 rounded text-xs bg-sky-600 hover:bg-sky-500 disabled:opacity-50"
          >
            {busy ? "Running…" : "Investigate 15 alerts"}
          </button>
        </div>
      </div>

      {isLoading && <p className="text-slate-500">Loading…</p>}
      <table className="w-full text-sm">
        <thead className="text-slate-500 text-left">
          <tr className="border-b border-slate-800">
            <th className="py-2">Alert</th>
            <th>Verdict</th>
            <th>Conf</th>
            <th>Severity</th>
            <th>Techniques</th>
            <th>Flags</th>
            <th>Time</th>
          </tr>
        </thead>
        <tbody>
          {(data ?? []).map((s) => (
            <tr key={s.investigation_id} className="border-b border-slate-900 hover:bg-slate-900/50">
              <td className="py-2">
                <Link href={`/investigations/${s.investigation_id}`} className="text-sky-300 hover:underline">
                  {s.title || s.alert_id}
                </Link>
              </td>
              <td><VerdictBadge v={s.verdict} /></td>
              <td>{s.confidence != null ? `${Math.round(s.confidence * 100)}%` : "-"}</td>
              <td className="text-slate-400">{s.severity}</td>
              <td className="text-slate-400">{s.techniques.slice(0, 3).join(", ")}</td>
              <td>
                {s.fast_pathed && <span className="text-xs text-slate-500 mr-1">fast</span>}
                {s.injection_flagged && <span className="text-xs text-amber-400">injection</span>}
              </td>
              <td className="text-slate-500 text-xs">{s.seconds.toFixed(2)}s</td>
            </tr>
          ))}
        </tbody>
      </table>
      {data && data.length === 0 && (
        <p className="text-slate-500 mt-6">Queue empty — click “Investigate 15 alerts”.</p>
      )}
    </div>
  );
}
