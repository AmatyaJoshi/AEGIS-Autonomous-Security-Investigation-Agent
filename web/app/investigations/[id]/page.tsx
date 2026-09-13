"use client";
import { use, useState } from "react";
import useSWR from "swr";
import ReactMarkdown from "react-markdown";
import { api, fetcher, type Investigation } from "@/lib/api";
import { VerdictBadge } from "@/components/VerdictBadge";

const STATUS: Record<string, string> = {
  supported: "text-red-300",
  refuted: "text-green-300",
  inconclusive: "text-amber-300",
  open: "text-slate-400",
};

export default function InvestigationPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params);
  const { data, mutate } = useSWR<Investigation>(`/api/investigations/${id}`, fetcher);
  const [drawer, setDrawer] = useState<Record<string, unknown> | null>(null);

  if (!data) return <p className="text-slate-500">Loading…</p>;
  const st = data.state;

  async function act(action: string, override?: string) {
    const annotation = action === "annotate" ? window.prompt("Annotation") ?? undefined : undefined;
    await api.review(id, { analyst: "analyst", action, override_verdict: override, annotation });
    await mutate();
  }

  return (
    <div className="grid grid-cols-3 gap-6">
      <div className="col-span-2 space-y-6">
        <div>
          <div className="flex items-center gap-3">
            <h1 className="text-lg font-semibold">{data.title}</h1>
            <VerdictBadge v={data.verdict} />
            {data.gold_label && <span className="text-xs text-slate-500">gold: {data.gold_label}</span>}
          </div>
          <p className="text-slate-500 text-sm">
            confidence {data.confidence != null ? Math.round(data.confidence * 100) : "-"}% ·
            severity {data.severity} · techniques {data.techniques.join(", ") || "none"}
          </p>
        </div>

        <section>
          <h2 className="text-sm font-semibold text-sky-400 mb-2">Hypotheses</h2>
          {st.hypotheses.map((h) => (
            <div key={h.id} className="border border-slate-800 rounded p-3 mb-2">
              <div className="flex items-center gap-2">
                <span className={`text-xs ${h.is_benign ? "text-green-400" : "text-red-400"}`}>
                  {h.is_benign ? "benign" : "malicious"}
                </span>
                <span className={`text-xs ${STATUS[h.status] ?? ""}`}>{h.status}</span>
                <span className="text-sm">{h.statement}</span>
              </div>
              {h.reasoning && <p className="text-xs text-slate-400 mt-1">{h.reasoning}</p>}
              {[...h.evidence_for, ...h.evidence_against].slice(0, 4).map((e, i) => (
                <button
                  key={i}
                  onClick={() => setDrawer(e.fields)}
                  className="block text-left text-xs text-slate-500 hover:text-sky-300 mt-1"
                >
                  ▸ {e.summary} [E:{e.event_id.slice(0, 8)}]
                </button>
              ))}
            </div>
          ))}
        </section>

        <section>
          <h2 className="text-sm font-semibold text-sky-400 mb-2">Timeline</h2>
          <ol className="border-l border-slate-800 pl-4 space-y-2">
            {st.timeline.map((t, i) => (
              <li key={i} className="text-sm">
                <span className="text-slate-500 text-xs">{t.ts ?? "?"}</span>{" "}
                {t.technique && <span className="text-amber-400 text-xs">[{t.technique}]</span>} {t.description}
              </li>
            ))}
            {st.timeline.length === 0 && <li className="text-slate-600 text-sm">no timeline events</li>}
          </ol>
        </section>

        <section>
          <h2 className="text-sm font-semibold text-sky-400 mb-2">Report</h2>
          <article className="prose prose-invert prose-sm max-w-none border border-slate-800 rounded p-4">
            <ReactMarkdown>{data.report_md ?? "_no report_"}</ReactMarkdown>
          </article>
        </section>
      </div>

      <aside className="space-y-4">
        <div className="border border-slate-800 rounded p-3">
          <h3 className="text-sm font-semibold mb-2">Analyst action required</h3>
          {st.playbook ? (
            <div className="text-xs text-slate-400">
              <p className="font-medium text-slate-200">{String(st.playbook["name"])}</p>
              <ol className="list-decimal ml-4 mt-2 space-y-1">
                {((st.playbook["recommended_steps"] as { action: string }[]) ?? []).map((s, i) => (
                  <li key={i}>{s.action}</li>
                ))}
              </ol>
            </div>
          ) : (
            <p className="text-xs text-slate-500">No playbook selected.</p>
          )}
          <div className="flex flex-col gap-2 mt-3">
            <button onClick={() => act("approve")} className="px-3 py-1 rounded text-xs bg-green-700 hover:bg-green-600">
              Approve recommendation
            </button>
            <div className="flex gap-1">
              {["true_positive", "false_positive", "escalate"].map((v) => (
                <button key={v} onClick={() => act("override", v)} className="flex-1 px-2 py-1 rounded text-xs bg-slate-700 hover:bg-slate-600">
                  {v.split("_")[0]}
                </button>
              ))}
            </div>
            <button onClick={() => act("annotate")} className="px-3 py-1 rounded text-xs bg-slate-800 hover:bg-slate-700">
              Annotate
            </button>
          </div>
        </div>

        <div className="border border-slate-800 rounded p-3">
          <h3 className="text-sm font-semibold mb-2">Context</h3>
          <pre className="text-xs text-slate-400 overflow-auto">{JSON.stringify(st.context, null, 1)}</pre>
        </div>

        {data.reviews.length > 0 && (
          <div className="border border-slate-800 rounded p-3">
            <h3 className="text-sm font-semibold mb-2">Reviews</h3>
            {data.reviews.map((r, i) => (
              <p key={i} className="text-xs text-slate-400">
                {r.analyst}: {r.action} {r.override_verdict ?? ""} {r.annotation ?? ""}
              </p>
            ))}
          </div>
        )}
      </aside>

      {drawer && (
        <div className="fixed inset-0 bg-black/60 flex justify-end" onClick={() => setDrawer(null)}>
          <div className="w-[480px] bg-slate-950 border-l border-slate-800 p-4 overflow-auto" onClick={(e) => e.stopPropagation()}>
            <h3 className="text-sm font-semibold mb-2">Raw event</h3>
            <pre className="text-xs text-slate-300">{JSON.stringify(drawer, null, 2)}</pre>
          </div>
        </div>
      )}
    </div>
  );
}
