"use client";
import { use, useState } from "react";
import Link from "next/link";
import useSWR from "swr";
import ReactMarkdown from "react-markdown";
import { api, fetcher, type Investigation } from "@/lib/api";
import { useAuth } from "@/components/auth";
import { Button, Card, Icon, SectionTitle, SeverityBadge, Spinner, VerdictBadge } from "@/components/ui";

const STATUS: Record<string, { cls: string; label: string }> = {
  supported: { cls: "text-danger", label: "Supported" },
  refuted: { cls: "text-success", label: "Refuted" },
  inconclusive: { cls: "text-warning", label: "Inconclusive" },
  open: { cls: "text-dim", label: "Open" },
};

export default function InvestigationPage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = use(params);
  const { has } = useAuth();
  const { data, mutate } = useSWR<Investigation>(`/api/investigations/${id}`, fetcher);
  const [drawer, setDrawer] = useState<Record<string, unknown> | null>(null);

  if (!data) return <Spinner />;
  const st = data.state;

  async function act(action: string, override?: string) {
    const annotation = action === "annotate" ? window.prompt("Annotation for this alert") ?? undefined : undefined;
    if (action === "annotate" && !annotation) return;
    await api.review(id, { analyst: "analyst", action, override_verdict: override, annotation });
    await mutate();
  }

  return (
    <div className="animate-rise">
      <Link href="/" className="mb-4 inline-flex items-center gap-1.5 text-sm text-dim hover:text-text">
        <Icon.chevron className="h-4 w-4 rotate-180" /> Queue
      </Link>

      {/* header */}
      <Card className="mb-6 p-5">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div className="min-w-0">
            <div className="flex items-center gap-3">
              <h1 className="text-xl font-semibold tracking-tight">{data.title}</h1>
              <VerdictBadge v={data.verdict} size="md" />
            </div>
            <div className="mt-1 font-mono text-xs text-dim">{data.alert_id}</div>
          </div>
          <div className="flex flex-wrap items-center gap-4 text-sm">
            <Stat label="Confidence" value={data.confidence != null ? `${Math.round(data.confidence * 100)}%` : "—"} />
            <div className="flex flex-col">
              <span className="text-xs uppercase tracking-wider text-dim">Severity</span>
              <span className="mt-1"><SeverityBadge s={data.severity} /></span>
            </div>
            <Stat label="Techniques" value={data.techniques.join(", ") || "none"} />
            {data.gold_label && <Stat label="Gold label" value={data.gold_label} />}
          </div>
        </div>
      </Card>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
        <div className="space-y-6 lg:col-span-2">
          {/* hypotheses */}
          <section>
            <SectionTitle>Competing hypotheses</SectionTitle>
            <div className="space-y-3">
              {st.hypotheses.map((h) => {
                const stt = STATUS[h.status] ?? STATUS.open;
                return (
                  <Card key={h.id} className="p-4">
                    <div className="flex flex-wrap items-center gap-2">
                      <span className={`rounded-md border px-1.5 py-0.5 text-[11px] font-medium uppercase tracking-wide ${
                        h.is_benign ? "border-success/30 bg-success/10 text-success" : "border-danger/30 bg-danger/10 text-danger"
                      }`}>
                        {h.is_benign ? "Benign" : "Malicious"}
                      </span>
                      <span className={`text-xs font-medium ${stt.cls}`}>{stt.label}</span>
                      {h.attack_techniques.map((t) => (
                        <span key={t} className="rounded border border-border bg-surface-2 px-1.5 py-0.5 font-mono text-[10px] text-muted">{t}</span>
                      ))}
                    </div>
                    <p className="mt-2 text-sm font-medium text-text">{h.statement}</p>
                    {h.reasoning && <p className="mt-1 text-sm leading-relaxed text-muted">{h.reasoning}</p>}
                    {[...h.evidence_for, ...h.evidence_against].slice(0, 5).map((e, i) => (
                      <button
                        key={i}
                        onClick={() => setDrawer(e.fields)}
                        className="mt-1.5 flex w-full items-center gap-2 rounded-md px-2 py-1 text-left text-xs text-muted transition hover:bg-surface-2 hover:text-accent"
                      >
                        <Icon.chevron className="h-3 w-3 shrink-0" />
                        <span className="truncate">{e.summary}</span>
                        <span className="ml-auto shrink-0 rounded bg-surface-2 px-1.5 py-0.5 font-mono text-[10px] text-dim">E:{e.event_id.slice(0, 8)}</span>
                      </button>
                    ))}
                  </Card>
                );
              })}
            </div>
          </section>

          {/* timeline */}
          <section>
            <SectionTitle>Reconstructed timeline</SectionTitle>
            <Card className="p-5">
              <ol className="relative space-y-4 border-l border-border pl-5">
                {st.timeline.map((t, i) => (
                  <li key={i} className="relative">
                    <span className="absolute -left-[1.42rem] top-1 h-2.5 w-2.5 rounded-full border-2 border-surface bg-accent" />
                    <div className="flex flex-wrap items-center gap-2 text-xs text-dim">
                      <span className="font-mono">{t.ts ?? "—"}</span>
                      {t.technique && <span className="rounded border border-border bg-surface-2 px-1.5 py-0.5 font-mono text-[10px] text-warning">{t.technique}</span>}
                    </div>
                    <p className="mt-0.5 text-sm text-text">{t.description}</p>
                  </li>
                ))}
                {st.timeline.length === 0 && <li className="text-sm text-dim">No timeline events.</li>}
              </ol>
            </Card>
          </section>

          {/* report */}
          <section>
            <SectionTitle right={<span className="text-xs text-success">✓ every claim cited</span>}>
              Incident report
            </SectionTitle>
            <Card className="report p-6">
              <ReactMarkdown>{data.report_md ?? "_no report_"}</ReactMarkdown>
            </Card>
          </section>
        </div>

        {/* aside */}
        <aside className="space-y-5">
          <Card className="p-4">
            <div className="mb-3 flex items-center gap-2">
              <Icon.shieldAlert className="h-4 w-4 text-warning" />
              <h3 className="text-sm font-semibold">Analyst action required</h3>
            </div>
            {st.playbook ? (
              <div className="text-sm">
                <p className="font-medium text-text">{String(st.playbook["name"])}</p>
                <ol className="mt-2 list-decimal space-y-1.5 pl-4 text-xs text-muted">
                  {((st.playbook["recommended_steps"] as { action: string }[]) ?? []).slice(0, 6).map((s, i) => (
                    <li key={i}>{s.action}</li>
                  ))}
                </ol>
              </div>
            ) : (
              <p className="text-sm text-dim">No playbook selected.</p>
            )}
            {has("review") ? (
            <div className="mt-4 space-y-2">
              <Button variant="success" className="w-full" onClick={() => act("approve")}>
                Approve recommendation
              </Button>
              <div className="grid grid-cols-3 gap-1.5">
                {[["true_positive", "TP"], ["false_positive", "FP"], ["escalate", "Esc"]].map(([v, l]) => (
                  <Button key={v} variant="ghost" onClick={() => act("override", v)}>{l}</Button>
                ))}
              </div>
              <Button variant="ghost" className="w-full" onClick={() => act("annotate")}>Annotate</Button>
            </div>
            ) : (
              <p className="mt-4 rounded-lg border border-border bg-surface-2 px-3 py-2 text-xs text-dim">Read-only role — reviewing requires an analyst account.</p>
            )}
            <p className="mt-3 text-[11px] leading-relaxed text-dim">
              Overrides become training labels. AEGIS recommends; a human decides and acts.
            </p>
          </Card>

          <Card className="p-4">
            <h3 className="mb-2 text-sm font-semibold">Context</h3>
            <ContextView ctx={st.context} />
          </Card>

          {data.reviews.length > 0 && (
            <Card className="p-4">
              <h3 className="mb-2 text-sm font-semibold">Review history</h3>
              {data.reviews.map((r, i) => (
                <div key={i} className="border-t border-border py-2 text-xs text-muted first:border-0 first:pt-0">
                  <span className="font-medium text-text">{r.analyst}</span> · {r.action}{" "}
                  {r.override_verdict && <span className="text-accent">→ {r.override_verdict}</span>}
                  {r.annotation && <p className="mt-0.5 text-dim">{r.annotation}</p>}
                </div>
              ))}
            </Card>
          )}
        </aside>
      </div>

      {/* evidence drawer */}
      {drawer && (
        <div className="fixed inset-0 z-40 flex justify-end bg-black/50 backdrop-blur-sm" onClick={() => setDrawer(null)}>
          <div className="h-full w-full max-w-lg overflow-auto border-l border-border bg-surface p-6 shadow-pop animate-rise" onClick={(e) => e.stopPropagation()}>
            <div className="mb-3 flex items-center justify-between">
              <h3 className="text-sm font-semibold">Raw event</h3>
              <button onClick={() => setDrawer(null)} className="text-dim hover:text-text">✕</button>
            </div>
            <pre className="overflow-auto rounded-lg border border-border bg-surface-2 p-4 font-mono text-xs leading-relaxed text-muted">
              {JSON.stringify(drawer, null, 2)}
            </pre>
          </div>
        </div>
      )}
    </div>
  );
}

function Stat({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex flex-col">
      <span className="text-xs uppercase tracking-wider text-dim">{label}</span>
      <span className="mt-1 font-medium tabular-nums text-text">{value}</span>
    </div>
  );
}

function ContextView({ ctx }: { ctx: Record<string, unknown> }) {
  const asset = (ctx.asset ?? {}) as Record<string, unknown>;
  const identity = (ctx.identity ?? {}) as Record<string, unknown>;
  const ti = (ctx.ti_hits ?? []) as { observable: string; verdict: string }[];
  const rows: [string, string][] = [
    ["Host", String(asset.host ?? "—")],
    ["Criticality", String(asset.criticality ?? "—")],
    ["Owner", String(asset.owner ?? "—")],
    ["User", String(identity.user ?? "—")],
    ["Privileged", identity.privileged ? "yes" : "no"],
    ["Known account", identity.known ? "yes" : "no"],
    ["Off-hours", ctx.off_hours ? "yes" : "no"],
  ];
  return (
    <div className="space-y-1.5 text-sm">
      {rows.map(([k, v]) => (
        <div key={k} className="flex justify-between gap-3">
          <span className="text-dim">{k}</span>
          <span className="truncate font-medium text-text">{v}</span>
        </div>
      ))}
      {ti.length > 0 && (
        <div className="mt-2 border-t border-border pt-2">
          <span className="text-dim">Threat intel</span>
          {ti.map((h, i) => (
            <div key={i} className="mt-1 flex justify-between text-xs">
              <span className="truncate font-mono text-muted">{h.observable}</span>
              <span className="text-danger">{h.verdict}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
