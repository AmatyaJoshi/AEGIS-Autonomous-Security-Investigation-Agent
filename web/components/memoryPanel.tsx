"use client";
import useSWR from "swr";
import { fetcher, type MemoryData } from "@/lib/api";
import { Card, SectionTitle, StatCard } from "@/components/ui";

/** Memory panel (Phase 1): what AEGIS learned, where it is stored, and how it feeds triage. */
export function MemoryPanel() {
  const { data, error } = useSWR<MemoryData>("/api/memory", fetcher, { refreshInterval: 10000 });
  if (error) {
    return (
      <Card className="p-5">
        <SectionTitle>Case memory</SectionTitle>
        <p className="text-sm text-dim">Memory service unavailable.</p>
      </Card>
    );
  }
  if (!data) {
    return (
      <Card className="p-5">
        <SectionTitle>Case memory</SectionTitle>
        <div className="space-y-2">
          {[0, 1, 2].map((i) => (
            <div key={i} className="h-3 w-full animate-pulse rounded bg-border" />
          ))}
        </div>
      </Card>
    );
  }
  const pct = (v: number) => `${Math.round(v * 100)}%`;
  const techs = data.techniques.filter((t) => t.n > 0);
  const pulse = data.backend === "pulse";
  const live = data.priors_source === "pulse";

  return (
    <div className="animate-rise">
      <div className="mb-3 flex flex-wrap items-center justify-between gap-2">
        <div>
          <h2 className="text-lg font-semibold tracking-tight">Case memory</h2>
          <p className="text-sm text-muted">
            Priors learned from past verdicts and analyst decisions, blended into triage at weight n/(n+20)
          </p>
        </div>
        <MemoryBadge backend={data.backend} source={data.priors_source} />
      </div>

      <div className="mb-4 grid grid-cols-2 gap-3 lg:grid-cols-4">
        <StatCard label="Cases remembered" value={String(data.cases)} />
        <StatCard label="Analyst decisions" value={String(data.feedback)} />
        <StatCard
          label="Analyst override rate"
          value={pct(data.analyst_override_rate)}
          sub="of reviewed cases"
          tone={data.analyst_override_rate > 0.25 ? "text-warning" : undefined}
        />
        <StatCard
          label={pulse ? "Pulse calls today" : "Backend"}
          value={pulse ? `${data.pulse_calls ?? 0} / ${data.pulse_calls_per_day ?? "—"}` : "local SQLite"}
          sub={pulse ? (live ? "priors read from Pulse" : "priors from local copy") : "no external calls"}
        />
      </div>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-5">
        <Card className="p-5 lg:col-span-3">
          <SectionTitle right={<span className="text-xs text-dim">true-positive rate · n cases</span>}>
            TP rate by technique
          </SectionTitle>
          {techs.length === 0 ? (
            <p className="text-sm text-dim">No cases yet. Run an investigation batch to populate memory.</p>
          ) : (
            <div className="space-y-2.5" role="table" aria-label="True-positive rate by ATT&CK technique">
              {techs.map((t) => (
                <div key={t.key} role="row" className="group flex items-center gap-3 text-sm" title={`${t.key}: ${pct(t.tp_rate)} TP over ${t.n} cases · escalate ${pct(t.escalate_rate)} · override ${pct(t.analyst_override_rate)}`}>
                  <span role="cell" className="w-24 shrink-0 font-mono text-xs text-muted">{t.key}</span>
                  <div role="cell" className="relative h-2.5 flex-1 overflow-hidden rounded-full bg-border">
                    <div
                      className="h-full rounded-r-[4px] bg-accent transition-[width] duration-500 ease-spring group-hover:brightness-110"
                      style={{ width: `${Math.max(2, Math.round(t.tp_rate * 100))}%` }}
                    />
                  </div>
                  <span role="cell" className="w-12 text-right tabular-nums text-text">{pct(t.tp_rate)}</span>
                  <span role="cell" className="w-14 text-right tabular-nums text-xs text-dim">n={t.n}</span>
                </div>
              ))}
            </div>
          )}
        </Card>

        <Card className="p-5 lg:col-span-2">
          <SectionTitle right={<span className="text-xs text-dim">{data.analytics.source === "pulse" ? "Pulse analytics" : "local"}</span>}>
            Analytics
          </SectionTitle>
          <p className="text-sm font-medium text-text">{data.analytics.question}</p>
          <p className="mt-2 text-sm leading-relaxed text-muted">{data.analytics.answer}</p>
          <p className="mt-3 text-[11px] text-dim">
            Cached {new Date(data.analytics.cached_at).toLocaleString()} · one call per day
          </p>
          {data.last_error && (
            <p className="mt-3 rounded-lg border border-warning/25 bg-warning/10 px-3 py-2 text-xs text-warning">
              Pulse unreachable, local copy in use: {data.last_error}
            </p>
          )}
        </Card>
      </div>

      <p className="mt-4 text-xs text-dim">
        Pulse receives metadata only (technique ids, source, verdict, confidence, counts, hashed tenant). Never log
        events, hostnames, usernames, IPs, alert text or report bodies. See SECURITY.md.
      </p>
    </div>
  );
}

export function MemoryBadge({ backend, source }: { backend: string; source: string }) {
  const live = backend === "pulse" && source === "pulse";
  const cls = live
    ? "border-success/25 bg-success/10 text-success"
    : "border-border bg-surface-2 text-muted";
  return (
    <span className={`inline-flex items-center gap-1.5 rounded-full border px-2.5 py-1 text-xs font-medium ${cls}`}>
      <span className={`h-1.5 w-1.5 rounded-full ${live ? "bg-success" : "bg-dim"}`} />
      memory: {backend === "pulse" ? (live ? "pulse" : "pulse (local copy)") : "local"}
    </span>
  );
}
