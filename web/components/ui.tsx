import type { ReactNode } from "react";

/* ------------------------------------------------------------------ icons (inline) */
const svg = (path: ReactNode) => (p: { className?: string }) => (
  <svg viewBox="0 0 24 24" fill="none" className={p.className} aria-hidden strokeLinecap="round" strokeLinejoin="round">
    {path}
  </svg>
);

export const Icon = {
  shield: svg(<><path d="M12 2 4 5v6c0 5 3.4 8.5 8 11 4.6-2.5 8-6 8-11V5l-8-3Z" fill="currentColor" opacity=".14" /><path d="M12 2 4 5v6c0 5 3.4 8.5 8 11 4.6-2.5 8-6 8-11V5l-8-3Z" stroke="currentColor" strokeWidth="1.6" /><path d="m9 12 2 2 4-4.5" stroke="currentColor" strokeWidth="1.9" /></>),
  monitor: svg(<><path d="M3 12h3l2 5 4-12 2 7h3l2-2" stroke="currentColor" strokeWidth="1.7" /></>),
  queue: svg(<><rect x="3" y="4.5" width="18" height="3.6" rx="1.3" stroke="currentColor" strokeWidth="1.6" /><rect x="3" y="10.2" width="18" height="3.6" rx="1.3" stroke="currentColor" strokeWidth="1.6" /><rect x="3" y="15.9" width="18" height="3.6" rx="1.3" stroke="currentColor" strokeWidth="1.6" /></>),
  logs: svg(<><rect x="4" y="3" width="16" height="18" rx="2.4" stroke="currentColor" strokeWidth="1.6" /><path d="M8 8h8M8 12h8M8 16h5" stroke="currentColor" strokeWidth="1.6" /></>),
  radar: svg(<><circle cx="12" cy="12" r="8.5" stroke="currentColor" strokeWidth="1.5" opacity=".5" /><circle cx="12" cy="12" r="4.5" stroke="currentColor" strokeWidth="1.5" opacity=".7" /><path d="M12 12 19 6" stroke="currentColor" strokeWidth="1.7" /><circle cx="12" cy="12" r="1.4" fill="currentColor" /></>),
  response: svg(<><path d="M12 2 4 5v6c0 5 3.4 8.5 8 11 4.6-2.5 8-6 8-11V5l-8-3Z" stroke="currentColor" strokeWidth="1.6" /><path d="M12 8v4M12 15.4v.2" stroke="currentColor" strokeWidth="1.9" /></>),
  shieldAlert: svg(<><path d="M12 2 4 5v6c0 5 3.4 8.5 8 11 4.6-2.5 8-6 8-11V5l-8-3Z" stroke="currentColor" strokeWidth="1.6" /><path d="M12 8v4M12 15.4v.2" stroke="currentColor" strokeWidth="1.9" /></>),
  automation: svg(<><circle cx="12" cy="12" r="3" stroke="currentColor" strokeWidth="1.6" /><path d="M12 2v3M12 19v3M2 12h3M19 12h3M5 5l2 2M17 17l2 2M19 5l-2 2M7 17l-2 2" stroke="currentColor" strokeWidth="1.5" /></>),
  tag: svg(<><path d="M3 12V4h8l10 10-8 8L3 12Z" stroke="currentColor" strokeWidth="1.6" /><circle cx="7.5" cy="7.5" r="1.4" fill="currentColor" /></>),
  chart: svg(<><path d="M4 20V10M10 20V4M16 20v-7M22 20H2" stroke="currentColor" strokeWidth="1.7" /></>),
  sun: svg(<><circle cx="12" cy="12" r="4" stroke="currentColor" strokeWidth="1.7" /><path d="M12 2v2M12 20v2M4 12H2M22 12h-2M5 5 3.5 3.5M20.5 20.5 19 19M19 5l1.5-1.5M3.5 20.5 5 19" stroke="currentColor" strokeWidth="1.7" /></>),
  moon: svg(<><path d="M21 12.8A8.5 8.5 0 1 1 11.2 3a6.5 6.5 0 0 0 9.8 9.8Z" stroke="currentColor" strokeWidth="1.7" /></>),
  bolt: svg(<><path d="M13 2 4 14h6l-1 8 9-12h-6l1-8Z" stroke="currentColor" strokeWidth="1.6" /></>),
  chevron: svg(<path d="m9 6 6 6-6 6" stroke="currentColor" strokeWidth="1.9" />),
  search: svg(<><circle cx="11" cy="11" r="7" stroke="currentColor" strokeWidth="1.6" /><path d="m20 20-3.2-3.2" stroke="currentColor" strokeWidth="1.7" /></>),
  check: svg(<path d="m5 12 5 5 9-11" stroke="currentColor" strokeWidth="2" />),
  clock: svg(<><circle cx="12" cy="12" r="9" stroke="currentColor" strokeWidth="1.6" /><path d="M12 7v5l3 2" stroke="currentColor" strokeWidth="1.7" /></>),
  globe: svg(<><circle cx="12" cy="12" r="9" stroke="currentColor" strokeWidth="1.5" /><path d="M3 12h18M12 3c3 3 3 15 0 18M12 3c-3 3-3 15 0 18" stroke="currentColor" strokeWidth="1.3" /></>),
};

/* ------------------------------------------------------------------ primitives */
export function Card({ children, className = "", glass = false }: { children: ReactNode; className?: string; glass?: boolean }) {
  return <div className={`rounded-2xl border border-border ${glass ? "glass" : "bg-surface"} shadow-card ${className}`}>{children}</div>;
}

export function SectionTitle({ children, right }: { children: ReactNode; right?: ReactNode }) {
  return (
    <div className="mb-3 flex items-center justify-between">
      <h2 className="text-[0.82rem] font-semibold uppercase tracking-[0.08em] text-dim">{children}</h2>
      {right}
    </div>
  );
}

export function PageHeader({ title, subtitle, action, live }: { title: string; subtitle?: string; action?: ReactNode; live?: boolean }) {
  return (
    <div className="mb-7 flex flex-wrap items-end justify-between gap-3">
      <div>
        <div className="flex items-center gap-2.5">
          <h1 className="text-2xl font-semibold tracking-tight">{title}</h1>
          {live && (
            <span className="inline-flex items-center gap-1.5 rounded-full border border-success/30 bg-success/10 px-2 py-0.5 text-xs font-medium text-success">
              <span className="live-dot h-1.5 w-1.5 rounded-full bg-success" /> Live
            </span>
          )}
        </div>
        {subtitle && <p className="mt-1.5 text-sm text-muted">{subtitle}</p>}
      </div>
      {action}
    </div>
  );
}

const VERDICT: Record<string, { label: string; cls: string; dot: string }> = {
  true_positive: { label: "True positive", cls: "bg-danger/10 text-danger border-danger/25", dot: "bg-danger" },
  false_positive: { label: "False positive", cls: "bg-success/10 text-success border-success/25", dot: "bg-success" },
  escalate: { label: "Escalate", cls: "bg-warning/10 text-warning border-warning/25", dot: "bg-warning" },
};

export function VerdictBadge({ v, size = "sm" }: { v: string | null; size?: "sm" | "md" }) {
  const m = (v && VERDICT[v]) || { label: v ?? "—", cls: "bg-info/10 text-info border-info/25", dot: "bg-info" };
  const pad = size === "md" ? "px-3 py-1 text-sm" : "px-2.5 py-0.5 text-xs";
  return (
    <span className={`inline-flex items-center gap-1.5 rounded-full border font-medium ${pad} ${m.cls}`}>
      <span className={`h-1.5 w-1.5 rounded-full ${m.dot}`} />
      {m.label}
    </span>
  );
}

const SEV: Record<string, string> = {
  critical: "bg-critical/12 text-critical border-critical/25",
  high: "bg-high/12 text-high border-high/25",
  medium: "bg-medium/14 text-medium border-medium/25",
  low: "bg-low/12 text-low border-low/25",
  informational: "bg-info/12 text-info border-info/25",
};

export function SeverityBadge({ s }: { s: string | null }) {
  if (!s) return <span className="text-xs text-dim">—</span>;
  const cls = SEV[s.toLowerCase()] ?? SEV.informational;
  return <span className={`inline-flex rounded-lg border px-2 py-0.5 text-xs font-medium capitalize ${cls}`}>{s}</span>;
}

export function StatCard({ label, value, sub, accent, tone }: { label: string; value: string; sub?: string; accent?: boolean; tone?: string }) {
  return (
    <Card className="p-4 transition duration-300 ease-spring hover:-translate-y-0.5 hover:shadow-float">
      <div className="text-xs font-medium uppercase tracking-wider text-dim">{label}</div>
      <div className={`mt-1.5 text-2xl font-semibold tabular-nums ${tone ?? (accent ? "text-accent" : "text-text")}`}>{value}</div>
      {sub && <div className="mt-0.5 text-xs text-dim">{sub}</div>}
    </Card>
  );
}

export function Spinner() {
  return (
    <div className="flex items-center justify-center gap-2 py-16 text-sm text-dim">
      <span className="h-4 w-4 animate-spin rounded-full border-2 border-border border-t-accent" /> Loading…
    </div>
  );
}

export function Button({
  children, onClick, variant = "primary", disabled, className = "", type = "button",
}: {
  children: ReactNode; onClick?: () => void; variant?: "primary" | "ghost" | "soft" | "danger" | "success";
  disabled?: boolean; className?: string; type?: "button" | "submit";
}) {
  const styles = {
    primary: "bg-accent text-white hover:bg-accent-hover shadow-card active:scale-[.98]",
    soft: "bg-accent-soft text-accent hover:brightness-95 active:scale-[.98]",
    ghost: "border border-border bg-surface text-muted hover:text-text hover:border-border-strong active:scale-[.98]",
    danger: "bg-danger/10 text-danger border border-danger/25 hover:bg-danger/15 active:scale-[.98]",
    success: "bg-success/12 text-success border border-success/25 hover:bg-success/18 active:scale-[.98]",
  }[variant];
  return (
    <button type={type} onClick={onClick} disabled={disabled}
      className={`inline-flex items-center justify-center gap-1.5 rounded-full px-4 py-2 text-sm font-medium transition duration-200 ease-spring disabled:cursor-not-allowed disabled:opacity-50 ${styles} ${className}`}>
      {children}
    </button>
  );
}

export function Segmented<T extends string>({ options, value, onChange }: { options: { key: T; label: string }[]; value: T; onChange: (v: T) => void }) {
  return (
    <div className="inline-flex rounded-full border border-border bg-surface p-1">
      {options.map((o) => (
        <button key={o.key} onClick={() => onChange(o.key)}
          className={`rounded-full px-3.5 py-1.5 text-sm font-medium transition duration-200 ease-spring ${
            value === o.key ? "bg-accent text-white shadow-card" : "text-muted hover:text-text"
          }`}>
          {o.label}
        </button>
      ))}
    </div>
  );
}

export function Meter({ value, tone = "bg-accent", width = "w-16" }: { value: number; tone?: string; width?: string }) {
  return (
    <div className={`h-1.5 ${width} overflow-hidden rounded-full bg-border`}>
      <div className={`h-full rounded-full ${tone}`} style={{ width: `${Math.round(value * 100)}%` }} />
    </div>
  );
}
