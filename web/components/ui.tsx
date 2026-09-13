import type { ReactNode } from "react";

/* ------------------------------------------------------------------ icons (inline, no dep) */
export const Icon = {
  shield: (p: { className?: string }) => (
    <svg viewBox="0 0 24 24" fill="none" className={p.className} aria-hidden>
      <path d="M12 2 4 5v6c0 5 3.4 8.5 8 11 4.6-2.5 8-6 8-11V5l-8-3Z" fill="currentColor" opacity=".15" />
      <path d="M12 2 4 5v6c0 5 3.4 8.5 8 11 4.6-2.5 8-6 8-11V5l-8-3Z" stroke="currentColor" strokeWidth="1.6" />
      <path d="m9 12 2 2 4-4.5" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  ),
  queue: (p: { className?: string }) => (
    <svg viewBox="0 0 24 24" fill="none" className={p.className} aria-hidden>
      <rect x="3" y="4" width="18" height="4" rx="1.4" stroke="currentColor" strokeWidth="1.6" />
      <rect x="3" y="10" width="18" height="4" rx="1.4" stroke="currentColor" strokeWidth="1.6" />
      <rect x="3" y="16" width="18" height="4" rx="1.4" stroke="currentColor" strokeWidth="1.6" />
    </svg>
  ),
  tag: (p: { className?: string }) => (
    <svg viewBox="0 0 24 24" fill="none" className={p.className} aria-hidden>
      <path d="M3 12V4h8l10 10-8 8L3 12Z" stroke="currentColor" strokeWidth="1.6" strokeLinejoin="round" />
      <circle cx="7.5" cy="7.5" r="1.4" fill="currentColor" />
    </svg>
  ),
  chart: (p: { className?: string }) => (
    <svg viewBox="0 0 24 24" fill="none" className={p.className} aria-hidden>
      <path d="M4 20V10M10 20V4M16 20v-7M22 20H2" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" />
    </svg>
  ),
  sun: (p: { className?: string }) => (
    <svg viewBox="0 0 24 24" fill="none" className={p.className} aria-hidden>
      <circle cx="12" cy="12" r="4" stroke="currentColor" strokeWidth="1.6" />
      <path d="M12 2v2M12 20v2M4 12H2M22 12h-2M5 5 3.5 3.5M20.5 20.5 19 19M19 5l1.5-1.5M3.5 20.5 5 19" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" />
    </svg>
  ),
  moon: (p: { className?: string }) => (
    <svg viewBox="0 0 24 24" fill="none" className={p.className} aria-hidden>
      <path d="M21 12.8A8.5 8.5 0 1 1 11.2 3a6.5 6.5 0 0 0 9.8 9.8Z" stroke="currentColor" strokeWidth="1.6" strokeLinejoin="round" />
    </svg>
  ),
  bolt: (p: { className?: string }) => (
    <svg viewBox="0 0 24 24" fill="none" className={p.className} aria-hidden>
      <path d="M13 2 4 14h6l-1 8 9-12h-6l1-8Z" stroke="currentColor" strokeWidth="1.6" strokeLinejoin="round" />
    </svg>
  ),
  shieldAlert: (p: { className?: string }) => (
    <svg viewBox="0 0 24 24" fill="none" className={p.className} aria-hidden>
      <path d="M12 2 4 5v6c0 5 3.4 8.5 8 11 4.6-2.5 8-6 8-11V5l-8-3Z" stroke="currentColor" strokeWidth="1.6" />
      <path d="M12 8v4M12 15.5v.5" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" />
    </svg>
  ),
  chevron: (p: { className?: string }) => (
    <svg viewBox="0 0 24 24" fill="none" className={p.className} aria-hidden>
      <path d="m9 6 6 6-6 6" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  ),
  search: (p: { className?: string }) => (
    <svg viewBox="0 0 24 24" fill="none" className={p.className} aria-hidden>
      <circle cx="11" cy="11" r="7" stroke="currentColor" strokeWidth="1.6" />
      <path d="m20 20-3.2-3.2" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" />
    </svg>
  ),
};

/* ------------------------------------------------------------------ primitives */
export function Card({ children, className = "" }: { children: ReactNode; className?: string }) {
  return (
    <div className={`rounded-xl border border-border bg-surface shadow-card ${className}`}>{children}</div>
  );
}

export function SectionTitle({ children, right }: { children: ReactNode; right?: ReactNode }) {
  return (
    <div className="flex items-center justify-between mb-3">
      <h2 className="text-sm font-semibold uppercase tracking-wider text-dim">{children}</h2>
      {right}
    </div>
  );
}

const VERDICT: Record<string, { label: string; cls: string; dot: string }> = {
  true_positive: { label: "True positive", cls: "bg-danger/10 text-danger border-danger/30", dot: "bg-danger" },
  false_positive: { label: "False positive", cls: "bg-success/10 text-success border-success/30", dot: "bg-success" },
  escalate: { label: "Escalate", cls: "bg-warning/10 text-warning border-warning/30", dot: "bg-warning" },
};

export function VerdictBadge({ v, size = "sm" }: { v: string | null; size?: "sm" | "md" }) {
  const m = (v && VERDICT[v]) || { label: v ?? "—", cls: "bg-info/10 text-info border-info/30", dot: "bg-info" };
  const pad = size === "md" ? "px-2.5 py-1 text-sm" : "px-2 py-0.5 text-xs";
  return (
    <span className={`inline-flex items-center gap-1.5 rounded-full border font-medium ${pad} ${m.cls}`}>
      <span className={`h-1.5 w-1.5 rounded-full ${m.dot}`} />
      {m.label}
    </span>
  );
}

const SEV: Record<string, string> = {
  critical: "bg-critical/12 text-critical border-critical/30",
  high: "bg-high/12 text-high border-high/30",
  medium: "bg-medium/12 text-medium border-medium/30",
  low: "bg-low/12 text-low border-low/30",
  informational: "bg-info/12 text-info border-info/30",
};

export function SeverityBadge({ s }: { s: string | null }) {
  if (!s) return <span className="text-dim text-xs">—</span>;
  const cls = SEV[s.toLowerCase()] ?? SEV.informational;
  return (
    <span className={`inline-flex rounded-md border px-1.5 py-0.5 text-xs font-medium capitalize ${cls}`}>
      {s}
    </span>
  );
}

export function Chip({ children }: { children: ReactNode }) {
  return (
    <span className="inline-flex rounded-md border border-border bg-surface-2 px-1.5 py-0.5 text-xs font-medium text-muted">
      {children}
    </span>
  );
}

export function StatCard({ label, value, sub, accent }: { label: string; value: string; sub?: string; accent?: boolean }) {
  return (
    <Card className="p-4">
      <div className="text-xs font-medium uppercase tracking-wider text-dim">{label}</div>
      <div className={`mt-1.5 text-2xl font-semibold tabular-nums ${accent ? "text-accent" : "text-text"}`}>{value}</div>
      {sub && <div className="mt-0.5 text-xs text-dim">{sub}</div>}
    </Card>
  );
}

export function Spinner() {
  return (
    <div className="flex items-center gap-2 text-dim text-sm py-10 justify-center">
      <span className="h-4 w-4 animate-spin rounded-full border-2 border-border border-t-accent" />
      Loading…
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
    primary: "bg-accent text-white hover:bg-accent-hover shadow-card",
    soft: "bg-accent-soft text-accent hover:brightness-95",
    ghost: "border border-border text-muted hover:text-text hover:border-border-strong",
    danger: "bg-danger/10 text-danger border border-danger/30 hover:bg-danger/20",
    success: "bg-success/10 text-success border border-success/30 hover:bg-success/20",
  }[variant];
  return (
    <button
      type={type}
      onClick={onClick}
      disabled={disabled}
      className={`inline-flex items-center justify-center gap-1.5 rounded-lg px-3 py-1.5 text-sm font-medium transition disabled:opacity-50 disabled:cursor-not-allowed ${styles} ${className}`}
    >
      {children}
    </button>
  );
}
