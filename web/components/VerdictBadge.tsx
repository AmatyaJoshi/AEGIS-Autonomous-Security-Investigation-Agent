export function VerdictBadge({ v }: { v: string | null }) {
  const map: Record<string, string> = {
    true_positive: "bg-red-500/20 text-red-300 border-red-500/40",
    false_positive: "bg-green-500/20 text-green-300 border-green-500/40",
    escalate: "bg-amber-500/20 text-amber-300 border-amber-500/40",
  };
  const cls = (v && map[v]) || "bg-slate-500/20 text-slate-300 border-slate-500/40";
  return <span className={`px-2 py-0.5 rounded border text-xs font-medium ${cls}`}>{v ?? "-"}</span>;
}
