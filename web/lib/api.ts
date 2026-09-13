// Typed client for the AEGIS review API (SPEC §6). Requests are proxied via next.config rewrites.

export interface Summary {
  investigation_id: string;
  alert_id: string;
  title: string;
  verdict: "true_positive" | "false_positive" | "escalate" | null;
  confidence: number | null;
  severity: string | null;
  techniques: string[];
  fast_pathed: boolean;
  injection_flagged: boolean;
  playbook_id: string | null;
  created_at: string;
  seconds: number;
}

export interface EvidenceRef {
  event_id: string;
  source: string;
  summary: string;
  fields: Record<string, unknown>;
}

export interface Hypothesis {
  id: string;
  statement: string;
  attack_techniques: string[];
  is_benign: boolean;
  status: string;
  reasoning: string;
  evidence_for: EvidenceRef[];
  evidence_against: EvidenceRef[];
}

export interface Investigation extends Summary {
  report_md: string | null;
  gold_label: string | null;
  alert: Record<string, unknown> | null;
  reviews: { analyst: string; action: string; override_verdict: string | null; annotation: string | null; reviewed_at: string }[];
  state: {
    context: Record<string, unknown>;
    hypotheses: Hypothesis[];
    timeline: { ts: string | null; description: string; technique: string | null; evidence: EvidenceRef }[];
    playbook: Record<string, unknown> | null;
    node_log: string[];
    malicious_score: number;
  };
}

export interface Metrics {
  total: number;
  by_verdict: Record<string, number>;
  fast_path_rate: number;
  avg_seconds: number;
  avg_tool_calls: number;
  avg_cost_usd: number;
  accuracy_vs_gold: number | null;
  reviews: number;
}

async function j<T>(url: string, init?: RequestInit): Promise<T> {
  const r = await fetch(url, { cache: "no-store", ...init });
  if (!r.ok) throw new Error(`${url} -> ${r.status}`);
  return r.json() as Promise<T>;
}

export const api = {
  queue: (verdict?: string) => j<Summary[]>(`/api/queue${verdict ? `?verdict=${verdict}` : ""}`),
  investigation: (id: string) => j<Investigation>(`/api/investigations/${id}`),
  metrics: () => j<Metrics>(`/api/metrics`),
  review: (id: string, body: { analyst: string; action: string; override_verdict?: string; annotation?: string }) =>
    j(`/api/investigations/${id}/review`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body),
    }),
  investigate: (limit: number) =>
    j<{ investigated: number }>(`/api/investigate`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ snapshot: "dev", limit }),
    }),
};

export const fetcher = (url: string) => fetch(url, { cache: "no-store" }).then((r) => r.json());
