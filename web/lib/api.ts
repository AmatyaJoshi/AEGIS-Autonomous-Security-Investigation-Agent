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

export function authToken(): string | null {
  if (typeof window === "undefined") return null;
  try { return localStorage.getItem("aegis-token"); } catch { return null; }
}

function authHeaders(extra?: HeadersInit): HeadersInit {
  const t = authToken();
  return { ...(t ? { Authorization: `Bearer ${t}` } : {}), ...(extra ?? {}) };
}

export class ApiError extends Error {
  constructor(public status: number, message: string) { super(message); }
}

async function j<T>(url: string, init?: RequestInit): Promise<T> {
  const r = await fetch(url, { cache: "no-store", ...init, headers: authHeaders(init?.headers) });
  if (r.status === 401 && typeof window !== "undefined" && !url.includes("/auth/")) {
    try { localStorage.removeItem("aegis-token"); } catch { /* */ }
    if (!location.pathname.startsWith("/login")) location.href = "/login";
  }
  if (!r.ok) {
    let msg = `${r.status}`;
    try { msg = (await r.json()).detail ?? msg; } catch { /* */ }
    throw new ApiError(r.status, msg);
  }
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

export const fetcher = (url: string) =>
  fetch(url, { cache: "no-store", headers: authHeaders() }).then((r) => {
    if (r.status === 401 && typeof window !== "undefined" && !location.pathname.startsWith("/login")) {
      try { localStorage.removeItem("aegis-token"); } catch { /* */ }
      location.href = "/login";
    }
    return r.json();
  });

/* ---------------------------------------------------------------- SOC capability types */
export interface MonitorData {
  posture: { total_investigations: number; by_verdict: Record<string, number>; open_incidents: number; auto_suppressed: number; injection_events: number; avg_latency_s: number };
  coverage: { datasets: Record<string, { events: number; hosts: number; first_ts: string; last_ts: string }>; events_monitored: number; hosts: number; snapshot: string };
  feed: { investigation_id: string; title: string; verdict: string | null; severity: string | null; confidence: number | null; created_at: string; injection_flagged: boolean }[];
  generated_at: string;
}
export interface LogRow { event_id: string; "@timestamp": string | null; dataset: string | null; host_name: string | null; user_name: string | null; event_action: string | null; event_channel: string | null; process_name: string | null; process_command_line: string | null; source_ip: string | null; destination_ip: string | null; message: string | null }
export interface LogSearch { count: number; rows: LogRow[]; facets: { actions: { key: string; count: number }[]; hosts: { key: string; count: number }[] } }
export interface ThreatData {
  detections: { investigation_id: string; title: string; techniques: string[]; severity: string | null; confidence: number | null; verdict: string | null; created_at: string }[];
  detection_count: number;
  top_techniques: { technique: string; count: number; name: string }[];
  iocs: { indicator: string; type: string; score: number; categories: string[] }[];
  intel_feed_size: number;
}
export interface ResponseData {
  playbooks: { id: string; name: string; techniques: string[]; verdicts: string[]; steps: { action: string; owner: string; requires_approval: boolean }[] }[];
  incidents: { investigation_id: string; title: string; verdict: string; severity: string | null; techniques: string[]; playbook: string | null; playbook_id: string | null; created_at: string }[];
  open_count: number;
}
export interface AutomationData {
  kpis: { auto_triaged_rate: number; fast_path_rate: number; auto_suppressed: number; avg_latency_s: number; avg_cost_usd: number; analyst_minutes_saved: number; manual_reviews: number; total: number };
  rules: { name: string; trigger: string; action: string; enabled: boolean; kind: string }[];
  guardrails: string[];
}

/* ---------------------------------------------------------------- auth */
export interface User { id: string; email: string; name: string; role: "viewer" | "analyst" | "soc_manager" | "admin"; team: string | null; avatar_color: string; permissions: string[]; created_at: string; last_login: string | null }
export const auth = {
  login: (email: string, password: string) => j<{ token: string; user: User }>(`/api/auth/login`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ email, password }) }),
  signup: (email: string, name: string, password: string, role: string) => j<{ token: string; user: User }>(`/api/auth/signup`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ email, name, password, role }) }),
  me: () => j<User>(`/api/auth/me`),
  users: () => j<User[]>(`/api/auth/users`),
  setRole: (id: string, role: string) => j<User>(`/api/auth/users/${id}/role`, { method: "PATCH", headers: { "content-type": "application/json" }, body: JSON.stringify({ role }) }),
};

/* ---------------------------------------------------------------- assets & identities */
export interface AssetRow { name: string; os: string; role: string; criticality: string; owner: string; zone: string; ip: string }
export interface AssetsData { hosts: AssetRow[]; count: number; domain: string; zones: string[] }
export interface IdentityRow { name: string; role: string; privileged?: boolean; local_admin?: boolean; service?: string; dept?: string; groups?: string[]; notes?: string }
export interface IdentitiesData { users: IdentityRow[]; count: number; privileged: number; service_accounts: number }
