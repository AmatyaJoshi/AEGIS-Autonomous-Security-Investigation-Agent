"use client";
import { useAuth } from "@/components/auth";
import { Button, Card, PageHeader, SectionTitle } from "@/components/ui";

const ROLE_LABEL: Record<string, string> = { admin: "Administrator", soc_manager: "SOC Manager", analyst: "Analyst", viewer: "Viewer" };
const PERM_LABEL: Record<string, string> = {
  read: "Read investigations & telemetry", investigate: "Run investigations",
  review: "Approve / override / annotate", automation: "Configure automation",
  team: "View team analytics", users: "Manage users", settings: "Manage settings",
};

export default function SettingsPage() {
  const { user, logout } = useAuth();
  if (!user) return null;
  return (
    <div className="animate-rise">
      <PageHeader title="Settings" subtitle="Your profile, access and workspace" />
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
        <Card className="p-6 lg:col-span-1">
          <div className="flex flex-col items-center text-center">
            <span className="flex h-20 w-20 items-center justify-center rounded-3xl text-2xl font-semibold text-white shadow-glow" style={{ background: user.avatar_color }}>
              {user.name.split(" ").map((s) => s[0]).slice(0, 2).join("")}
            </span>
            <h2 className="mt-4 text-lg font-semibold">{user.name}</h2>
            <p className="text-sm text-dim">{user.email}</p>
            <span className="mt-3 rounded-full border border-accent/25 bg-accent/10 px-3 py-1 text-xs font-medium text-accent">{ROLE_LABEL[user.role]}</span>
            {user.team && <p className="mt-2 text-xs text-dim">{user.team}</p>}
          </div>
          <div className="mt-6 border-t border-border pt-4">
            <Button variant="danger" className="w-full" onClick={logout}>Sign out</Button>
          </div>
        </Card>

        <div className="space-y-6 lg:col-span-2">
          <Card className="p-6">
            <SectionTitle>Your permissions</SectionTitle>
            <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
              {["read", "investigate", "review", "automation", "team", "users", "settings"].map((p) => {
                const on = user.permissions.includes(p);
                return (
                  <div key={p} className={`flex items-center gap-2.5 rounded-xl border px-3 py-2.5 text-sm ${on ? "border-success/25 bg-success/5" : "border-border bg-surface-2 opacity-50"}`}>
                    <span className={`flex h-5 w-5 shrink-0 items-center justify-center rounded-full text-[10px] ${on ? "bg-success/15 text-success" : "bg-border text-dim"}`}>{on ? "✓" : "—"}</span>
                    <span className={on ? "text-text" : "text-dim"}>{PERM_LABEL[p]}</span>
                  </div>
                );
              })}
            </div>
          </Card>

          <Card className="p-6">
            <SectionTitle>Account</SectionTitle>
            <Row label="Account ID" value={user.id} mono />
            <Row label="Member since" value={new Date(user.created_at).toLocaleDateString()} />
            <Row label="Last sign-in" value={user.last_login ? new Date(user.last_login).toLocaleString() : "—"} />
          </Card>

          <Card className="p-6">
            <SectionTitle>About AEGIS</SectionTitle>
            <p className="text-sm leading-relaxed text-muted">
              AEGIS is an autonomous SOC investigation agent. It forms and tests competing hypotheses
              against SIEM logs, maps behaviour to MITRE ATT&CK, and produces evidence-cited incident
              reports. Response is recommend-only — every containment action stays a human decision.
            </p>
            <p className="mt-3 text-xs text-dim">Use the theme toggle in the top bar to switch between light and dark.</p>
          </Card>
        </div>
      </div>
    </div>
  );
}

function Row({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="flex items-center justify-between border-b border-border py-2.5 text-sm last:border-0">
      <span className="text-muted">{label}</span>
      <span className={`font-medium text-text ${mono ? "font-mono text-xs" : ""}`}>{value}</span>
    </div>
  );
}
