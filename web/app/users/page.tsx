"use client";
import useSWR from "swr";
import { useAuth } from "@/components/auth";
import { auth, fetcher, type User } from "@/lib/api";
import { Card, Icon, PageHeader, SectionTitle, Spinner, StatCard } from "@/components/ui";

const ROLES = ["viewer", "analyst", "soc_manager", "admin"];
const ROLE_LABEL: Record<string, string> = { admin: "Administrator", soc_manager: "SOC Manager", analyst: "Analyst", viewer: "Viewer" };
const ROLE_TONE: Record<string, string> = {
  admin: "text-critical bg-critical/10 border-critical/25",
  soc_manager: "text-warning bg-warning/10 border-warning/25",
  analyst: "text-accent bg-accent/10 border-accent/25",
  viewer: "text-info bg-info/10 border-info/25",
};

export default function UsersPage() {
  const { user, has } = useAuth();
  const { data, mutate, error } = useSWR<User[]>(has("users") ? "/api/auth/users" : null, fetcher);

  if (!has("users")) return <Denied />;
  if (error) return <Denied />;
  if (!data) return <Spinner />;

  async function changeRole(id: string, role: string) {
    await auth.setRole(id, role);
    await mutate();
  }

  const counts = ROLES.reduce((a, r) => ({ ...a, [r]: data.filter((u) => u.role === r).length }), {} as Record<string, number>);

  return (
    <div className="animate-rise">
      <PageHeader title="User Management" subtitle="Provision analysts and assign role-based access" />
      <div className="mb-6 grid grid-cols-2 gap-3 lg:grid-cols-4">
        {ROLES.slice().reverse().map((r) => (
          <StatCard key={r} label={ROLE_LABEL[r]} value={String(counts[r] ?? 0)} />
        ))}
      </div>
      <Card className="overflow-hidden">
        <div className="border-b border-border px-5 py-3"><SectionTitle>Accounts · {data.length}</SectionTitle></div>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead><tr className="border-b border-border text-left text-xs uppercase tracking-wider text-dim">
              <th className="px-5 py-2.5 font-medium">User</th><th className="px-3 py-2.5 font-medium">Team</th>
              <th className="px-3 py-2.5 font-medium">Last login</th><th className="px-3 py-2.5 font-medium">Role</th></tr></thead>
            <tbody>
              {data.map((u) => (
                <tr key={u.id} className="border-b border-border/60 transition last:border-0 hover:bg-surface-2">
                  <td className="px-5 py-2.5">
                    <div className="flex items-center gap-3">
                      <span className="flex h-8 w-8 items-center justify-center rounded-full text-xs font-semibold text-white" style={{ background: u.avatar_color }}>
                        {u.name.split(" ").map((s) => s[0]).slice(0, 2).join("")}
                      </span>
                      <div className="leading-tight">
                        <div className="font-medium text-text">{u.name}{u.id === user?.id && <span className="ml-1.5 text-[10px] text-dim">you</span>}</div>
                        <div className="text-xs text-dim">{u.email}</div>
                      </div>
                    </div>
                  </td>
                  <td className="px-3 py-2.5 text-muted">{u.team ?? "—"}</td>
                  <td className="px-3 py-2.5 text-xs text-dim">{u.last_login ? new Date(u.last_login).toLocaleString() : "never"}</td>
                  <td className="px-3 py-2.5">
                    <div className="relative inline-flex items-center">
                      <select value={u.role} disabled={u.id === user?.id} onChange={(e) => changeRole(u.id, e.target.value)}
                        className={`appearance-none rounded-lg border px-2.5 py-1 pr-7 text-xs font-medium capitalize outline-none disabled:opacity-60 ${ROLE_TONE[u.role]}`}>
                        {ROLES.map((r) => <option key={r} value={r} className="bg-surface text-text">{ROLE_LABEL[r]}</option>)}
                      </select>
                      <Icon.chevron className="pointer-events-none absolute right-2 h-3 w-3 rotate-90 text-dim" />
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>
    </div>
  );
}

function Denied() {
  return (
    <div className="animate-rise">
      <Card className="mx-auto mt-16 max-w-md p-8 text-center">
        <span className="mx-auto flex h-12 w-12 items-center justify-center rounded-2xl bg-danger/10 text-danger"><Icon.shieldAlert className="h-6 w-6" /></span>
        <h2 className="mt-4 text-lg font-semibold">Administrator access required</h2>
        <p className="mt-1 text-sm text-muted">User management is restricted to administrators.</p>
      </Card>
    </div>
  );
}
