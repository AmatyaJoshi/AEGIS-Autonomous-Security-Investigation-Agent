"use client";
import useSWR from "swr";
import { fetcher, type IdentitiesData } from "@/lib/api";
import { Card, PageHeader, SectionTitle, Spinner, StatCard } from "@/components/ui";

export default function IdentitiesPage() {
  const { data } = useSWR<IdentitiesData>("/api/identities", fetcher);
  if (!data) return <Spinner />;
  return (
    <div className="animate-rise">
      <PageHeader title="Identities" subtitle="Identity provider · accounts, privilege and service identities" />
      <div className="mb-6 grid grid-cols-2 gap-3 lg:grid-cols-4">
        <StatCard label="Accounts" value={String(data.count)} />
        <StatCard label="Privileged" value={String(data.privileged)} tone="text-warning" />
        <StatCard label="Service accounts" value={String(data.service_accounts)} tone="text-accent" />
        <StatCard label="Standard users" value={String(data.count - data.privileged - data.service_accounts)} />
      </div>
      <Card className="overflow-hidden">
        <div className="border-b border-border px-5 py-3"><SectionTitle>Directory</SectionTitle></div>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead><tr className="border-b border-border text-left text-xs uppercase tracking-wider text-dim">
              <th className="px-5 py-2.5 font-medium">User</th><th className="px-3 py-2.5 font-medium">Role</th>
              <th className="px-3 py-2.5 font-medium">Department</th><th className="px-3 py-2.5 font-medium">Attributes</th>
              <th className="px-3 py-2.5 font-medium">Groups</th></tr></thead>
            <tbody>
              {data.users.map((u) => (
                <tr key={u.name} className="border-b border-border/60 transition last:border-0 hover:bg-surface-2">
                  <td className="px-5 py-2.5 font-medium text-text">{u.name}</td>
                  <td className="px-3 py-2.5 text-muted">{u.role}</td>
                  <td className="px-3 py-2.5 text-muted">{u.dept ?? "—"}</td>
                  <td className="px-3 py-2.5">
                    <div className="flex flex-wrap gap-1">
                      {u.privileged && <span className="rounded-md border border-warning/25 bg-warning/10 px-1.5 py-0.5 text-[10px] font-medium text-warning">privileged</span>}
                      {u.service && <span className="rounded-md border border-accent/25 bg-accent/10 px-1.5 py-0.5 text-[10px] font-medium text-accent">service: {u.service}</span>}
                      {u.local_admin && <span className="rounded-md border border-border bg-surface-2 px-1.5 py-0.5 text-[10px] text-dim">local admin</span>}
                      {!u.privileged && !u.service && !u.local_admin && <span className="text-xs text-dim">standard</span>}
                    </div>
                  </td>
                  <td className="px-3 py-2.5 text-xs text-dim">{(u.groups ?? []).join(", ") || "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </Card>
    </div>
  );
}
