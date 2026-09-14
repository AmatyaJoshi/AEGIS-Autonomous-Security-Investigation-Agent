"use client";
import { useEffect, useState } from "react";
import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { useAuth } from "@/components/auth";
import { ThemeToggle } from "@/components/theme";
import { Icon } from "@/components/ui";

type NavItem = { href: string; label: string; icon: (p: { className?: string }) => React.ReactNode; perm?: string };
const NAV: { group: string; items: NavItem[] }[] = [
  { group: "Overview", items: [
    { href: "/overview", label: "Dashboard", icon: Icon.chart },
    { href: "/assistant", label: "AI Copilot", icon: Icon.spark },
  ] },
  { group: "Operate", items: [
    { href: "/monitor", label: "Monitor", icon: Icon.monitor },
    { href: "/", label: "Investigations", icon: Icon.queue },
    { href: "/logs", label: "Log Analysis", icon: Icon.logs },
  ] },
  { group: "Defend", items: [
    { href: "/threats", label: "Threat Detection", icon: Icon.radar },
    { href: "/response", label: "Incident Response", icon: Icon.response },
    { href: "/automation", label: "Automation", icon: Icon.automation },
  ] },
  { group: "Inventory", items: [
    { href: "/assets", label: "Assets", icon: Icon.globe },
    { href: "/identities", label: "Identities", icon: Icon.tag },
  ] },
  { group: "Improve", items: [
    { href: "/labels", label: "Labels", icon: Icon.check, perm: "review" },
    { href: "/metrics", label: "Metrics", icon: Icon.chart },
  ] },
  { group: "Manage", items: [
    { href: "/users", label: "Users", icon: Icon.response, perm: "users" },
    { href: "/settings", label: "Settings", icon: Icon.automation },
  ] },
];

const ROLE_LABEL: Record<string, string> = { admin: "Administrator", soc_manager: "SOC Manager", analyst: "Analyst", viewer: "Viewer" };

const AUTH_ROUTES = ["/login", "/signup"];

export function Chrome({ children }: { children: React.ReactNode }) {
  const pathname = usePathname();
  const router = useRouter();
  const { user, loading, logout, has } = useAuth();
  const isAuth = AUTH_ROUTES.some((r) => pathname.startsWith(r));

  useEffect(() => {
    if (!loading && !user && !isAuth) router.replace("/login");
  }, [loading, user, isAuth, router]);

  if (isAuth) return <>{children}</>;
  if (loading || !user) {
    return (
      <div className="flex min-h-screen items-center justify-center">
        <span className="h-6 w-6 animate-spin rounded-full border-2 border-border border-t-accent" />
      </div>
    );
  }

  return (
    <div className="relative z-10 flex min-h-screen">
      <aside className="glass sticky top-0 hidden h-screen w-64 shrink-0 flex-col border-r border-border md:flex">
        <div className="flex items-center gap-3 px-5 py-6">
          <span className="flex h-10 w-10 items-center justify-center rounded-2xl bg-gradient-to-br from-accent to-accent-hover text-white shadow-glow">
            <Icon.shield className="h-6 w-6" />
          </span>
          <div className="leading-tight">
            <div className="text-[15px] font-bold tracking-tight">AEGIS</div>
            <div className="text-[11px] text-dim">Autonomous SOC</div>
          </div>
        </div>

        <nav className="flex flex-1 flex-col gap-4 overflow-y-auto px-3 py-2">
          {NAV.map((g) => {
            const items = g.items.filter((i) => !i.perm || has(i.perm));
            if (items.length === 0) return null;
            return (
              <div key={g.group}>
                <div className="px-3 pb-1 text-[10px] font-semibold uppercase tracking-[0.12em] text-dim">{g.group}</div>
                <div className="flex flex-col gap-0.5">
                  {items.map((n) => {
                    const active = n.href === "/" ? pathname === "/" : pathname.startsWith(n.href);
                    return (
                      <Link key={n.href} href={n.href}
                        className={`group flex items-center gap-3 rounded-xl px-3 py-2 text-[0.92rem] font-medium transition duration-200 ease-spring ${
                          active ? "bg-accent/12 text-accent" : "text-muted hover:bg-surface-2 hover:text-text"
                        }`}>
                        <n.icon className={`h-[19px] w-[19px] ${active ? "text-accent" : "text-dim group-hover:text-accent"}`} />
                        {n.label}
                      </Link>
                    );
                  })}
                </div>
              </div>
            );
          })}
        </nav>

        <ProfileCard />
      </aside>

      <div className="flex min-w-0 flex-1 flex-col">
        <header className="glass sticky top-0 z-20 flex items-center gap-3 border-b border-border px-6 py-3">
          <Link href="/overview" className="flex items-center gap-2 md:hidden">
            <Icon.shield className="h-5 w-5 text-accent" />
            <span className="font-semibold">AEGIS</span>
          </Link>
          <div className="ml-auto flex items-center gap-3">
            <span className="hidden text-xs text-dim sm:inline">Agentic AI · Continuous cloud SOC</span>
            <ThemeToggle />
            <ProfileMenu />
          </div>
        </header>
        <main className="mx-auto w-full max-w-[1240px] flex-1 px-6 py-7">{children}</main>
      </div>

      {!pathname.startsWith("/assistant") && (
        <Link
          href="/assistant"
          aria-label="Ask the AI Copilot"
          className="group fixed bottom-6 right-6 z-40 flex items-center gap-2.5 rounded-full bg-gradient-to-br from-accent to-accent-hover py-3 pl-3.5 pr-4 text-white shadow-glow transition duration-200 ease-spring hover:scale-105 active:scale-95"
        >
          <Icon.spark className="h-5 w-5" />
          <span className="text-sm font-semibold">Ask Copilot</span>
        </Link>
      )}
    </div>
  );

  function ProfileCard() {
    return (
      <div className="px-3 py-3">
        <Link href="/settings" className="flex items-center gap-3 rounded-2xl border border-border bg-surface-2 p-3 transition hover:border-border-strong">
          <Avatar />
          <div className="min-w-0 leading-tight">
            <div className="truncate text-sm font-semibold">{user!.name}</div>
            <div className="truncate text-[11px] text-dim">{ROLE_LABEL[user!.role]}{user!.team ? ` · ${user!.team}` : ""}</div>
          </div>
        </Link>
      </div>
    );
  }

  function ProfileMenu() {
    const [open, setOpen] = useState(false);
    return (
      <div className="relative">
        <button onClick={() => setOpen((o) => !o)} className="flex items-center gap-2 rounded-full border border-border bg-surface py-1 pl-1 pr-2.5 transition hover:border-border-strong">
          <Avatar sm />
          <span className="hidden text-sm font-medium sm:inline">{user!.name.split(" ")[0]}</span>
          <Icon.chevron className={`h-3.5 w-3.5 text-dim transition ${open ? "rotate-90" : ""}`} />
        </button>
        {open && (
          <>
            <div className="fixed inset-0 z-30" onClick={() => setOpen(false)} />
            <div className="animate-pop absolute right-0 z-40 mt-2 w-60 overflow-hidden rounded-2xl border border-border bg-surface shadow-float">
              <div className="flex items-center gap-3 border-b border-border p-4">
                <Avatar />
                <div className="min-w-0 leading-tight">
                  <div className="truncate text-sm font-semibold">{user!.name}</div>
                  <div className="truncate text-xs text-dim">{user!.email}</div>
                </div>
              </div>
              <div className="p-1.5">
                <div className="flex items-center justify-between px-3 py-2 text-sm">
                  <span className="text-muted">Role</span>
                  <span className="rounded-full border border-accent/25 bg-accent/10 px-2 py-0.5 text-xs font-medium text-accent">{ROLE_LABEL[user!.role]}</span>
                </div>
                <Link href="/settings" onClick={() => setOpen(false)} className="block rounded-lg px-3 py-2 text-sm text-muted transition hover:bg-surface-2 hover:text-text">Settings</Link>
                <button onClick={logout} className="w-full rounded-lg px-3 py-2 text-left text-sm text-danger transition hover:bg-danger/10">Sign out</button>
              </div>
            </div>
          </>
        )}
      </div>
    );
  }

  function Avatar({ sm }: { sm?: boolean }) {
    const initials = user!.name.split(" ").map((s) => s[0]).slice(0, 2).join("").toUpperCase();
    return (
      <span className={`flex ${sm ? "h-7 w-7 text-xs" : "h-9 w-9 text-sm"} shrink-0 items-center justify-center rounded-full font-semibold text-white`} style={{ background: user!.avatar_color }}>
        {initials}
      </span>
    );
  }
}
