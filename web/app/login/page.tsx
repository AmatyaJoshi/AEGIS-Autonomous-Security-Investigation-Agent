"use client";
import { useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useAuth } from "@/components/auth";
import { AuthScreen, Field } from "@/components/authScreen";
import { ApiError } from "@/lib/api";

const DEMO = [
  { email: "admin@aegis.local", role: "Administrator" },
  { email: "manager@aegis.local", role: "SOC Manager" },
  { email: "analyst@aegis.local", role: "Analyst" },
  { email: "viewer@aegis.local", role: "Viewer" },
];

export default function LoginPage() {
  const { login } = useAuth();
  const router = useRouter();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setErr(""); setBusy(true);
    try { await login(email, password); router.replace("/overview"); }
    catch (e) { setErr(e instanceof ApiError ? e.message : "Sign in failed"); }
    finally { setBusy(false); }
  }

  function demo(mail: string) { setEmail(mail); setPassword("aegis1234"); }

  return (
    <AuthScreen>
      <h2 className="text-2xl font-bold tracking-tight">Welcome back</h2>
      <p className="mt-1 text-sm text-muted">Sign in to the AEGIS console</p>

      <form onSubmit={submit} className="mt-7 space-y-4">
        <Field label="Email" type="email" value={email} onChange={(e) => setEmail(e.target.value)} placeholder="you@company.com" required autoFocus />
        <Field label="Password" type="password" value={password} onChange={(e) => setPassword(e.target.value)} placeholder="••••••••" required />
        {err && <p className="rounded-lg bg-danger/10 px-3 py-2 text-sm text-danger">{err}</p>}
        <button type="submit" disabled={busy}
          className="w-full rounded-xl bg-accent py-2.5 text-sm font-semibold text-white shadow-card transition hover:bg-accent-hover active:scale-[.99] disabled:opacity-50">
          {busy ? "Signing in…" : "Sign in"}
        </button>
      </form>

      <p className="mt-5 text-center text-sm text-muted">
        No account? <Link href="/signup" className="font-medium text-accent hover:underline">Create one</Link>
      </p>

      <div className="mt-8 rounded-2xl border border-border bg-surface-2 p-3.5">
        <div className="mb-2 text-xs font-semibold uppercase tracking-wider text-dim">Demo accounts · password aegis1234</div>
        <div className="grid grid-cols-2 gap-1.5">
          {DEMO.map((d) => (
            <button key={d.email} onClick={() => demo(d.email)}
              className="rounded-lg border border-border bg-surface px-2.5 py-1.5 text-left text-xs transition hover:border-accent">
              <div className="font-medium text-text">{d.role}</div>
              <div className="truncate text-dim">{d.email}</div>
            </button>
          ))}
        </div>
      </div>
    </AuthScreen>
  );
}
