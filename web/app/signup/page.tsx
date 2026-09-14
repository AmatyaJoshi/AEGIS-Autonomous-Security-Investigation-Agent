"use client";
import { useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useAuth } from "@/components/auth";
import { AuthScreen, Field } from "@/components/authScreen";
import { ApiError } from "@/lib/api";

const ROLES = [
  { key: "analyst", label: "Analyst", desc: "Investigate & review" },
  { key: "soc_manager", label: "SOC Manager", desc: "Configure automation" },
  { key: "viewer", label: "Viewer", desc: "Read-only access" },
];

export default function SignupPage() {
  const { signup } = useAuth();
  const router = useRouter();
  const [email, setEmail] = useState("");
  const [name, setName] = useState("");
  const [password, setPassword] = useState("");
  const [role, setRole] = useState("analyst");
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    setErr(""); setBusy(true);
    try { await signup(email, name, password, role); router.replace("/overview"); }
    catch (e) { setErr(e instanceof ApiError ? e.message : "Sign up failed"); }
    finally { setBusy(false); }
  }

  return (
    <AuthScreen>
      <h2 className="text-2xl font-semibold tracking-tight">Create your account</h2>
      <p className="mt-1 text-sm text-muted">Join the AEGIS SOC console</p>

      <form onSubmit={submit} className="mt-7 space-y-4">
        <Field label="Full name" value={name} onChange={(e) => setName(e.target.value)} placeholder="Alex Rivera" required autoFocus />
        <Field label="Work email" type="email" value={email} onChange={(e) => setEmail(e.target.value)} placeholder="you@company.com" required />
        <Field label="Password" type="password" value={password} onChange={(e) => setPassword(e.target.value)} placeholder="At least 6 characters" required minLength={6} />
        <div>
          <span className="mb-1.5 block text-sm font-medium text-muted">Role</span>
          <div className="grid grid-cols-3 gap-2">
            {ROLES.map((r) => (
              <button type="button" key={r.key} onClick={() => setRole(r.key)}
                className={`rounded-xl border px-2 py-2 text-left text-xs transition ${role === r.key ? "border-accent bg-accent/10" : "border-border bg-surface-2 hover:border-border-strong"}`}>
                <div className="font-semibold text-text">{r.label}</div>
                <div className="mt-0.5 text-dim">{r.desc}</div>
              </button>
            ))}
          </div>
        </div>
        {err && <p className="rounded-lg bg-danger/10 px-3 py-2 text-sm text-danger">{err}</p>}
        <button type="submit" disabled={busy}
          className="w-full rounded-full bg-accent py-2.5 text-sm font-semibold text-white transition hover:bg-accent-hover active:scale-[.99] disabled:opacity-50">
          {busy ? "Creating…" : "Create account"}
        </button>
      </form>

      <p className="mt-5 text-center text-sm text-muted">
        Already have an account? <Link href="/login" className="font-medium text-accent hover:underline">Sign in</Link>
      </p>
      <p className="mt-3 text-center text-xs text-dim">The first account created becomes the administrator.</p>
    </AuthScreen>
  );
}
