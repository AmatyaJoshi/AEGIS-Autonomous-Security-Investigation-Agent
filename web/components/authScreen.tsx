"use client";
import type { ReactNode } from "react";
import { Icon } from "@/components/ui";

/** Full-screen split layout for login / signup — Apple-style hero + frosted card. */
export function AuthScreen({ children }: { children: ReactNode }) {
  return (
    <div className="relative z-10 flex min-h-screen">
      {/* hero */}
      <div className="relative hidden w-1/2 flex-col justify-between overflow-hidden bg-gradient-to-br from-accent to-accent-hover p-12 text-white lg:flex">
        <div className="flex items-center gap-3">
          <span className="flex h-11 w-11 items-center justify-center rounded-2xl bg-white/15 backdrop-blur">
            <Icon.shield className="h-7 w-7" />
          </span>
          <span className="text-lg font-semibold tracking-tight">AEGIS</span>
        </div>
        <div className="max-w-md">
          <h1 className="text-3xl font-semibold leading-tight tracking-tight">Autonomous SOC investigation, built for the cloud.</h1>
          <p className="mt-4 text-white/80">
            Agentic AI that plans, executes and verifies investigations — evidence-cited verdicts,
            continuous monitoring, and human-approved response.
          </p>
          <div className="mt-8 grid grid-cols-2 gap-4 text-sm">
            {[
              ["Continuous monitoring", "always-on visibility"],
              ["Threat detection", "real-time intel + IoCs"],
              ["Incident response", "human-approved playbooks"],
              ["Automation", "focus on complex threats"],
            ].map(([t, s]) => (
              <div key={t} className="rounded-2xl bg-white/10 p-3 backdrop-blur">
                <div className="font-medium">{t}</div>
                <div className="text-white/70">{s}</div>
              </div>
            ))}
          </div>
        </div>
        <div className="text-xs text-white/60">Recommend-only · human-in-the-loop · SPEC.md</div>
        <div className="pointer-events-none absolute -right-24 -top-24 h-80 w-80 rounded-full bg-white/10 blur-3xl" />
        <div className="pointer-events-none absolute -bottom-32 -left-16 h-96 w-96 rounded-full bg-black/10 blur-3xl" />
      </div>

      {/* form */}
      <div className="flex flex-1 items-center justify-center px-6 py-12">
        <div className="w-full max-w-sm animate-rise">
          <div className="mb-8 flex items-center gap-2.5 lg:hidden">
            <span className="flex h-9 w-9 items-center justify-center rounded-xl bg-accent text-white">
              <Icon.shield className="h-5 w-5" />
            </span>
            <span className="font-semibold">AEGIS</span>
          </div>
          {children}
        </div>
      </div>
    </div>
  );
}

export function Field({ label, ...props }: { label: string } & React.InputHTMLAttributes<HTMLInputElement>) {
  return (
    <label className="block">
      <span className="mb-1.5 block text-sm font-medium text-muted">{label}</span>
      <input {...props}
        className="w-full rounded-xl border border-border bg-surface-2 px-3.5 py-2.5 text-[0.95rem] text-text placeholder:text-dim transition focus:border-accent focus:outline-none focus:ring-2 focus:ring-ring/25" />
    </label>
  );
}
