"use client";
import type { ReactNode } from "react";
import { Icon } from "@/components/ui";

const FEATURES = [
  { icon: "monitor", t: "Continuous monitoring" },
  { icon: "radar", t: "Threat detection" },
  { icon: "response", t: "Incident response" },
  { icon: "automation", t: "Automation" },
] as const;

/** Split layout — live animated hero on the left, clean form on the right. */
export function AuthScreen({ children }: { children: ReactNode }) {
  return (
    <div className="relative z-10 flex min-h-screen">
      {/* animated hero */}
      <div className="relative hidden w-[48%] overflow-hidden bg-[#0A2540] text-white lg:block">
        {/* base gradient */}
        <div className="hero-hue absolute inset-0 bg-gradient-to-br from-accent via-[#3B5BFF] to-[#7B2FF7]" />
        {/* drifting orbs */}
        <div className="orb-a pointer-events-none absolute -left-24 top-10 h-96 w-96 rounded-full bg-white/25 blur-3xl" />
        <div className="orb-b pointer-events-none absolute right-0 top-1/3 h-[26rem] w-[26rem] rounded-full bg-[#00E0FF]/25 blur-3xl" />
        <div className="orb-c pointer-events-none absolute -bottom-32 left-1/4 h-[30rem] w-[30rem] rounded-full bg-[#B721FF]/25 blur-3xl" />
        {/* animated grid */}
        <div
          className="hero-grid pointer-events-none absolute inset-0 opacity-[0.18]"
          style={{
            backgroundImage:
              "linear-gradient(rgba(255,255,255,.6) 1px, transparent 1px), linear-gradient(90deg, rgba(255,255,255,.6) 1px, transparent 1px)",
            backgroundSize: "44px 44px",
            maskImage: "radial-gradient(circle at 40% 40%, black, transparent 78%)",
            WebkitMaskImage: "radial-gradient(circle at 40% 40%, black, transparent 78%)",
          }}
        />

        {/* content */}
        <div className="relative flex h-full flex-col justify-between p-12">
          <div className="inline-flex w-fit items-center gap-2 rounded-full bg-white/12 px-3 py-1 text-xs font-bold backdrop-blur">
            <span className="live-dot h-1.5 w-1.5 rounded-full bg-white" /> Agentic AI · evidence-cited
          </div>

          <div className="max-w-md">
            <div className="animate-floaty mb-6 flex h-16 w-16 items-center justify-center rounded-3xl bg-white/15 shadow-2xl backdrop-blur">
              <Icon.shield className="h-9 w-9" />
            </div>
            <h1 className="text-[2.3rem] font-bold leading-[1.1] tracking-tight">
              Autonomous SOC investigation, built for the cloud.
            </h1>
            <p className="mt-4 text-[0.98rem] font-medium leading-relaxed text-white/80">
              AI that plans, executes and verifies investigations — with evidence-cited verdicts and
              human-approved response.
            </p>
            <div className="mt-7 flex flex-wrap gap-2">
              {FEATURES.map((f) => {
                const Ico = Icon[f.icon];
                return (
                  <span
                    key={f.t}
                    className="inline-flex items-center gap-2 rounded-full border border-white/15 bg-white/10 px-3.5 py-2 text-sm font-semibold backdrop-blur transition hover:bg-white/[0.18]"
                  >
                    <Ico className="h-4 w-4" /> {f.t}
                  </span>
                );
              })}
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-x-5 gap-y-2 text-xs font-semibold text-white/75">
            <span className="inline-flex items-center gap-1.5"><Icon.check className="h-3.5 w-3.5" /> Recommend-only</span>
            <span className="inline-flex items-center gap-1.5"><Icon.check className="h-3.5 w-3.5" /> Read-only SIEM</span>
            <span className="inline-flex items-center gap-1.5"><Icon.check className="h-3.5 w-3.5" /> Human-in-the-loop</span>
          </div>
        </div>
      </div>

      {/* form */}
      <div className="flex flex-1 items-center justify-center px-6 py-12">
        <div className="w-full max-w-sm animate-rise">
          <div className="mb-8 flex items-center gap-2.5">
            <span className="flex h-9 w-9 items-center justify-center rounded-xl bg-accent text-white shadow-glow">
              <Icon.shield className="h-5 w-5" />
            </span>
            <div className="leading-tight">
              <div className="text-sm font-bold tracking-tight">AEGIS</div>
              <div className="text-[0.7rem] font-medium text-dim">Autonomous SOC</div>
            </div>
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
      <span className="mb-1.5 block text-sm font-semibold text-muted">{label}</span>
      <input {...props}
        className="w-full rounded-xl border border-border bg-surface-2 px-3.5 py-2.5 text-[0.95rem] font-medium text-text placeholder:font-normal placeholder:text-dim transition focus:border-accent focus:outline-none focus:ring-2 focus:ring-ring/25" />
    </label>
  );
}
