"use client";
import { useEffect, useRef, useState } from "react";
import useSWR from "swr";
import { assistant, type AssistantReply } from "@/lib/api";
import { Card, Icon, PageHeader, SectionTitle } from "@/components/ui";
import { useAuth } from "@/components/auth";

type Msg =
  | { role: "user"; text: string }
  | { role: "assistant"; reply: AssistantReply }
  | { role: "typing" };

/* very small, safe markdown: **bold**, `-`/`1.` lists, paragraphs. No raw HTML passthrough. */
function inline(s: string) {
  const parts = s.split(/(\*\*[^*]+\*\*|\*[^*]+\*)/g).filter(Boolean);
  return parts.map((p, i) => {
    if (p.startsWith("**") && p.endsWith("**")) return <strong key={i}>{p.slice(2, -2)}</strong>;
    if (p.startsWith("*") && p.endsWith("*")) return <em key={i}>{p.slice(1, -1)}</em>;
    return <span key={i}>{p}</span>;
  });
}
function Markdown({ text }: { text: string }) {
  const blocks = text.trim().split(/\n\s*\n/);
  return (
    <div className="space-y-2.5 text-[0.95rem] leading-relaxed text-text">
      {blocks.map((b, i) => {
        const lines = b.split("\n");
        if (lines.every((l) => /^\s*-\s+/.test(l))) {
          return (
            <ul key={i} className="ml-1 space-y-1.5">
              {lines.map((l, j) => (
                <li key={j} className="flex gap-2">
                  <span className="mt-2 h-1.5 w-1.5 shrink-0 rounded-full bg-accent/60" />
                  <span>{inline(l.replace(/^\s*-\s+/, ""))}</span>
                </li>
              ))}
            </ul>
          );
        }
        if (lines.every((l) => /^\s*\d+\.\s+/.test(l))) {
          return (
            <ol key={i} className="ml-1 space-y-1.5">
              {lines.map((l, j) => (
                <li key={j} className="flex gap-2.5">
                  <span className="grid h-5 w-5 shrink-0 place-items-center rounded-full bg-accent/12 text-[0.72rem] font-bold text-accent">{j + 1}</span>
                  <span>{inline(l.replace(/^\s*\d+\.\s+/, ""))}</span>
                </li>
              ))}
            </ol>
          );
        }
        return <p key={i}>{inline(b)}</p>;
      })}
    </div>
  );
}

const CAPABILITIES = [
  { icon: "monitor", t: "Explains the pipeline", s: "How triage, plan, reason and verdict fit together" },
  { icon: "radar", t: "MITRE ATT&CK", s: "Look up techniques and how AEGIS detects them" },
  { icon: "response", t: "Response guidance", s: "Points to the right recommend-only playbook" },
  { icon: "shield", t: "Guardrail-aware", s: "Advisory only — never executes or attacks" },
] as const;

export default function AssistantPage() {
  const { user } = useAuth();
  const { data: sugg } = useSWR("/api/assistant/suggestions", () => assistant.suggestions());
  const [msgs, setMsgs] = useState<Msg[]>([]);
  const [input, setInput] = useState("");
  const [busy, setBusy] = useState(false);
  const endRef = useRef<HTMLDivElement>(null);

  useEffect(() => { endRef.current?.scrollIntoView({ behavior: "smooth" }); }, [msgs]);

  async function send(q: string) {
    const question = q.trim();
    if (!question || busy) return;
    setInput("");
    setBusy(true);
    setMsgs((m) => [...m, { role: "user", text: question }, { role: "typing" }]);
    try {
      const reply = await assistant.ask(question);
      setMsgs((m) => [...m.filter((x) => x.role !== "typing"), { role: "assistant", reply }]);
    } catch {
      setMsgs((m) => m.filter((x) => x.role !== "typing"));
    } finally {
      setBusy(false);
    }
  }

  const starters = sugg?.starters ?? [];
  const empty = msgs.length === 0;

  return (
    <div className="animate-rise">
      <PageHeader
        title="AI Copilot"
        subtitle="Ask about investigations, MITRE techniques, playbooks and guardrails — grounded in this deployment and fully offline"
        live
      />

      <div className="grid gap-5 lg:grid-cols-[1fr_18rem]">
        {/* chat column */}
        <Card className="flex h-[calc(100vh-13rem)] min-h-[26rem] flex-col overflow-hidden">
          <div className="flex-1 space-y-5 overflow-y-auto p-5 sm:p-6">
            {empty && (
              <div className="mx-auto flex max-w-md flex-col items-center pt-6 text-center">
                <span className="animate-floaty flex h-16 w-16 items-center justify-center rounded-3xl bg-accent text-white shadow-glow">
                  <Icon.spark className="h-9 w-9" />
                </span>
                <h2 className="mt-4 text-xl font-bold tracking-tight">How can I help, {user?.name?.split(" ")[0] ?? "analyst"}?</h2>
                <p className="mt-1.5 text-sm text-muted">I answer from AEGIS's own knowledge and always cite sources. Nothing leaves this machine.</p>
                <div className="mt-6 grid w-full gap-2 sm:grid-cols-2">
                  {starters.map((s) => (
                    <button key={s} onClick={() => send(s)}
                      className="rounded-2xl border border-border bg-surface-2 px-4 py-3 text-left text-sm font-medium text-text shadow-card transition hover:border-accent hover:shadow-float">
                      {s}
                    </button>
                  ))}
                </div>
              </div>
            )}

            {msgs.map((m, i) => {
              if (m.role === "user") {
                return (
                  <div key={i} className="flex justify-end">
                    <div className="max-w-[85%] rounded-2xl rounded-br-md bg-accent px-4 py-2.5 text-[0.95rem] font-medium text-white shadow-card">{m.text}</div>
                  </div>
                );
              }
              if (m.role === "typing") {
                return (
                  <div key={i} className="flex items-center gap-2 text-dim">
                    <Icon.spark className="h-5 w-5 text-accent" />
                    <span className="flex gap-1">
                      {[0, 1, 2].map((d) => <span key={d} className="live-dot h-2 w-2 rounded-full bg-accent/50" style={{ animationDelay: `${d * 0.2}s` }} />)}
                    </span>
                  </div>
                );
              }
              const r = m.reply;
              return (
                <div key={i} className="flex gap-3">
                  <span className="mt-0.5 grid h-8 w-8 shrink-0 place-items-center rounded-xl bg-accent/12 text-accent"><Icon.spark className="h-5 w-5" /></span>
                  <div className="min-w-0 flex-1 space-y-3">
                    {r.guardrail_notice && (
                      <div className="flex gap-2.5 rounded-2xl border border-warning/30 bg-warning/10 px-3.5 py-2.5 text-sm text-warning">
                        <Icon.shield className="mt-0.5 h-4 w-4 shrink-0" />
                        <span>{r.guardrail_notice}</span>
                      </div>
                    )}
                    <Markdown text={r.answer} />
                    {r.citations.length > 0 && (
                      <div className="flex flex-wrap items-center gap-1.5 pt-1">
                        <span className="text-[0.7rem] font-semibold uppercase tracking-wider text-dim">Sources</span>
                        {r.citations.map((c, j) => (
                          <span key={j} className="inline-flex items-center gap-1.5 rounded-full border border-border bg-surface-2 px-2.5 py-1 text-xs font-medium text-muted">
                            <Icon.book className="h-3.5 w-3.5 text-accent" /> {c.source} · {c.ref}
                          </span>
                        ))}
                      </div>
                    )}
                    {r.suggestions.length > 0 && (
                      <div className="flex flex-wrap gap-1.5 pt-1">
                        {r.suggestions.map((s) => (
                          <button key={s} onClick={() => send(s)}
                            className="rounded-full border border-accent/30 bg-accent/8 px-3 py-1.5 text-xs font-medium text-accent transition hover:bg-accent/15">
                            {s}
                          </button>
                        ))}
                      </div>
                    )}
                  </div>
                </div>
              );
            })}
            <div ref={endRef} />
          </div>

          {/* composer */}
          <div className="border-t border-border bg-surface-2/50 p-3">
            <form onSubmit={(e) => { e.preventDefault(); send(input); }} className="flex items-center gap-2">
              <input value={input} onChange={(e) => setInput(e.target.value)} placeholder="Ask the AEGIS Copilot…"
                className="flex-1 rounded-xl border border-border bg-surface px-4 py-3 text-[0.95rem] font-medium text-text placeholder:font-normal placeholder:text-dim outline-none transition focus:border-accent focus:ring-2 focus:ring-ring/25" />
              <button type="submit" disabled={busy || !input.trim()}
                className="grid h-11 w-11 shrink-0 place-items-center rounded-xl bg-accent text-white shadow-card transition hover:bg-accent-hover active:scale-95 disabled:opacity-40">
                <Icon.send className="h-5 w-5" />
              </button>
            </form>
            <p className="mt-2 px-1 text-center text-[0.7rem] text-dim">Advisory only · recommend-only · human-in-the-loop · runs offline</p>
          </div>
        </Card>

        {/* capabilities rail */}
        <div className="hidden lg:block">
          <SectionTitle>What it can do</SectionTitle>
          <div className="space-y-2.5">
            {CAPABILITIES.map((c) => {
              const Ico = Icon[c.icon];
              return (
                <Card key={c.t} className="p-3.5">
                  <span className="mb-2 flex h-8 w-8 items-center justify-center rounded-xl bg-accent/12 text-accent"><Ico className="h-4.5 w-4.5" /></span>
                  <div className="text-sm font-bold">{c.t}</div>
                  <div className="mt-0.5 text-xs text-muted">{c.s}</div>
                </Card>
              );
            })}
          </div>
        </div>
      </div>
    </div>
  );
}
