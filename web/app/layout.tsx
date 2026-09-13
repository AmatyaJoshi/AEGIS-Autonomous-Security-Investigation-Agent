import "./globals.css";
import type { Metadata } from "next";
import Link from "next/link";
import { ThemeToggle, themeScript } from "@/components/theme";
import { Icon } from "@/components/ui";

export const metadata: Metadata = {
  title: "AEGIS — SOC Investigation",
  description: "Autonomous SOC investigation agent · review console",
};

const NAV = [
  { href: "/", label: "Queue", icon: Icon.queue },
  { href: "/labels", label: "Labels", icon: Icon.tag },
  { href: "/metrics", label: "Metrics", icon: Icon.chart },
];

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" suppressHydrationWarning>
      <head>
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link rel="preconnect" href="https://fonts.gstatic.com" crossOrigin="anonymous" />
        <link
          href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;650;700&display=swap"
          rel="stylesheet"
        />
        <script dangerouslySetInnerHTML={{ __html: themeScript }} />
      </head>
      <body>
        <div className="relative z-10 flex min-h-screen">
          {/* sidebar */}
          <aside className="sticky top-0 hidden h-screen w-60 shrink-0 flex-col border-r border-border bg-surface/80 backdrop-blur md:flex">
            <div className="flex items-center gap-2.5 px-5 py-5">
              <span className="flex h-9 w-9 items-center justify-center rounded-lg bg-accent/10 text-accent">
                <Icon.shield className="h-6 w-6" />
              </span>
              <div className="leading-tight">
                <div className="text-[15px] font-semibold tracking-tight">AEGIS</div>
                <div className="text-[11px] text-dim">SOC Investigation</div>
              </div>
            </div>

            <nav className="flex flex-col gap-1 px-3 py-2">
              {NAV.map((n) => (
                <Link
                  key={n.href}
                  href={n.href}
                  className="group flex items-center gap-3 rounded-lg px-3 py-2 text-sm font-medium text-muted transition hover:bg-surface-2 hover:text-text"
                >
                  <n.icon className="h-[18px] w-[18px] text-dim group-hover:text-accent" />
                  {n.label}
                </Link>
              ))}
            </nav>

            <div className="mt-auto px-4 py-4">
              <div className="rounded-lg border border-border bg-surface-2 p-3">
                <div className="flex items-center gap-1.5 text-xs font-semibold text-success">
                  <span className="h-1.5 w-1.5 rounded-full bg-success" /> Recommend-only
                </div>
                <p className="mt-1 text-[11px] leading-relaxed text-dim">
                  AEGIS never executes containment. Every action is a human decision.
                </p>
              </div>
            </div>
          </aside>

          {/* main */}
          <div className="flex min-w-0 flex-1 flex-col">
            <header className="sticky top-0 z-20 flex items-center gap-3 border-b border-border bg-surface/70 px-6 py-3 backdrop-blur">
              <Link href="/" className="flex items-center gap-2 md:hidden">
                <Icon.shield className="h-5 w-5 text-accent" />
                <span className="font-semibold">AEGIS</span>
              </Link>
              <div className="ml-auto flex items-center gap-3">
                <span className="hidden text-xs text-dim sm:inline">Human-in-the-loop L1/L2 triage</span>
                <ThemeToggle />
              </div>
            </header>
            <main className="mx-auto w-full max-w-[1200px] flex-1 px-6 py-7">{children}</main>
          </div>
        </div>
      </body>
    </html>
  );
}
