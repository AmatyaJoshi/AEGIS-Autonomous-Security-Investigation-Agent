import "./globals.css";
import type { Metadata } from "next";
import Link from "next/link";

export const metadata: Metadata = {
  title: "AEGIS Review",
  description: "Autonomous SOC investigation review queue",
};

const NAV = [
  { href: "/", label: "Queue" },
  { href: "/labels", label: "Labels" },
  { href: "/metrics", label: "Metrics" },
];

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>
        <header className="border-b border-slate-800 px-6 py-3 flex items-center gap-6">
          <span className="font-semibold text-sky-400">AEGIS</span>
          <nav className="flex gap-4 text-sm">
            {NAV.map((n) => (
              <Link key={n.href} href={n.href} className="text-slate-300 hover:text-white">
                {n.label}
              </Link>
            ))}
          </nav>
          <span className="ml-auto text-xs text-slate-500">recommend-only · human-in-the-loop</span>
        </header>
        <main className="max-w-6xl mx-auto px-6 py-6">{children}</main>
      </body>
    </html>
  );
}
