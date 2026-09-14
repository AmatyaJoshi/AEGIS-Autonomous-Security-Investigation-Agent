import "./globals.css";
import type { Metadata } from "next";
import { AuthProvider } from "@/components/auth";
import { Chrome } from "@/components/chrome";
import { themeScript } from "@/components/theme";

export const metadata: Metadata = {
  title: "AEGIS — Autonomous SOC",
  description: "Autonomous SOC investigation agent · Agentic AI for cloud security operations",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" suppressHydrationWarning>
      <head>
        <script dangerouslySetInnerHTML={{ __html: themeScript }} />
      </head>
      <body>
        <AuthProvider>
          <Chrome>{children}</Chrome>
        </AuthProvider>
      </body>
    </html>
  );
}
