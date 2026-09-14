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
        <link rel="preconnect" href="https://fonts.googleapis.com" />
        <link rel="preconnect" href="https://fonts.gstatic.com" crossOrigin="anonymous" />
        <link
          href="https://fonts.googleapis.com/css2?family=Inter:opsz,wght@14..32,300..700&display=swap"
          rel="stylesheet"
        />
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
