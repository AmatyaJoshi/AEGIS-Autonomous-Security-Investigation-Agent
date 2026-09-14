import type { Config } from "tailwindcss";

const v = (name: string) => `rgb(var(--${name}) / <alpha-value>)`;

export default {
  darkMode: ["class", '[data-theme="dark"]'],
  content: ["./app/**/*.{ts,tsx}", "./components/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        bg: v("bg"), "bg-2": v("bg-2"), surface: v("surface"), "surface-2": v("surface-2"),
        elevated: v("elevated"), border: v("border"), "border-strong": v("border-strong"),
        text: v("text"), muted: v("text-muted"), dim: v("text-dim"),
        accent: v("accent"), "accent-hover": v("accent-hover"), "accent-soft": v("accent-soft"),
        critical: v("critical"), high: v("high"), medium: v("medium"), low: v("low"),
        info: v("info"), success: v("success"), danger: v("danger"), warning: v("warning"),
      },
      borderRadius: { lg: "0.7rem", xl: "0.95rem", "2xl": "1.25rem", "3xl": "1.6rem" },
      boxShadow: {
        card: "0 1px 1px rgb(var(--shadow) / calc(var(--shadow-strength) * 0.6)), 0 6px 20px -8px rgb(var(--shadow) / var(--shadow-strength))",
        float: "0 2px 4px rgb(var(--shadow) / calc(var(--shadow-strength) * 0.5)), 0 18px 44px -16px rgb(var(--shadow) / calc(var(--shadow-strength) * 1.6))",
        glow: "0 0 0 1px rgb(var(--accent) / 0.35), 0 8px 30px -8px rgb(var(--accent) / 0.45)",
      },
      fontSize: {
        xs: ["0.8rem", { lineHeight: "1.1rem", letterSpacing: "-0.006em" }],
        sm: ["0.9rem", { lineHeight: "1.35rem", letterSpacing: "-0.01em" }],
        base: ["1rem", { lineHeight: "1.6rem", letterSpacing: "-0.014em" }],
        lg: ["1.15rem", { lineHeight: "1.65rem", letterSpacing: "-0.018em" }],
        xl: ["1.45rem", { lineHeight: "1.9rem", letterSpacing: "-0.022em" }],
        "2xl": ["1.9rem", { lineHeight: "2.2rem", letterSpacing: "-0.026em" }],
        "3xl": ["2.4rem", { lineHeight: "2.6rem", letterSpacing: "-0.03em" }],
      },
      transitionTimingFunction: { spring: "cubic-bezier(.22,1,.36,1)" },
    },
  },
  plugins: [],
} satisfies Config;
