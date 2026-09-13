import type { Config } from "tailwindcss";

const withVar = (v: string) => `rgb(var(--${v}) / <alpha-value>)`;

export default {
  darkMode: ["class", '[data-theme="dark"]'],
  content: ["./app/**/*.{ts,tsx}", "./components/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        bg: withVar("bg"),
        surface: withVar("surface"),
        "surface-2": withVar("surface-2"),
        elevated: withVar("elevated"),
        border: withVar("border"),
        "border-strong": withVar("border-strong"),
        text: withVar("text"),
        muted: withVar("text-muted"),
        dim: withVar("text-dim"),
        accent: withVar("accent"),
        "accent-hover": withVar("accent-hover"),
        "accent-soft": withVar("accent-soft"),
        critical: withVar("critical"),
        high: withVar("high"),
        medium: withVar("medium"),
        low: withVar("low"),
        info: withVar("info"),
        success: withVar("success"),
        danger: withVar("danger"),
        warning: withVar("warning"),
      },
      borderRadius: { xl: "0.75rem", "2xl": "1rem" },
      boxShadow: {
        card: "0 1px 2px rgb(var(--shadow) / var(--shadow-strength)), 0 1px 3px rgb(var(--shadow) / calc(var(--shadow-strength) * 0.7))",
        pop: "0 10px 30px -10px rgb(var(--shadow) / calc(var(--shadow-strength) * 2))",
      },
      fontSize: {
        xs: ["0.78rem", { lineHeight: "1.1rem" }],
        sm: ["0.875rem", { lineHeight: "1.3rem" }],
        base: ["0.975rem", { lineHeight: "1.55rem" }],
        lg: ["1.1rem", { lineHeight: "1.6rem" }],
        xl: ["1.375rem", { lineHeight: "1.85rem" }],
        "2xl": ["1.75rem", { lineHeight: "2.1rem" }],
        "3xl": ["2.15rem", { lineHeight: "2.4rem" }],
      },
    },
  },
  plugins: [],
} satisfies Config;
