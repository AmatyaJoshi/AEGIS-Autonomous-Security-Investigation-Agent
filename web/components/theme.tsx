"use client";
import { useEffect, useState } from "react";
import { Icon } from "./ui";

type Theme = "light" | "dark";

export function ThemeToggle() {
  const [theme, setTheme] = useState<Theme>("dark");
  useEffect(() => setTheme((localStorage.getItem("aegis-theme") as Theme | null) ?? "dark"), []);
  function apply(next: Theme) {
    setTheme(next);
    document.documentElement.setAttribute("data-theme", next);
    try { localStorage.setItem("aegis-theme", next); } catch { /* ignore */ }
  }
  return (
    <button
      onClick={() => apply(theme === "dark" ? "light" : "dark")}
      className="inline-flex h-9 w-9 items-center justify-center rounded-full border border-border bg-surface text-muted transition duration-200 ease-spring hover:text-text hover:border-border-strong active:scale-95"
      title={theme === "dark" ? "Switch to light" : "Switch to dark"}
      aria-label="Toggle theme"
    >
      {theme === "dark" ? <Icon.sun className="h-[18px] w-[18px]" /> : <Icon.moon className="h-[18px] w-[18px]" />}
    </button>
  );
}

export const themeScript = `(function(){try{var t=localStorage.getItem('aegis-theme')||'dark';document.documentElement.setAttribute('data-theme',t);}catch(e){document.documentElement.setAttribute('data-theme','dark');}})();`;
