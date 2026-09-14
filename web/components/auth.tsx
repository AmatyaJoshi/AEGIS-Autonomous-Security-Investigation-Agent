"use client";
import { createContext, useContext, useEffect, useState } from "react";
import { auth as authApi, type User } from "@/lib/api";

interface AuthCtx {
  user: User | null;
  loading: boolean;
  login: (email: string, password: string) => Promise<void>;
  signup: (email: string, name: string, password: string, role: string) => Promise<void>;
  logout: () => void;
  has: (perm: string) => boolean;
}

const Ctx = createContext<AuthCtx | null>(null);

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [user, setUser] = useState<User | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const t = (() => { try { return localStorage.getItem("aegis-token"); } catch { return null; } })();
    if (!t) { setLoading(false); return; }
    authApi.me().then(setUser).catch(() => { try { localStorage.removeItem("aegis-token"); } catch { /* */ } }).finally(() => setLoading(false));
  }, []);

  async function login(email: string, password: string) {
    const { token, user } = await authApi.login(email, password);
    localStorage.setItem("aegis-token", token);
    setUser(user);
  }
  async function signup(email: string, name: string, password: string, role: string) {
    const { token, user } = await authApi.signup(email, name, password, role);
    localStorage.setItem("aegis-token", token);
    setUser(user);
  }
  function logout() {
    try { localStorage.removeItem("aegis-token"); } catch { /* */ }
    setUser(null);
    location.href = "/login";
  }
  const has = (perm: string) => !!user?.permissions.includes(perm);

  return <Ctx.Provider value={{ user, loading, login, signup, logout, has }}>{children}</Ctx.Provider>;
}

export function useAuth() {
  const c = useContext(Ctx);
  if (!c) throw new Error("useAuth outside AuthProvider");
  return c;
}
