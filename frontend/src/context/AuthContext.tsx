"use client";

import { createContext, useContext, useEffect, useState, ReactNode } from "react";
import { API_BASE, getAccessToken, setAccessToken, clearTokens, decodeUser, DecodedUser } from "@/lib/auth";

interface LoginResult {
  mfaRequired?: boolean;
  mfaToken?: string;
}

interface AuthContextValue {
  user: DecodedUser | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  login: (email: string, password: string) => Promise<LoginResult>;
  verifyMfa: (mfaToken: string, code: string) => Promise<void>;
  logout: () => Promise<void>;
  refreshAuth: () => Promise<boolean>;
}

const AuthContext = createContext<AuthContextValue | undefined>(undefined);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<DecodedUser | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  const refreshAuth = async (): Promise<boolean> => {
    try {
      const res = await fetch(`${API_BASE}/api/v1/auth/refresh`, {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({}),
      });

      if (res.ok) {
        const data = await res.json();
        setAccessToken(data.access_token);
        setUser(decodeUser(data.access_token));
        return true;
      } else {
        clearTokens();
        setUser(null);
        return false;
      }
    } catch {
      clearTokens();
      setUser(null);
      return false;
    }
  };

  useEffect(() => {
    let cancelled = false;

    (async () => {
      const token = getAccessToken();
      const decoded = token ? decodeUser(token) : null;

      if (decoded) {
        if (!cancelled) {
          setUser(decoded);
          setIsLoading(false);
        }
        return;
      }

      // Initial page load attempt via HttpOnly cookie
      try {
        const res = await fetch(`${API_BASE}/api/v1/auth/refresh`, {
          method: "POST",
          credentials: "include",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({}),
        });

        if (res.ok) {
          const data = await res.json();
          setAccessToken(data.access_token);
          if (!cancelled) setUser(decodeUser(data.access_token));
        } else {
          clearTokens();
          if (!cancelled) setUser(null);
        }
      } catch {
        clearTokens();
        if (!cancelled) setUser(null);
      }

      if (!cancelled) setIsLoading(false);
    })();

    return () => {
      cancelled = true;
    };
  }, []);

  const login = async (email: string, password: string): Promise<LoginResult> => {
    const res = await fetch(`${API_BASE}/api/v1/auth/login`, {
      method: "POST",
      credentials: "include",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, password }),
    });

    if (!res.ok) {
      const body = await res.json().catch(() => ({}));
      if (typeof body.detail === "string" && body.detail) {
        throw new Error(body.detail);
      }
      throw new Error(
        res.status === 422 && Array.isArray(body.detail)
          ? "Invalid email or password format"
          : "Login failed"
      );
    }

    const data = await res.json();
    if (data.mfa_required) {
      return { mfaRequired: true, mfaToken: data.mfa_token };
    }

    setAccessToken(data.access_token);
    setUser(decodeUser(data.access_token));
    return { mfaRequired: false };
  };

  const verifyMfa = async (mfaToken: string, code: string) => {
    const res = await fetch(`${API_BASE}/api/v1/auth/mfa/challenge`, {
      method: "POST",
      credentials: "include",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ mfa_token: mfaToken, code }),
    });

    if (!res.ok) {
      const body = await res.json().catch(() => ({}));
      throw new Error(body.detail || "MFA verification failed");
    }

    const data = await res.json();
    setAccessToken(data.access_token);
    setUser(decodeUser(data.access_token));
  };

  const logout = async () => {
    try {
      await fetch(`${API_BASE}/api/v1/auth/logout`, {
        method: "POST",
        credentials: "include",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({}),
      });
    } catch {
      // Best-effort
    }
    clearTokens();
    setUser(null);
    if (typeof window !== "undefined") {
      window.location.replace("/login");
    }
  };

  return (
    <AuthContext.Provider
      value={{
        user,
        isAuthenticated: !!user,
        isLoading,
        login,
        verifyMfa,
        logout,
        refreshAuth,
      }}
    >
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error("useAuth must be used within an AuthProvider");
  }
  return context;
}
