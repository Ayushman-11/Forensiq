# Frontend Auth + RBAC Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Wire the Next.js frontend into the backend's JWT auth (shipped in PR #1 / branch `jwt-auth-rbac`) — a login page, token storage with auto-refresh, route protection, and a role badge (SOC L1 / SOC Manager / Splunk Admin) in the header.

**Architecture:** A `lib/` layer (`auth.ts` for token storage/decoding, `api.ts` for an authenticated fetch wrapper, `roles.ts` for role→label mapping) backs a React `AuthContext` provider and an `AuthGuard` client component that redirects unauthenticated visitors to a new standalone `/login` route. `AppLayout` skips its sidebar chrome on `/login` and gains a user menu. The three existing pages swap their hardcoded `fetch('http://localhost:8001/...')` calls for the new `apiFetch()`.

**Tech Stack:** Next.js 16 (App Router), React 19, TypeScript, no test runner (frontend has none installed — verification is manual, see Task 8).

**Spec:** `docs/superpowers/specs/2026-08-19-frontend-auth-rbac-design.md`

## Global Constraints

- No backend changes. Backend role values (`soc_analyst`/`soc_manager`/`admin`) are unchanged; only the frontend maps them to display labels (SOC L1 / SOC Manager / Splunk Admin).
- Tokens live in `localStorage` (not httpOnly cookies) — the backend returns them in the JSON response body and sets no cookies.
- The frontend never verifies JWT signatures or uses the decoded payload for authorization — decoding is display-only (email/role in the header). All real authorization stays server-side, already shipped.
- No automated tests exist for the frontend (no Jest/Vitest/Playwright in `package.json`) and adding one is out of scope. Each task's correctness gate is `npx tsc --noEmit` (TypeScript's own compiler, using the existing `tsconfig.json`) plus, where noted, manual verification against a running dev server. Full end-to-end manual QA happens in Task 8.
- Use the `@/*` → `./src/*` path alias (already configured in `frontend/tsconfig.json`) for all new imports, matching existing files' import style (e.g. `@/components/AppLayout`).
- Match the existing dark theme palette used throughout the app: background `#0e0e0e`, surface `#141414`, borders `#2a2a2a`/`#383838`, text `#f0f0f0`/`#888888`, accent `#FF1E56`. Don't invent new colors.
- This is a Next.js `"use client"` codebase for all interactive pages/components — every new component that uses hooks or browser APIs needs the `"use client"` directive at the top of the file, matching the existing pages' pattern.

---

### Task 1: Role labels + token storage

**Files:**
- Create: `frontend/src/lib/roles.ts`
- Create: `frontend/src/lib/auth.ts`

**Interfaces:**
- Produces: `ROLE_LABELS: Record<string, string>`, `roleLabel(role: string): string` (from `roles.ts`).
- Produces: `API_BASE: string`, `getAccessToken(): string | null`, `getRefreshToken(): string | null`, `setTokens(access: string, refresh: string): void`, `clearTokens(): void`, `interface DecodedUser { email: string; role: string; sub: string }`, `decodeUser(accessToken: string): DecodedUser | null` (from `auth.ts`). Consumed by Task 2 (`api.ts`), Task 3 (`AuthContext.tsx`), Task 6 (`AppLayout.tsx`).

- [ ] **Step 1: Create `frontend/src/lib/roles.ts`**

```typescript
export const ROLE_LABELS: Record<string, string> = {
  soc_analyst: "SOC L1",
  soc_manager: "SOC Manager",
  admin: "Splunk Admin",
};

export function roleLabel(role: string): string {
  return ROLE_LABELS[role] ?? role;
}
```

- [ ] **Step 2: Create `frontend/src/lib/auth.ts`**

```typescript
export const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8001";

const ACCESS_TOKEN_KEY = "forensiq_access_token";
const REFRESH_TOKEN_KEY = "forensiq_refresh_token";

export function getAccessToken(): string | null {
  if (typeof window === "undefined") return null;
  return window.localStorage.getItem(ACCESS_TOKEN_KEY);
}

export function getRefreshToken(): string | null {
  if (typeof window === "undefined") return null;
  return window.localStorage.getItem(REFRESH_TOKEN_KEY);
}

export function setTokens(access: string, refresh: string): void {
  if (typeof window === "undefined") return;
  window.localStorage.setItem(ACCESS_TOKEN_KEY, access);
  window.localStorage.setItem(REFRESH_TOKEN_KEY, refresh);
}

export function clearTokens(): void {
  if (typeof window === "undefined") return;
  window.localStorage.removeItem(ACCESS_TOKEN_KEY);
  window.localStorage.removeItem(REFRESH_TOKEN_KEY);
}

export interface DecodedUser {
  email: string;
  role: string;
  sub: string;
}

export function decodeUser(accessToken: string): DecodedUser | null {
  try {
    const payloadSegment = accessToken.split(".")[1];
    if (!payloadSegment) return null;
    const base64 = payloadSegment.replace(/-/g, "+").replace(/_/g, "/");
    const json = JSON.parse(atob(base64));
    if (typeof json.email !== "string" || typeof json.role !== "string" || typeof json.sub !== "string") {
      return null;
    }
    return { email: json.email, role: json.role, sub: json.sub };
  } catch {
    return null;
  }
}
```

- [ ] **Step 3: Type-check**

Run: `cd frontend && npx tsc --noEmit`
Expected: no errors.

- [ ] **Step 4: Commit**

```bash
git add frontend/src/lib/roles.ts frontend/src/lib/auth.ts
git commit -m "feat(frontend-auth): add role labels and token storage helpers"
```

---

### Task 2: Authenticated fetch wrapper with auto-refresh

**Files:**
- Create: `frontend/src/lib/api.ts`

**Interfaces:**
- Consumes: `API_BASE`, `getAccessToken`, `getRefreshToken`, `setTokens`, `clearTokens` from `frontend/src/lib/auth.ts` (Task 1).
- Produces: `apiFetch(path: string, options?: RequestInit): Promise<Response>`. Consumed by Task 8 (replacing the pages' raw `fetch()` calls).

- [ ] **Step 1: Create `frontend/src/lib/api.ts`**

```typescript
import { API_BASE, getAccessToken, getRefreshToken, setTokens, clearTokens } from "./auth";

async function tryRefresh(): Promise<boolean> {
  const refresh_token = getRefreshToken();
  if (!refresh_token) return false;

  try {
    const res = await fetch(`${API_BASE}/api/v1/auth/refresh`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ refresh_token }),
    });
    if (!res.ok) return false;
    const data = await res.json();
    setTokens(data.access_token, data.refresh_token);
    return true;
  } catch {
    return false;
  }
}

export async function apiFetch(path: string, options: RequestInit = {}): Promise<Response> {
  const access = getAccessToken();
  const headers = new Headers(options.headers);
  if (access) headers.set("Authorization", `Bearer ${access}`);

  let res = await fetch(`${API_BASE}${path}`, { ...options, headers });

  if (res.status === 401 && getRefreshToken()) {
    const refreshed = await tryRefresh();
    if (refreshed) {
      const retryHeaders = new Headers(options.headers);
      const newAccess = getAccessToken();
      if (newAccess) retryHeaders.set("Authorization", `Bearer ${newAccess}`);
      res = await fetch(`${API_BASE}${path}`, { ...options, headers: retryHeaders });
    } else {
      clearTokens();
      if (typeof window !== "undefined") window.location.href = "/login";
    }
  }

  return res;
}
```

This is a single-retry interceptor: on a 401, it tries exactly one refresh-and-retry. If the retried request is itself a 401, that response is returned as-is (no infinite loop) and the caller's existing `!res.ok` handling shows an error — matching the design's "single retry" behavior.

- [ ] **Step 2: Type-check**

Run: `cd frontend && npx tsc --noEmit`
Expected: no errors.

- [ ] **Step 3: Commit**

```bash
git add frontend/src/lib/api.ts
git commit -m "feat(frontend-auth): add apiFetch wrapper with single-retry token refresh"
```

---

### Task 3: AuthContext (login/logout/user state)

**Files:**
- Create: `frontend/src/context/AuthContext.tsx`

**Interfaces:**
- Consumes: `API_BASE`, `getAccessToken`, `getRefreshToken`, `setTokens`, `clearTokens`, `decodeUser`, `DecodedUser` from `frontend/src/lib/auth.ts` (Task 1).
- Produces: `AuthProvider({ children }): JSX.Element`, `useAuth(): { user: DecodedUser | null; isAuthenticated: boolean; isLoading: boolean; login(email: string, password: string): Promise<void>; logout(): Promise<void> }`. Consumed by Task 4 (`AuthGuard`), Task 5 (`login/page.tsx`), Task 6 (`AppLayout.tsx`), Task 7 (`layout.tsx`).

- [ ] **Step 1: Create `frontend/src/context/AuthContext.tsx`**

```tsx
"use client";

import { createContext, useContext, useEffect, useState, ReactNode } from "react";
import { API_BASE, getAccessToken, getRefreshToken, setTokens, clearTokens, decodeUser, DecodedUser } from "@/lib/auth";

interface AuthContextValue {
  user: DecodedUser | null;
  isAuthenticated: boolean;
  isLoading: boolean;
  login: (email: string, password: string) => Promise<void>;
  logout: () => Promise<void>;
}

const AuthContext = createContext<AuthContextValue | undefined>(undefined);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [user, setUser] = useState<DecodedUser | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  useEffect(() => {
    const token = getAccessToken();
    if (token) {
      setUser(decodeUser(token));
    }
    setIsLoading(false);
  }, []);

  const login = async (email: string, password: string) => {
    const res = await fetch(`${API_BASE}/api/v1/auth/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ email, password }),
    });

    if (!res.ok) {
      const body = await res.json().catch(() => ({}));
      throw new Error(body.detail || "Login failed");
    }

    const data = await res.json();
    setTokens(data.access_token, data.refresh_token);
    setUser(decodeUser(data.access_token));
  };

  const logout = async () => {
    const refresh_token = getRefreshToken();
    if (refresh_token) {
      try {
        await fetch(`${API_BASE}/api/v1/auth/logout`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ refresh_token }),
        });
      } catch {
        // best-effort: logout must always succeed locally regardless of network state
      }
    }
    clearTokens();
    setUser(null);
  };

  return (
    <AuthContext.Provider value={{ user, isAuthenticated: !!user, isLoading, login, logout }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) {
    throw new Error("useAuth must be used within an AuthProvider");
  }
  return ctx;
}
```

- [ ] **Step 2: Type-check**

Run: `cd frontend && npx tsc --noEmit`
Expected: no errors.

- [ ] **Step 3: Commit**

```bash
git add frontend/src/context/AuthContext.tsx
git commit -m "feat(frontend-auth): add AuthContext with login/logout/user state"
```

---

### Task 4: AuthGuard (route protection)

**Files:**
- Create: `frontend/src/components/AuthGuard.tsx`

**Interfaces:**
- Consumes: `useAuth` from `frontend/src/context/AuthContext.tsx` (Task 3).
- Produces: `AuthGuard({ children }): JSX.Element | null`. Consumed by Task 7 (`layout.tsx`).

- [ ] **Step 1: Create `frontend/src/components/AuthGuard.tsx`**

```tsx
"use client";

import { useEffect } from "react";
import { useRouter, usePathname } from "next/navigation";
import { useAuth } from "@/context/AuthContext";

const PUBLIC_PATHS = ["/login"];

export default function AuthGuard({ children }: { children: React.ReactNode }) {
  const { isAuthenticated, isLoading } = useAuth();
  const router = useRouter();
  const pathname = usePathname();
  const isPublicPath = PUBLIC_PATHS.includes(pathname);

  useEffect(() => {
    if (isLoading) return;
    if (!isAuthenticated && !isPublicPath) {
      router.replace(`/login?redirect=${encodeURIComponent(pathname)}`);
    }
  }, [isLoading, isAuthenticated, isPublicPath, pathname, router]);

  if (isLoading) {
    return (
      <div className="h-screen w-screen flex items-center justify-center bg-[#0e0e0e]">
        <div className="w-6 h-6 border-2 border-[#888888] border-t-transparent rounded-full animate-spin" />
      </div>
    );
  }

  if (!isAuthenticated && !isPublicPath) {
    return null;
  }

  return <>{children}</>;
}
```

The `isLoading` check prevents redirecting before `AuthContext`'s initial `localStorage` read completes (avoids a flash-redirect on first render). The `!isAuthenticated && !isPublicPath` return-`null` avoids flashing protected content while the redirect effect is in flight.

- [ ] **Step 2: Type-check**

Run: `cd frontend && npx tsc --noEmit`
Expected: no errors.

- [ ] **Step 3: Commit**

```bash
git add frontend/src/components/AuthGuard.tsx
git commit -m "feat(frontend-auth): add AuthGuard route protection component"
```

---

### Task 5: Login page

**Files:**
- Create: `frontend/src/app/login/page.tsx`

**Interfaces:**
- Consumes: `useAuth` from `frontend/src/context/AuthContext.tsx` (Task 3).
- Produces: the `/login` route. No other task consumes this directly (it's a leaf route), but Task 6's `AppLayout` special-cases the `/login` pathname to skip chrome around it.

- [ ] **Step 1: Create `frontend/src/app/login/page.tsx`**

```tsx
"use client";

import { useState, Suspense, FormEvent } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { useAuth } from "@/context/AuthContext";
import { Loader2, ShieldCheck } from "lucide-react";

function LoginForm() {
  const { login } = useAuth();
  const router = useRouter();
  const searchParams = useSearchParams();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    setLoading(true);
    try {
      await login(email, password);
      const redirect = searchParams.get("redirect") || "/";
      router.replace(redirect);
    } catch (err: any) {
      setError(err.message || "Login failed");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="h-screen w-screen flex items-center justify-center bg-[#0e0e0e]">
      <div className="w-full max-w-sm bg-[#141414] border border-[#2a2a2a] rounded-lg p-8 flex flex-col gap-6">
        <div className="flex flex-col items-center gap-2">
          <ShieldCheck className="w-8 h-8 text-[#FF1E56]" />
          <h1 className="text-xl font-bold text-white tracking-tight">Forensiq</h1>
          <p className="text-[10px] text-[#888888] uppercase tracking-widest font-bold">
            AI Security Ops Sign In
          </p>
        </div>
        <form onSubmit={handleSubmit} className="flex flex-col gap-4">
          <div className="flex flex-col gap-1.5">
            <label className="text-[10px] text-[#888888] uppercase tracking-widest font-bold">
              Email
            </label>
            <input
              type="email"
              required
              value={email}
              onChange={(e) => setEmail(e.target.value)}
              className="bg-[#0e0e0e] border border-[#2a2a2a] rounded px-3 py-2 text-sm text-[#f0f0f0] outline-none focus:border-[#383838]"
            />
          </div>
          <div className="flex flex-col gap-1.5">
            <label className="text-[10px] text-[#888888] uppercase tracking-widest font-bold">
              Password
            </label>
            <input
              type="password"
              required
              value={password}
              onChange={(e) => setPassword(e.target.value)}
              className="bg-[#0e0e0e] border border-[#2a2a2a] rounded px-3 py-2 text-sm text-[#f0f0f0] outline-none focus:border-[#383838]"
            />
          </div>
          {error && (
            <div className="bg-[#FF1E56]/10 text-[#FF1E56] border border-[#FF1E56]/30 rounded px-3 py-2 text-xs font-bold">
              {error}
            </div>
          )}
          <button
            type="submit"
            disabled={loading}
            className="bg-[#FF1E56] text-white hover:bg-[#FF1E56]/90 disabled:opacity-50 transition-all rounded py-2.5 flex items-center justify-center gap-2 font-bold text-[11px] uppercase tracking-widest cursor-pointer"
          >
            {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : null}
            {loading ? "Signing in" : "Sign In"}
          </button>
        </form>
      </div>
    </div>
  );
}

export default function LoginPage() {
  return (
    <Suspense fallback={null}>
      <LoginForm />
    </Suspense>
  );
}
```

The `Suspense` boundary around `LoginForm` is required by Next.js App Router because `useSearchParams()` opts the component into client-side-only rendering — without it, `next build` fails with a "useSearchParams should be wrapped in a suspense boundary" error.

- [ ] **Step 2: Type-check**

Run: `cd frontend && npx tsc --noEmit`
Expected: no errors.

- [ ] **Step 3: Commit**

```bash
git add frontend/src/app/login/page.tsx
git commit -m "feat(frontend-auth): add login page"
```

---

### Task 6: AppLayout — skip chrome on /login, add user menu

**Files:**
- Modify: `frontend/src/components/AppLayout.tsx`

**Interfaces:**
- Consumes: `useAuth` from `frontend/src/context/AuthContext.tsx` (Task 3), `roleLabel` from `frontend/src/lib/roles.ts` (Task 1).

- [ ] **Step 1: Add imports and pathname short-circuit**

In `frontend/src/components/AppLayout.tsx`, add to the top imports (after the existing `lucide-react` import block):

```tsx
import { useAuth } from "@/context/AuthContext";
import { roleLabel } from "@/lib/roles";
```

Change the function body's opening (currently `const [isSidebarMinimized, setIsSidebarMinimized] = useState(false); const pathname = usePathname();`) to:

```tsx
export default function AppLayout({ children }: { children: React.ReactNode }) {
  const [isSidebarMinimized, setIsSidebarMinimized] = useState(false);
  const [isUserMenuOpen, setIsUserMenuOpen] = useState(false);
  const pathname = usePathname();
  const { user, logout } = useAuth();

  if (pathname === "/login") {
    return <>{children}</>;
  }

  const navItems = [
```

(i.e. insert the `isUserMenuOpen` state, the `useAuth()` call, and the early-return block; the existing `const navItems = [...]` line and everything below it stays as-is.)

- [ ] **Step 2: Replace the Account button with a user menu**

Find this block (the last button in the header's right-hand icon group):

```tsx
            <button aria-label="Account" className="text-[#888888] hover:text-[#f0f0f0] transition-all h-8 w-8 rounded flex items-center justify-center hover:bg-[#1c1c1c] cursor-pointer ml-1">
              <UserCircle className="w-5 h-5" />
            </button>
```

Replace it with:

```tsx
            <div className="relative">
              <button
                aria-label="Account"
                onClick={() => setIsUserMenuOpen((v) => !v)}
                className="text-[#888888] hover:text-[#f0f0f0] transition-all h-8 w-8 rounded flex items-center justify-center hover:bg-[#1c1c1c] cursor-pointer ml-1"
              >
                <UserCircle className="w-5 h-5" />
              </button>
              <AnimatePresence>
                {isUserMenuOpen && (
                  <motion.div
                    initial={{ opacity: 0, y: -8 }}
                    animate={{ opacity: 1, y: 0 }}
                    exit={{ opacity: 0, y: -8 }}
                    className="absolute right-0 top-10 w-56 bg-[#141414] border border-[#2a2a2a] rounded-lg shadow-lg p-3 flex flex-col gap-2 z-50"
                  >
                    <div className="flex flex-col gap-0.5 pb-2 border-b border-[#2a2a2a]">
                      <span className="text-[13px] font-bold text-[#f0f0f0] truncate">
                        {user?.email}
                      </span>
                      <span className="text-[10px] text-[#888888] uppercase tracking-widest font-bold">
                        {user ? roleLabel(user.role) : ""}
                      </span>
                    </div>
                    <button
                      onClick={() => {
                        setIsUserMenuOpen(false);
                        logout();
                      }}
                      className="text-left text-[12px] font-bold text-[#888888] hover:text-[#FF1E56] transition-colors py-1 cursor-pointer"
                    >
                      Logout
                    </button>
                  </motion.div>
                )}
              </AnimatePresence>
            </div>
```

`logout()` doesn't need to navigate itself — clearing auth state makes `AuthGuard` (Task 4, wired in Task 7) detect `isAuthenticated=false` on the next render and redirect to `/login` automatically.

- [ ] **Step 2: Type-check**

Run: `cd frontend && npx tsc --noEmit`
Expected: no errors.

- [ ] **Step 3: Commit**

```bash
git add frontend/src/components/AppLayout.tsx
git commit -m "feat(frontend-auth): skip chrome on /login, add user menu with role badge and logout"
```

---

### Task 7: Wire providers into the root layout, add env files

**Files:**
- Modify: `frontend/src/app/layout.tsx`
- Modify: `frontend/.gitignore`
- Create: `frontend/.env.example`
- Create: `frontend/.env.local` (untracked — for your own local dev)

**Interfaces:**
- Consumes: `AuthProvider` from `frontend/src/context/AuthContext.tsx` (Task 3), `AuthGuard` from `frontend/src/components/AuthGuard.tsx` (Task 4).

This is the task where the app actually becomes protected end-to-end — after this task, every page requires login.

- [ ] **Step 1: Fix `frontend/.gitignore` to allow committing `.env.example`**

The current `frontend/.gitignore` has:

```
# env files (can opt-in for committing if needed)
.env*
```

This pattern also matches `.env.example`, which we want committed as a template. Change it to:

```
# env files (can opt-in for committing if needed)
.env*
!.env.example
```

- [ ] **Step 2: Create `frontend/.env.example`**

```
NEXT_PUBLIC_API_URL=http://localhost:8001
```

- [ ] **Step 3: Create `frontend/.env.local`** (this file is gitignored — it's your personal local config, not committed)

```
NEXT_PUBLIC_API_URL=http://localhost:8001
```

- [ ] **Step 4: Wire `AuthProvider` and `AuthGuard` into the root layout**

In `frontend/src/app/layout.tsx`, add imports after the existing `AppLayout` import:

```tsx
import AppLayout from "@/components/AppLayout";
import { AuthProvider } from "@/context/AuthContext";
import AuthGuard from "@/components/AuthGuard";
import "./globals.css";
```

Change the `<body>` contents from:

```tsx
      <body className="min-h-screen overflow-x-hidden selection:bg-primary-container selection:text-on-primary-container bg-background text-on-surface flex">
        <AppLayout>
          {children}
        </AppLayout>
      </body>
```

to:

```tsx
      <body className="min-h-screen overflow-x-hidden selection:bg-primary-container selection:text-on-primary-container bg-background text-on-surface flex">
        <AuthProvider>
          <AuthGuard>
            <AppLayout>
              {children}
            </AppLayout>
          </AuthGuard>
        </AuthProvider>
      </body>
```

- [ ] **Step 5: Type-check**

Run: `cd frontend && npx tsc --noEmit`
Expected: no errors.

- [ ] **Step 6: Manual smoke test**

Run: `cd frontend && npm run dev`, then open `http://localhost:3000` in a browser.
Expected: redirected to `/login` (no sidebar chrome, just the centered login form) since there's no token yet. This confirms the guard is wired correctly even before Task 8 restores the pages' data fetching.

- [ ] **Step 7: Commit**

```bash
git add frontend/src/app/layout.tsx frontend/.gitignore frontend/.env.example frontend/.env.local
git commit -m "feat(frontend-auth): wire AuthProvider/AuthGuard into root layout, add env config"
```

Note: `git add` on a gitignored file with an exception rule only works if the exception is scoped correctly — `frontend/.env.local` should NOT be added (it's still covered by `.env*` and has no `!` exception, unlike `.env.example`). If `git status` shows `frontend/.env.local` as untracked after this commit, that's correct — leave it untracked.

---

### Task 8: Wire existing pages to `apiFetch`, full manual QA

**Files:**
- Modify: `frontend/src/app/page.tsx`
- Modify: `frontend/src/app/alerts/page.tsx`
- Modify: `frontend/src/app/search/page.tsx`

**Interfaces:**
- Consumes: `apiFetch` from `frontend/src/lib/api.ts` (Task 2).

- [ ] **Step 1: Update `frontend/src/app/page.tsx`**

Add the import (after the existing `next/link` import):

```tsx
import { apiFetch } from "@/lib/api";
```

Replace the `fetchDashboardData` function's `Promise.all` block:

```tsx
      const [metricsRes, alertsRes, timelineRes, ruleRes] = await Promise.all([
        fetch('http://localhost:8001/api/v1/dashboard/metrics'),
        fetch('http://localhost:8001/api/v1/alerts?limit=8'),
        fetch('http://localhost:8001/api/v1/alerts/stats/timeline'),
        fetch('http://localhost:8001/api/v1/alerts/stats/by-rule')
      ]);
```

with:

```tsx
      const [metricsRes, alertsRes, timelineRes, ruleRes] = await Promise.all([
        apiFetch('/api/v1/dashboard/metrics'),
        apiFetch('/api/v1/alerts?limit=8'),
        apiFetch('/api/v1/alerts/stats/timeline'),
        apiFetch('/api/v1/alerts/stats/by-rule')
      ]);
```

- [ ] **Step 2: Update `frontend/src/app/alerts/page.tsx`**

Add the import (after the existing `lucide-react` import):

```tsx
import { apiFetch } from '@/lib/api';
```

Replace:

```tsx
      const res = await fetch(`http://localhost:8001/api/v1/alerts?${params.toString()}`);
```

with:

```tsx
      const res = await apiFetch(`/api/v1/alerts?${params.toString()}`);
```

- [ ] **Step 3: Update `frontend/src/app/search/page.tsx`**

Add the import (after the existing `lucide-react` import):

```tsx
import { apiFetch } from '@/lib/api';
```

Replace:

```tsx
      const res = await fetch('http://localhost:8001/api/v1/search/search', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          query: searchQuery,
          earliest_time: '-24h',
          latest_time: 'now',
          limit: 100
        }),
      });
```

with:

```tsx
      const res = await apiFetch('/api/v1/search/search', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          query: searchQuery,
          earliest_time: '-24h',
          latest_time: 'now',
          limit: 100
        }),
      });
```

- [ ] **Step 4: Type-check**

Run: `cd frontend && npx tsc --noEmit`
Expected: no errors.

- [ ] **Step 5: Manual QA against a running backend**

You'll need the backend running from the `jwt-auth-rbac` branch (or `main` after PR #1 merges) with a seeded user. From `backend/`, with a running MongoDB and Splunk (or accept degraded/mocked responses for pages that don't have live data — the point of this QA is exercising the auth flow, not full data correctness):

```bash
cd backend
"D:\forensiq\Forensiq\backend\venv\Scripts\python.exe" scripts/create_admin_user.py --email admin@forensiq.ai --password "test-password-123" --role admin
"D:\forensiq\Forensiq\backend\venv\Scripts\python.exe" -m uvicorn app.main:app --reload --port 8001
```

In another terminal:

```bash
cd frontend
npm run dev
```

In a browser at `http://localhost:3000`, verify each of the following and check it off:

- [ ] Visiting `/`, `/alerts`, or `/search` while logged out redirects to `/login`.
- [ ] Submitting the login form with a wrong password shows an inline error, stays on `/login`.
- [ ] Submitting with `admin@forensiq.ai` / `test-password-123` redirects to `/` (the dashboard) and the dashboard's KPI cards/table render (data may be empty/zero if Splunk/Mongo have no alerts yet — that's fine, the point is no 401s).
- [ ] The header's account icon opens a menu showing the logged-in email and "Splunk Admin" as the role label.
- [ ] Clicking "Logout" redirects back to `/login`, and `localStorage` no longer has `forensiq_access_token`/`forensiq_refresh_token` (check via browser DevTools → Application → Local Storage).
- [ ] After logging back in, navigating to `/alerts` and `/search` both load without redirecting to `/login` (proves the token is attached correctly on every page's fetch calls).
- [ ] With the browser DevTools Network tab open, manually delete `forensiq_access_token` from `localStorage` (leave `forensiq_refresh_token` in place) and trigger a refetch (e.g. click the refresh button on `/alerts`, or wait for the 10s auto-refresh interval on `/` or `/alerts`) — the request should still succeed (an empty/no `Authorization` header still reaches the backend, gets a 401, `apiFetch` refreshes using the still-present refresh token, and retries transparently — no visible error, no redirect).
- [ ] With DevTools open, delete *both* tokens from `localStorage` and trigger a refetch — this time you should be redirected to `/login` (no valid refresh token to recover with).

- [ ] **Step 6: Commit**

```bash
git add frontend/src/app/page.tsx frontend/src/app/alerts/page.tsx frontend/src/app/search/page.tsx
git commit -m "feat(frontend-auth): route existing pages' API calls through apiFetch"
```

---

## Self-Review Notes

- **Spec coverage**: role mapping (Task 1), token storage (Task 1), `apiFetch` with single-retry refresh (Task 2), `AuthContext` login/logout (Task 3), `AuthGuard` route protection (Task 4), login page (Task 5), `AppLayout` chrome-skip + role badge (Task 6), provider wiring + env config (Task 7), existing pages migrated to `apiFetch` + manual QA (Task 8) — all spec sections covered. Per-role nav hiding is explicitly a spec Non-Goal, no task builds it.
- **Type consistency checked**: `DecodedUser` (Task 1) is used identically in `AuthContext.tsx` (Task 3, `useState<DecodedUser | null>`), `AuthGuard.tsx` (Task 4, via `useAuth()`), and `AppLayout.tsx` (Task 6, `user.role` / `user.email`) — same shape (`email`, `role`, `sub`) throughout. `apiFetch(path, options)` signature (Task 2) matches its Task 8 call sites exactly (positional `path` string, optional `RequestInit`).
- **No placeholders**: every step has runnable code or an exact find/replace with both sides shown in full.
