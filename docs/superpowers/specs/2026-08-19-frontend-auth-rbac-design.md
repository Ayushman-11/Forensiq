# Frontend Auth + RBAC Design

## Problem

The Next.js frontend (`frontend/`) currently has zero awareness of the backend's JWT auth (added in PR #1 / branch `jwt-auth-rbac`, not yet merged). Every page fires unauthenticated `fetch()` calls with hardcoded `http://localhost:8001` URLs; there is no login page, no token storage, no route protection, and no display of who's logged in or what role they hold. This design adds that layer without changing the backend.

## Role mapping

Backend enum values (`app/core/config.py` / user documents' `role` field, unchanged) map to frontend display labels only:

| Backend value | Display label |
|---|---|
| `soc_analyst` | SOC L1 |
| `soc_manager` | SOC Manager |
| `admin` | Splunk Admin |

No backend changes. This mapping lives in one file (`src/lib/roles.ts`) so it's the single place to edit if labels change later.

## Token storage

Access + refresh JWTs (returned in the `POST /auth/login` response body — the backend sets no cookies) are stored in `localStorage`. The access token is attached as `Authorization: Bearer <token>` on every API call. On a 401, the client transparently refreshes once via `POST /auth/refresh` and retries; if that also fails, tokens are cleared and the user is redirected to `/login`.

This trades some XSS exposure (a compromised page can read localStorage) for simplicity — no backend cookie-setting exists yet to do better, and rotating to httpOnly cookies is a backend change that can happen in a later pass without touching this design's component boundaries (only `lib/auth.ts`'s storage functions would change).

The frontend never verifies JWT signatures or trusts the decoded payload for authorization — it only decodes the payload to *display* email/role. All actual authorization stays server-side (unchanged, already shipped in PR #1).

## RBAC scope (this pass)

Most sidebar nav items (`Threat Intel`, `MITRE ATT&CK`, `Assets`, `Reports`, `Analytics`, `Settings`) are placeholder links (`href="#"`) with no pages behind them yet. This pass does NOT add per-role nav hiding — there's nothing real to differentiate yet, and hiding placeholder links would be speculative. Scope is:

- Login/logout flow
- All real pages (`/`, `/alerts`, `/search`) require any authenticated user (matches the backend's current router-level protection — no role differs between them yet)
- Display the current user's role badge in the header

Per-role UI gating (e.g., restricting a future "trigger ingest" button to Splunk Admin/SOC Manager, matching the backend's existing `require_roles("admin", "soc_manager")` on `POST /alerts/ingest`) is deferred until that feature exists in the UI — the plumbing (`AuthContext.user.role`) will already be there to build it on.

## Components

| File | Responsibility |
|---|---|
| `src/lib/roles.ts` | `ROLE_LABELS: Record<string, string>` mapping backend role → display label, plus a `roleLabel(role: string): string` helper (falls back to the raw value for unknown roles). |
| `src/lib/auth.ts` | `getAccessToken()`, `getRefreshToken()`, `setTokens(access, refresh)`, `clearTokens()` — thin localStorage wrappers. `decodeUser(accessToken): {email, role} \| null` — base64url-decodes the JWT payload (no external dependency, no signature check, display-only). |
| `src/lib/api.ts` | `apiFetch(path: string, options?: RequestInit): Promise<Response>` — prepends `process.env.NEXT_PUBLIC_API_URL`, attaches the access token header, handles the single-retry-after-refresh flow described above, throws/redirects on unrecoverable auth failure. Existing pages' `fetch('http://localhost:8001/...')` calls are replaced with `apiFetch('/api/v1/...')` calls. |
| `src/context/AuthContext.tsx` | React context + provider: `{user: {email, role} \| null, isAuthenticated: boolean, login(email, password): Promise<void>, logout(): Promise<void>}`. `login()` calls `POST /auth/login` via `apiFetch`-equivalent (unauthenticated variant, since no token exists yet), stores tokens, decodes and sets `user`. `logout()` calls `POST /auth/logout` best-effort (ignores errors — logout must always succeed locally) and clears state. |
| `src/components/AuthGuard.tsx` | Client component rendered inside `RootLayout`, wrapping `{children}`. Reads `isAuthenticated` from `AuthContext`; if false and `pathname !== '/login'`, redirects to `/login?redirect=<original path>`. Renders nothing (or a minimal loading state) during the initial client-side auth check to avoid a flash of protected content. |
| `src/app/login/page.tsx` | New route. Email/password form matching the existing dark theme (`#0e0e0e`/`#141414`/`#2a2a2a` palette already used in `AppLayout.tsx`). On submit, calls `AuthContext.login()`; on success, redirects to the `redirect` query param or `/`; on failure, shows the backend's error message inline. No sidebar/header chrome. |
| `src/components/AppLayout.tsx` (modified) | Add a `pathname === '/login'` check: when true, render `{children}` directly without the sidebar/header/breadcrumb chrome. When false, unchanged layout, except the existing `UserCircle` header button becomes a dropdown (or simple click-toggle menu) showing `user.email` + the mapped role label + a "Logout" action calling `AuthContext.logout()`. |
| `frontend/.env.local` (new, gitignored — matches existing `frontend/.gitignore`'s `.env*` rule) / `frontend/.env.example` (new, committed) | `NEXT_PUBLIC_API_URL=http://localhost:8001` |

`RootLayout` (`src/app/layout.tsx`) wraps `<AppLayout>` with `<AuthContext.Provider>` and `<AuthGuard>`, in that order (provider outermost, so the guard can read context).

## Data flow

- **Login:** form submit → `AuthContext.login()` → `POST /auth/login` → store both tokens → decode `{email, role}` from the access token → redirect to `redirect` query param or `/`.
- **Authenticated request:** `apiFetch()` reads the access token, attaches the header, fires the request.
- **Access token expired mid-session:** `apiFetch()` gets 401 → calls `POST /auth/refresh` once with the stored refresh token → success: store the new pair, retry the original request once → failure: clear tokens, redirect to `/login`.
- **Logout:** clear tokens, best-effort `POST /auth/logout`, redirect to `/login`.
- **Page load with missing/expired tokens:** `AuthGuard` sees `isAuthenticated=false` on mount, redirects to `/login` before protected content renders.

## Error handling

- Wrong credentials: `POST /auth/login` 401 body's `detail` message shown inline on the login form; no redirect.
- Backend unreachable / network error: `apiFetch` rejects; existing pages' current `try/catch` blocks around their `fetch()` calls (already present in `page.tsx`, `alerts/page.tsx`, `search/page.tsx`) catch it — no new global error boundary needed for this pass.
- Corrupt/malformed token in localStorage: treated identically to "missing" — `decodeUser` returns `null` on any parse failure, `isAuthenticated` becomes `false`.

## Testing / verification

`frontend/package.json` has no test runner (no Jest/Vitest/Playwright) — adding one is out of scope for this design (separate decision, not needed to ship this feature). Verification is manual: run the Next.js dev server against a running backend (from the `jwt-auth-rbac` branch, until PR #1 merges) and a seeded admin user (via `backend/scripts/create_admin_user.py`), and exercise in a real browser: successful login, wrong password, logout, protected-route redirect when logged out, access-token-expiry-triggers-refresh (can be forced by using a short `FORENSIQ_ACCESS_TOKEN_EXPIRE_MINUTES` value against the local backend), and refresh-also-fails-redirects-to-login (e.g. after backend restart clears in-memory... no, sessions are in Mongo, so simulate by logging out in another tab or deleting the session document).

## Non-goals (this pass)

- Per-role nav/UI hiding beyond the role badge (deferred — no real per-role feature exists in the UI yet).
- httpOnly cookie token storage (would need backend changes; localStorage is the pragmatic choice given the backend as shipped).
- A "forgot password" / self-registration flow (matches the backend's existing non-goals from PR #1 — CLI-only user creation).
- Automated frontend tests (no test runner exists; adding one is a separate decision).
