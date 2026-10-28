"use client";

import { useState, Suspense, FormEvent } from "react";
import { useRouter, useSearchParams } from "next/navigation";
import { useAuth } from "@/context/AuthContext";
import { Loader2, ShieldCheck, KeyRound } from "lucide-react";

function LoginForm() {
  const { login, verifyMfa } = useAuth();
  const router = useRouter();
  const searchParams = useSearchParams();
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [mfaCode, setMfaCode] = useState("");
  const [mfaPendingToken, setMfaPendingToken] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const completeRedirect = () => {
    const redirectParam = searchParams.get("redirect");
    const redirect =
      redirectParam && redirectParam.startsWith("/") && !redirectParam.startsWith("//")
        ? redirectParam
        : "/";
    router.replace(redirect);
  };

  const handleSubmit = async (e: FormEvent) => {
    e.preventDefault();
    setError(null);
    setLoading(true);

    try {
      if (mfaPendingToken) {
        // Complete MFA challenge
        await verifyMfa(mfaPendingToken, mfaCode);
        completeRedirect();
      } else {
        // Primary credential check
        const res = await login(email, password);
        if (res.mfaRequired && res.mfaToken) {
          setMfaPendingToken(res.mfaToken);
        } else {
          completeRedirect();
        }
      }
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Authentication failed");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="h-screen w-screen flex items-center justify-center bg-[#0e0e0e]">
      <div className="w-full max-w-sm bg-[#141414] border border-[#2a2a2a] rounded-lg p-8 flex flex-col gap-6 shadow-2xl">
        <div className="flex flex-col items-center gap-2">
          {mfaPendingToken ? (
            <KeyRound className="w-8 h-8 text-[#8B5CF6]" />
          ) : (
            <ShieldCheck className="w-8 h-8 text-[#FF1E56]" />
          )}
          <h1 className="text-xl font-bold text-white tracking-tight">Forensiq</h1>
          <p className="text-[10px] text-[#888888] uppercase tracking-widest font-bold">
            {mfaPendingToken ? "Two-Factor Authentication" : "AI Security Ops Sign In"}
          </p>
        </div>

        <form onSubmit={handleSubmit} className="flex flex-col gap-4">
          {!mfaPendingToken ? (
            <>
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
            </>
          ) : (
            <div className="flex flex-col gap-1.5">
              <label className="text-[10px] text-[#888888] uppercase tracking-widest font-bold">
                6-Digit Authenticator Code
              </label>
              <input
                type="text"
                required
                maxLength={6}
                autoFocus
                placeholder="000000"
                value={mfaCode}
                onChange={(e) => setMfaCode(e.target.value.replace(/\D/g, ""))}
                className="bg-[#0e0e0e] border border-[#8B5CF6]/40 rounded px-3 py-2.5 text-center text-lg font-mono tracking-widest text-white outline-none focus:border-[#8B5CF6]"
              />
              <p className="text-[11px] text-[#888888] mt-1 text-center">
                Enter code from Google Authenticator, Authy, or 1Password.
              </p>
            </div>
          )}

          {error && (
            <div className="bg-[#FF1E56]/10 text-[#FF1E56] border border-[#FF1E56]/30 rounded px-3 py-2 text-xs font-bold">
              {error}
            </div>
          )}

          <button
            type="submit"
            disabled={loading || (!!mfaPendingToken && mfaCode.length !== 6)}
            className="bg-[#FF1E56] text-white hover:bg-[#FF1E56]/90 disabled:opacity-50 transition-all rounded py-2.5 flex items-center justify-center gap-2 font-bold text-[11px] uppercase tracking-widest cursor-pointer"
          >
            {loading ? <Loader2 className="w-4 h-4 animate-spin" /> : null}
            {loading ? "Verifying..." : mfaPendingToken ? "Verify Code" : "Sign In"}
          </button>

          {mfaPendingToken && (
            <button
              type="button"
              onClick={() => {
                setMfaPendingToken(null);
                setMfaCode("");
                setError(null);
              }}
              className="text-xs text-[#888888] hover:text-white underline text-center"
            >
              Cancel and return to login
            </button>
          )}
        </form>
      </div>
    </div>
  );
}

export default function LoginPage() {
  return (
    <Suspense
      fallback={
        <div className="h-screen w-screen flex items-center justify-center bg-[#0e0e0e]">
          <Loader2 className="w-6 h-6 animate-spin text-[#FF1E56]" />
        </div>
      }
    >
      <LoginForm />
    </Suspense>
  );
}
