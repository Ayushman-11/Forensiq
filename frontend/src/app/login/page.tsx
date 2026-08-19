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
