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
