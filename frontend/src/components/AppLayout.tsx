"use client";

import { useState } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { motion, AnimatePresence } from "framer-motion";
import { 
  LayoutDashboard, 
  Bell,
  Terminal, 
  Search,
  ChevronLeft,
  ChevronRight,
  UserCircle,
  Shield,
  Activity,
  LogOut,
  ChevronRight as ChevronIcon
} from "lucide-react";
import { useAuth } from "@/context/AuthContext";
import { roleLabel } from "@/lib/roles";

export default function AppLayout({ children }: { children: React.ReactNode }) {
  const [isSidebarMinimized, setIsSidebarMinimized] = useState(false);
  const [isUserMenuOpen, setIsUserMenuOpen] = useState(false);
  const pathname = usePathname();
  const { user, logout } = useAuth();

  if (pathname === "/login") {
    return <>{children}</>;
  }

  const navItems = [
    { href: "/", icon: LayoutDashboard, label: "Dashboard", badge: null },
    { href: "/alerts", icon: Bell, label: "Alerts Queue", badge: null },
    { href: "/search", icon: Terminal, label: "Raw Logs (SPL)", badge: "SPL" },
  ];

  return (
    <>
      {/* Side Navigation Bar */}
      <motion.aside 
        initial={false}
        animate={{ width: isSidebarMinimized ? 68 : 248 }}
        className="fixed left-0 top-0 h-full bg-[#0A101D] border-r border-[#1C2C44] flex flex-col z-50 transition-all duration-300 overflow-hidden shadow-2xl"
      >
        {/* Brand Header */}
        <div className={`flex items-center gap-3 px-4 py-5 border-b border-[#16243A] ${isSidebarMinimized ? "justify-center px-0" : ""}`}>
          <div className="w-9 h-9 rounded-lg bg-gradient-to-br from-cyan-500 via-sky-600 to-indigo-700 p-0.5 shadow-lg shadow-cyan-500/20 shrink-0 flex items-center justify-center">
            <div className="w-full h-full bg-[#0A101D] rounded-[7px] flex items-center justify-center">
              <Shield className="w-4 h-4 text-cyan-400" />
            </div>
          </div>
          <AnimatePresence>
            {!isSidebarMinimized && (
              <motion.div 
                initial={{ opacity: 0, x: -8 }}
                animate={{ opacity: 1, x: 0 }}
                exit={{ opacity: 0, x: -8 }}
                className="whitespace-nowrap overflow-hidden flex flex-col"
              >
                <div className="flex items-center gap-1.5">
                  <h1 className="text-base font-extrabold text-white tracking-tight leading-none">
                    FORENSIQ
                  </h1>
                  <span className="text-[9px] px-1 py-0.2 rounded bg-cyan-500/20 text-cyan-300 font-mono font-bold">SOC</span>
                </div>
                <p className="text-[11px] text-slate-400 font-semibold mt-1 tracking-wider uppercase">
                  AI Security Ops
                </p>
              </motion.div>
            )}
          </AnimatePresence>
        </div>
        
        {/* Navigation Links */}
        <nav className="flex flex-col gap-1.5 p-3 overflow-y-auto overflow-x-hidden flex-1">
          <div className={`text-[10px] font-bold uppercase tracking-wider text-slate-400 px-3 py-1.5 ${isSidebarMinimized ? "hidden" : "block"}`}>
            Navigation
          </div>
          {navItems.map((item) => {
            const isActive = pathname === item.href;
            return (
              <Link 
                key={item.label}
                href={item.href} 
                className={`relative rounded-lg py-2.5 flex items-center transition-all group overflow-hidden ${
                  isSidebarMinimized ? "justify-center px-0" : "px-3.5 gap-3"
                } ${
                  isActive 
                    ? "bg-gradient-to-r from-cyan-500/20 to-sky-500/10 text-white font-semibold border border-cyan-500/30 shadow-md shadow-cyan-950/40" 
                    : "text-slate-300 hover:text-white hover:bg-[#131F33] border border-transparent"
                }`}
                title={isSidebarMinimized ? item.label : undefined}
              >
                {isActive && (
                  <span className="absolute left-0 top-1.5 bottom-1.5 w-1 rounded-r bg-cyan-400 shadow-[0_0_8px_#22d3ee]" />
                )}
                <item.icon className={`w-4 h-4 shrink-0 transition-colors ${
                  isActive ? "text-cyan-400" : "text-slate-400 group-hover:text-cyan-300"
                }`} />
                
                <AnimatePresence>
                  {!isSidebarMinimized && (
                    <motion.div 
                      initial={{ opacity: 0, width: 0 }}
                      animate={{ opacity: 1, width: 'auto' }}
                      exit={{ opacity: 0, width: 0 }}
                      className="flex items-center justify-between flex-1 whitespace-nowrap overflow-hidden"
                    >
                      <span className={`text-[13px] ${isActive ? "text-white font-bold" : "text-slate-200 font-medium"}`}>
                        {item.label}
                      </span>
                      {item.badge && (
                        <span className="font-mono text-[9px] px-1.5 py-0.5 rounded bg-[#1A2A42] text-cyan-300 border border-[#2B4063]">
                          {item.badge}
                        </span>
                      )}
                    </motion.div>
                  )}
                </AnimatePresence>
              </Link>
            );
          })}
        </nav>
        
        {/* Toggle Collapse Button */}
        <div className="p-3 border-t border-[#16243A]">
          <button 
            onClick={() => setIsSidebarMinimized(!isSidebarMinimized)}
            className="w-full py-2 px-2.5 rounded-lg border border-[#1E2E48] bg-[#0E1726] text-slate-400 hover:text-white hover:border-cyan-500/40 hover:bg-[#152238] transition-all flex justify-center items-center cursor-pointer shadow-sm"
            title={isSidebarMinimized ? "Expand sidebar" : "Collapse sidebar"}
          >
            {isSidebarMinimized ? <ChevronRight className="w-4 h-4" /> : <div className="flex items-center gap-2 text-xs font-semibold text-slate-300"><ChevronLeft className="w-4 h-4" /><span>Collapse Sidebar</span></div>}
          </button>
        </div>
      </motion.aside>

      {/* Main Content Area */}
      <motion.div 
        animate={{ marginLeft: isSidebarMinimized ? 68 : 248 }}
        className="flex-1 flex flex-col min-h-screen transition-all duration-300 bg-[#070B12]"
      >
        {/* Top Header */}
        <header className="sticky top-0 h-[60px] z-40 bg-[#0A101D]/90 backdrop-blur-md border-b border-[#1C2C44] flex justify-between items-center px-6 w-full shadow-sm">
          {/* Global Search Bar */}
          <div className="flex items-center gap-3 flex-1 max-w-lg">
            <Link 
              href="/search" 
              className="flex items-center justify-between w-full h-9 px-3.5 rounded-lg bg-[#0E1726] border border-[#1E2E48] hover:border-cyan-500/50 hover:bg-[#131F33] text-slate-300 text-xs font-medium transition-all group"
            >
              <div className="flex items-center gap-2.5">
                <Search className="w-4 h-4 text-cyan-400 group-hover:text-cyan-300 transition-colors" />
                <span className="text-slate-300">Search telemetry, indicators, hosts...</span>
              </div>
              <div className="flex items-center gap-1.5">
                <kbd className="hidden sm:inline-block px-1.5 py-0.5 rounded bg-[#16243A] border border-[#2B3E5E] text-[10px] font-mono text-slate-400 font-semibold">
                  Ctrl K
                </kbd>
                <span className="rounded bg-cyan-950/80 border border-cyan-800/50 px-1.5 py-0.5 font-mono text-[9px] text-cyan-300 font-bold">
                  SPL
                </span>
              </div>
            </Link>
          </div>

          {/* Right Header Status & Profile */}
          <div className="flex items-center gap-4">
            {/* Live Status indicator */}
            <div className="hidden md:flex items-center gap-2 px-3 py-1.5 rounded-full bg-[#0E1829] border border-[#1C2E4A]">
              <span className="dot-live" />
              <span className="text-[11px] font-mono font-semibold text-emerald-400 tracking-wide">
                SPLUNK LIVE
              </span>
            </div>

            {/* User Profile */}
            <div className="relative">
              <button
                aria-label="Account"
                onClick={() => setIsUserMenuOpen((v) => !v)}
                className="flex items-center gap-2.5 px-2.5 py-1.5 rounded-lg bg-[#0E1726] border border-[#1E2E48] hover:border-cyan-500/40 hover:bg-[#131F33] transition-all cursor-pointer"
              >
                <div className="w-6 h-6 rounded-full bg-gradient-to-tr from-cyan-600 to-indigo-600 flex items-center justify-center text-white text-[11px] font-bold">
                  {user?.email?.charAt(0).toUpperCase() || "A"}
                </div>
                <div className="hidden sm:flex flex-col text-left">
                  <span className="text-xs font-semibold text-slate-200 leading-tight">
                    {user?.email?.split('@')[0] || "Analyst"}
                  </span>
                  <span className="text-[9px] font-mono font-bold text-cyan-400 uppercase tracking-wider">
                    {user ? roleLabel(user.role) : "SOC Team"}
                  </span>
                </div>
              </button>

              <AnimatePresence>
                {isUserMenuOpen && (
                  <motion.div
                    initial={{ opacity: 0, y: -6, scale: 0.98 }}
                    animate={{ opacity: 1, y: 0, scale: 1 }}
                    exit={{ opacity: 0, y: -6, scale: 0.98 }}
                    className="absolute right-0 top-12 w-64 bg-[#0E1626] border border-[#23354E] rounded-xl shadow-2xl p-3 flex flex-col gap-2.5 z-50 backdrop-blur-xl"
                  >
                    <div className="flex flex-col gap-1 pb-2.5 border-b border-[#1E2E48] px-1">
                      <span className="text-xs font-bold text-white truncate">
                        {user?.email}
                      </span>
                      <span className="text-[10px] text-cyan-400 uppercase tracking-widest font-mono font-bold">
                        {user ? roleLabel(user.role) : ""}
                      </span>
                    </div>

                    <button
                      onClick={() => {
                        setIsUserMenuOpen(false);
                        logout();
                      }}
                      className="flex items-center gap-2 text-left text-xs font-semibold text-rose-400 hover:text-rose-300 hover:bg-rose-500/10 rounded-lg px-2.5 py-2 transition-colors cursor-pointer"
                    >
                      <LogOut className="w-4 h-4" />
                      Sign Out
                    </button>
                  </motion.div>
                )}
              </AnimatePresence>
            </div>
          </div>
        </header>

        {/* Subheader / Breadcrumbs */}
        <div className="bg-[#090F1C] px-6 py-2.5 border-b border-[#16243A] flex items-center gap-2 text-xs font-medium text-slate-400">
          <Link href="/" className="text-slate-400 hover:text-cyan-400 transition-colors font-semibold uppercase tracking-wider text-[11px]">
            SOC Console
          </Link>
          <ChevronIcon className="w-3.5 h-3.5 text-slate-600" />
          <span className="text-slate-200 font-bold uppercase tracking-wider text-[11px]">
            {pathname === "/" ? "Dashboard" : pathname.replace("/", "").toUpperCase()}
          </span>
        </div>
        
        {/* Main Content Body */}
        <main className="flex-1 p-6 relative z-20">
          {children}
        </main>
      </motion.div>
    </>
  );
}

