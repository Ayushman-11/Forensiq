"use client";

import { useState } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { motion, AnimatePresence } from "framer-motion";
import { 
  LayoutDashboard, 
  Bell, 
  Search as SearchIcon, 
  Sparkles, 
  Terminal, 
  FileText, 
  Settings, 
  ShieldAlert, 
  Sun, 
  Moon, 
  LogOut, 
  ChevronLeft, 
  ChevronRight,
  Database,
  User,
  Activity
} from "lucide-react";
import { useAuth } from "@/context/AuthContext";
import { useTheme } from "@/context/ThemeContext";
import { roleLabel } from "@/lib/roles";

export default function AppLayout({ children }: { children: React.ReactNode }) {
  const [isSidebarMinimized, setIsSidebarMinimized] = useState(false);
  const [isUserMenuOpen, setIsUserMenuOpen] = useState(false);
  const pathname = usePathname();
  const { user, logout } = useAuth();
  const { theme, toggleTheme } = useTheme();

  if (pathname === "/login") {
    return <>{children}</>;
  }

  const navItems = [
    { href: "/", icon: LayoutDashboard, label: "Dashboard", badge: null },
    { href: "/alerts", icon: Bell, label: "Alerts", badge: "3" },
    { href: "/investigations", icon: ShieldAlert, label: "Investigations", badge: null },
    { href: "/ai-extraction", icon: Sparkles, label: "AI Extraction", badge: "AI" },
    { href: "/raw-logs", icon: Terminal, label: "Raw Logs", badge: "SPL" },
    { href: "/reports", icon: FileText, label: "Reports", badge: null },
    { href: "/admin", icon: Settings, label: "Administration", badge: null },
  ];

  const userEmail = user?.email || "admin@forensiq.ai";
  const userRole = user ? roleLabel(user.role) : "SPLUNK ADMIN";

  return (
    <div className="min-h-screen flex w-full bg-[var(--bg-app)] text-[var(--text-primary)]">
      {/* Sidebar */}
      <motion.aside 
        initial={false}
        animate={{ width: isSidebarMinimized ? 64 : 240 }}
        className="fixed left-0 top-0 h-full bg-[var(--sidebar-bg)] border-r border-[var(--sidebar-border)] flex flex-col z-50 transition-all duration-200 overflow-hidden"
      >
        {/* Top Brand Header */}
        <div className="flex items-center gap-2.5 px-4 h-14 border-b border-[var(--sidebar-border)] shrink-0">
          <div className="w-6 h-6 rounded bg-[var(--text-primary)] text-[var(--bg-app)] flex items-center justify-center font-bold text-xs shrink-0">
            F
          </div>
          {!isSidebarMinimized && (
            <div className="flex flex-col whitespace-nowrap overflow-hidden">
              <span className="text-xs font-bold tracking-tight text-[var(--text-primary)] leading-tight">
                FORENSIQ
              </span>
              <span className="text-[9px] font-mono font-medium text-[var(--text-muted)] tracking-wider uppercase">
                AI SECURITY OPS
              </span>
            </div>
          )}
        </div>

        {/* Navigation Items */}
        <nav className="flex-1 py-3 px-2 flex flex-col gap-0.5 overflow-y-auto">
          {navItems.map((item) => {
            // Match exactly or subpaths
            const isActive = pathname === item.href || (item.href !== "/" && pathname.startsWith(item.href));
            return (
              <Link
                key={item.label}
                href={item.href}
                title={isSidebarMinimized ? item.label : undefined}
                className={`relative flex items-center h-8 rounded px-2.5 text-xs font-medium transition-colors group ${
                  isActive
                    ? "bg-[var(--sidebar-active-bg)] text-[var(--text-primary)] font-semibold"
                    : "text-[var(--text-secondary)] hover:text-[var(--text-primary)] hover:bg-[var(--surface-hover)]"
                }`}
              >
                {isActive && (
                  <span className="absolute left-0 top-1.5 bottom-1.5 w-0.5 rounded-r bg-[var(--text-primary)]" />
                )}

                <item.icon className={`w-4 h-4 shrink-0 mr-2.5 ${isActive ? "text-[var(--text-primary)]" : "text-[var(--text-muted)] group-hover:text-[var(--text-primary)]"}`} />
                
                {!isSidebarMinimized && (
                  <div className="flex items-center justify-between flex-1 truncate">
                    <span className="truncate">{item.label}</span>
                    {item.badge && (
                      <span className={`ml-auto font-mono text-[9px] px-1.5 py-0.2 rounded border font-semibold ${
                        item.badge === "3" 
                          ? "bg-[#EF4444]/10 text-[#EF4444] border-[#EF4444]/30"
                          : "bg-[var(--surface-elevated)] text-[var(--text-muted)] border-[var(--border-color)]"
                      }`}>
                        {item.badge}
                      </span>
                    )}
                  </div>
                )}
              </Link>
            );
          })}
        </nav>

        {/* Sidebar Footer - User Profile */}
        <div className="p-2 border-t border-[var(--sidebar-border)] flex flex-col gap-1 shrink-0">
          <div className="flex items-center justify-between px-2 py-1.5 rounded hover:bg-[var(--surface-hover)] transition-colors">
            <div className="flex items-center gap-2.5 min-w-0">
              <div className="w-6 h-6 rounded-full bg-[var(--surface-elevated)] border border-[var(--border-color)] flex items-center justify-center text-[10px] font-bold text-[var(--text-primary)] shrink-0">
                {userEmail.charAt(0).toUpperCase()}
              </div>
              {!isSidebarMinimized && (
                <div className="flex flex-col min-w-0">
                  <span className="text-xs font-medium text-[var(--text-primary)] truncate">
                    {userEmail}
                  </span>
                  <span className="text-[9px] font-mono text-[var(--text-muted)] uppercase tracking-wider font-semibold truncate">
                    {userRole}
                  </span>
                </div>
              )}
            </div>
            {!isSidebarMinimized && (
              <button
                onClick={logout}
                title="Sign Out"
                className="text-[var(--text-muted)] hover:text-[#EF4444] transition-colors p-1"
              >
                <LogOut className="w-3.5 h-3.5" />
              </button>
            )}
          </div>

          <button
            onClick={() => setIsSidebarMinimized(!isSidebarMinimized)}
            className="w-full flex items-center justify-center h-7 rounded text-[var(--text-muted)] hover:text-[var(--text-primary)] hover:bg-[var(--surface-hover)] transition-colors text-xs font-medium"
            title={isSidebarMinimized ? "Expand sidebar" : "Collapse sidebar"}
          >
            {isSidebarMinimized ? <ChevronRight className="w-3.5 h-3.5" /> : <ChevronLeft className="w-3.5 h-3.5" />}
          </button>
        </div>
      </motion.aside>

      {/* Main Container */}
      <motion.div
        animate={{ marginLeft: isSidebarMinimized ? 64 : 240 }}
        className="flex-1 flex flex-col min-h-screen bg-[var(--bg-app)] transition-all duration-200"
      >
        {/* Top Header */}
        <header className="sticky top-0 h-14 z-40 bg-[var(--header-bg)] backdrop-blur border-b border-[var(--border-color)] flex items-center justify-between px-6">
          {/* Global Search Bar */}
          <div className="flex items-center gap-2 max-w-md flex-1">
            <Link
              href="/search"
              className="flex items-center gap-2.5 w-full h-8 px-3 rounded-md bg-[var(--surface-secondary)] border border-[var(--border-color)] text-xs text-[var(--text-muted)] hover:text-[var(--text-primary)] hover:border-[var(--border-active)] transition-colors"
            >
              <SearchIcon className="w-3.5 h-3.5 shrink-0" />
              <span className="truncate">Search telemetry (IP, hash, hostname, user, SPL...)</span>
              <kbd className="ml-auto text-[10px] font-mono bg-[var(--surface-elevated)] border border-[var(--border-color)] px-1.5 py-0.2 rounded text-[var(--text-muted)]">
                Ctrl K
              </kbd>
            </Link>
          </div>

          {/* Header Right Status & Actions */}
          <div className="flex items-center gap-4">
            {/* Splunk Status */}
            <div className="flex items-center gap-1.5 px-2.5 py-1 rounded bg-[var(--surface-secondary)] border border-[var(--border-color)] text-[11px] font-mono font-medium">
              <span className="dot-live" />
              <span className="text-[var(--text-secondary)]">Splunk Connected</span>
            </div>

            {/* Notifications Icon */}
            <Link 
              href="/alerts" 
              className="relative p-1.5 rounded hover:bg-[var(--surface-hover)] text-[var(--text-secondary)] hover:text-[var(--text-primary)] transition-colors"
              title="Notifications"
            >
              <Bell className="w-4 h-4" />
              <span className="absolute top-1 right-1 w-1.5 h-1.5 rounded-full bg-[#EF4444]" />
            </Link>

            {/* Theme Switcher Toggle */}
            <button
              onClick={toggleTheme}
              className="p-1.5 rounded hover:bg-[var(--surface-hover)] text-[var(--text-secondary)] hover:text-[var(--text-primary)] transition-colors cursor-pointer"
              title={`Switch to ${theme === "dark" ? "Light" : "Dark"} Mode`}
            >
              {theme === "dark" ? <Sun className="w-4 h-4 text-[#F59E0B]" /> : <Moon className="w-4 h-4 text-[var(--text-primary)]" />}
            </button>

            {/* User Avatar */}
            <div className="w-7 h-7 rounded-full bg-[var(--surface-elevated)] border border-[var(--border-color)] flex items-center justify-center text-xs font-bold text-[var(--text-primary)] cursor-pointer">
              {userEmail.charAt(0).toUpperCase()}
            </div>
          </div>
        </header>

        {/* Main Content Area */}
        <main className="flex-1 p-6">
          {children}
        </main>
      </motion.div>
    </div>
  );
}
