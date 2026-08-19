"use client";

import { useState } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { motion, AnimatePresence } from "framer-motion";
import { 
  LayoutDashboard, 
  Bell, 
  Terminal, 
  ShieldAlert, 
  Target, 
  Clock, 
  Server, 
  FileText, 
  BarChart2, 
  Settings,
  Search,
  ChevronLeft,
  ChevronRight,
  HelpCircle,
  UserCircle
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
    { href: "/", icon: LayoutDashboard, label: "Dashboard" },
    { href: "/alerts", icon: Bell, label: "Alerts" },
    { href: "/search", icon: Terminal, label: "Raw Logs" },
    { href: "#", icon: ShieldAlert, label: "Threat Intel" },
    { href: "#", icon: Target, label: "MITRE ATT&CK" },
    { href: "#", icon: Clock, label: "Timeline" },
    { href: "#", icon: Server, label: "Assets" },
    { href: "#", icon: FileText, label: "Reports" },
    { href: "#", icon: BarChart2, label: "Analytics" },
    { href: "#", icon: Settings, label: "Settings" },
  ];

  return (
    <>
      {/* Side Navigation Bar */}
      <motion.aside 
        initial={false}
        animate={{ width: isSidebarMinimized ? 60 : 240 }}
        className="fixed left-0 top-0 h-full bg-[#141414] border-r border-[#2a2a2a] flex flex-col z-50 transition-all duration-300 overflow-hidden"
      >
        <div className={`flex items-center gap-3 p-4 mb-4 mt-2 ${isSidebarMinimized ? "justify-center px-0" : ""}`}>
          <div className="w-8 h-8 rounded bg-transparent border border-[#383838] flex items-center justify-center text-white font-display-md text-sm font-bold shrink-0">
            F
          </div>
          <AnimatePresence>
            {!isSidebarMinimized && (
              <motion.div 
                initial={{ opacity: 0, x: -10 }}
                animate={{ opacity: 1, x: 0 }}
                exit={{ opacity: 0, x: -10 }}
                className="whitespace-nowrap overflow-hidden flex flex-col"
              >
                <h1 className="font-display-md text-lg font-bold text-[#f0f0f0] leading-none tracking-tight">Forensiq</h1>
                <p className="font-caption text-[10px] text-[#888888] font-bold mt-1 uppercase tracking-wider">AI Security Ops</p>
              </motion.div>
            )}
          </AnimatePresence>
        </div>
        
        <nav className="flex flex-col gap-1 px-3 overflow-y-auto overflow-x-hidden flex-1 pb-6">
          {navItems.map((item) => {
            const isActive = pathname === item.href;
            return (
              <Link 
                key={item.label}
                href={item.href} 
                className={`relative rounded-md py-2 flex items-center transition-all group overflow-hidden ${
                  isSidebarMinimized ? "justify-center px-0" : "px-3 gap-3"
                } ${
                  isActive 
                    ? "bg-[#2a2a2a] text-[#ffffff]" 
                    : "text-[#888888] hover:text-[#f0f0f0] hover:bg-[#1c1c1c]"
                }`}
                title={isSidebarMinimized ? item.label : undefined}
              >
                <item.icon className={`w-4 h-4 shrink-0 relative z-10 ${isActive ? "text-[#FF1E56]" : "opacity-80 group-hover:opacity-100 transition-opacity"}`} />
                
                <AnimatePresence>
                  {!isSidebarMinimized && (
                    <motion.span 
                      initial={{ opacity: 0, width: 0 }}
                      animate={{ opacity: 1, width: 'auto' }}
                      exit={{ opacity: 0, width: 0 }}
                      className={`whitespace-nowrap relative z-10 text-[13px] ${isActive ? "font-bold tracking-wide" : "font-medium"}`}
                    >
                      {item.label}
                    </motion.span>
                  )}
                </AnimatePresence>
              </Link>
            );
          })}
        </nav>
        
        {/* Toggle Button */}
        <button 
          onClick={() => setIsSidebarMinimized(!isSidebarMinimized)}
          className="mx-3 mb-4 p-2 rounded-md border border-[#2a2a2a] bg-[#1c1c1c] text-[#888888] hover:text-white hover:border-[#383838] transition-colors flex justify-center items-center cursor-pointer"
        >
          {isSidebarMinimized ? <ChevronRight className="w-4 h-4" /> : <ChevronLeft className="w-4 h-4" />}
        </button>
      </motion.aside>

      {/* Main Content Area */}
      <motion.div 
        animate={{ marginLeft: isSidebarMinimized ? 60 : 240 }}
        className="flex-1 flex flex-col min-h-screen transition-all duration-300"
      >
        {/* Top Navigation Bar */}
        <header className="sticky top-0 h-[56px] z-40 bg-[#0e0e0e] border-b border-[#2a2a2a] flex justify-between items-center px-6 w-full">
          <div className="flex items-center gap-3 flex-1 max-w-xl">
            <div className="bg-[#141414] border border-[#2a2a2a] rounded px-3 py-1.5 flex items-center gap-2 w-full focus-within:border-[#383838] transition-all">
              <Search className="w-4 h-4 text-[#555555]" />
              <input 
                className="bg-transparent border-none focus:ring-0 text-sm font-medium text-[#f0f0f0] placeholder:text-[#555555] w-full outline-none" 
                placeholder="Search..." 
                type="text"
              />
            </div>
          </div>
          <div className="flex items-center gap-2">
            <button aria-label="Notifications" className="text-[#888888] hover:text-[#f0f0f0] transition-all h-8 w-8 rounded flex items-center justify-center hover:bg-[#1c1c1c] cursor-pointer">
              <Bell className="w-4 h-4" />
            </button>
            <button aria-label="Help" className="text-[#888888] hover:text-[#f0f0f0] transition-all h-8 w-8 rounded flex items-center justify-center hover:bg-[#1c1c1c] cursor-pointer">
              <HelpCircle className="w-4 h-4" />
            </button>
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
          </div>
        </header>

        {/* Subheader / Breadcrumbs */}
        <div className="bg-[#141414] px-6 py-2 border-b border-[#2a2a2a] flex items-center gap-2 relative z-30">
          <Link href="/" className="text-[#888888] hover:text-[#f0f0f0] transition-colors font-semibold tracking-wider text-[11px] uppercase">Dashboard</Link>
          {pathname.split('/').filter(p => p).map((segment, index, arr) => {
            const href = `/${arr.slice(0, index + 1).join('/')}`;
            const isLast = index === arr.length - 1;
            const title = segment.charAt(0).toUpperCase() + segment.slice(1);
            return (
              <div key={href} className="flex items-center gap-2">
                <span className="text-[#555555] mx-1">/</span>
                {isLast ? (
                  <span className="text-[#f0f0f0] font-bold text-[11px] uppercase tracking-wider">{title}</span>
                ) : (
                  <Link href={href} className="text-[#888888] hover:text-[#f0f0f0] transition-colors font-semibold text-[11px] uppercase tracking-wider">{title}</Link>
                )}
              </div>
            );
          })}
        </div>
        
        <main className="flex-1 p-6 relative z-20">
          {children}
        </main>
      </motion.div>
    </>
  );
}
