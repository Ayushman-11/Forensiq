"use client";

import { useState } from "react";
import Link from "next/link";
import { usePathname } from "next/navigation";

export default function AppLayout({ children }: { children: React.ReactNode }) {
  const [isSidebarMinimized, setIsSidebarMinimized] = useState(false);
  const pathname = usePathname();

  const navItems = [
    { href: "/", icon: "dashboard", label: "Dashboard" },
    { href: "/alerts", icon: "notifications", label: "Alerts" },
    { href: "#", icon: "search_insights", label: "Investigations" },
    { href: "#", icon: "shield", label: "Threat Intel" },
    { href: "#", icon: "grid_view", label: "MITRE ATT&CK" },
    { href: "#", icon: "history", label: "Timeline" },
    { href: "#", icon: "inventory_2", label: "Assets" },
    { href: "#", icon: "description", label: "Reports" },
    { href: "#", icon: "bar_chart", label: "Analytics" },
    { href: "#", icon: "settings", label: "Settings" },
  ];

  return (
    <>
      {/* Side Navigation Bar */}
      <aside 
        className={`fixed left-0 top-0 h-full ${isSidebarMinimized ? "w-[68px]" : "w-[240px]"} transition-all duration-300 bg-surface dark:bg-surface-dim border-r border-outline-variant dark:border-outline flex flex-col z-50`}
      >
        <div className={`flex items-center gap-3 p-4 mb-4 mt-2 ${isSidebarMinimized ? "justify-center px-2" : ""}`}>
          <div className="w-8 h-8 rounded bg-primary flex items-center justify-center text-on-primary font-bold shrink-0">F</div>
          {!isSidebarMinimized && (
            <div className="whitespace-nowrap overflow-hidden">
              <h1 className="font-display-md text-display-md font-bold text-primary dark:text-primary-fixed leading-none">Forensiq</h1>
              <p className="font-caption text-caption text-on-surface-variant">AI Security Ops</p>
            </div>
          )}
        </div>
        
        <nav className="flex flex-col gap-1 px-3 overflow-y-auto overflow-x-hidden flex-1">
          {navItems.map((item) => {
            const isActive = pathname === item.href;
            return (
              <Link 
                key={item.label}
                href={item.href} 
                className={`rounded-lg py-2 flex items-center transition-colors group ${
                  isSidebarMinimized ? "justify-center px-0" : "px-3 gap-3"
                } ${
                  isActive 
                    ? "bg-primary/10 text-primary dark:bg-primary-fixed dark:text-on-primary-fixed" 
                    : "text-on-surface-variant dark:text-outline-variant hover:bg-surface-container-highest dark:hover:bg-on-secondary-fixed-variant"
                }`}
                title={isSidebarMinimized ? item.label : undefined}
              >
                <span className={`material-symbols-outlined ${!isActive ? "group-hover:text-primary transition-colors" : ""}`}>
                  {item.icon}
                </span>
                {!isSidebarMinimized && (
                  <span className={`whitespace-nowrap ${isActive ? "font-semibold" : "font-body-md text-body-md"}`}>
                    {item.label}
                  </span>
                )}
              </Link>
            );
          })}
        </nav>
        
        {/* Floating Toggle Button */}
        <button 
          onClick={() => setIsSidebarMinimized(!isSidebarMinimized)}
          className="absolute -right-3 top-1/2 -translate-y-1/2 w-6 h-6 bg-surface-bright dark:bg-surface-dim border border-outline-variant dark:border-outline rounded-full flex items-center justify-center text-on-surface-variant hover:text-primary hover:border-primary shadow-sm z-50 cursor-pointer transition-colors"
          title={isSidebarMinimized ? "Expand Menu" : "Collapse Menu"}
        >
          <span className={`material-symbols-outlined text-[16px] transition-transform duration-300 ${isSidebarMinimized ? "rotate-180" : "rotate-0"}`}>
            chevron_left
          </span>
        </button>
      </aside>

      {/* Main Content Area */}
      <div className={`flex-1 flex flex-col min-h-screen transition-all duration-300 ${isSidebarMinimized ? "ml-[68px]" : "ml-[240px]"}`}>
        {/* Top Navigation Bar */}
        <header className="sticky top-0 h-[64px] z-40 bg-surface/80 dark:bg-surface-dim/80 backdrop-blur-md border-b border-outline-variant dark:border-outline flex justify-between items-center px-6 w-full">
          <div className="flex items-center gap-4 flex-1">
            <span className="material-symbols-outlined text-on-surface-variant cursor-pointer hover:text-primary transition-colors">search</span>
            <input className="bg-transparent border-none focus:ring-0 text-body-md font-body-md text-on-surface placeholder:text-on-surface-variant/50 w-full max-w-md outline-none" placeholder="Search investigations, alerts..." type="text"/>
          </div>
          <div className="flex items-center gap-4">
            <button aria-label="Notifications" className="text-on-surface-variant hover:text-primary transition-colors h-8 w-8 rounded flex items-center justify-center hover:bg-surface-container-high active:scale-95 duration-150 cursor-pointer">
              <span className="material-symbols-outlined">notifications</span>
            </button>
            <button aria-label="Help" className="text-on-surface-variant hover:text-primary transition-colors h-8 w-8 rounded flex items-center justify-center hover:bg-surface-container-high active:scale-95 duration-150 cursor-pointer">
              <span className="material-symbols-outlined">help</span>
            </button>
            <button aria-label="Account" className="text-on-surface-variant hover:text-primary transition-colors h-8 w-8 rounded flex items-center justify-center hover:bg-surface-container-high active:scale-95 duration-150 cursor-pointer">
              <span className="material-symbols-outlined">account_circle</span>
            </button>
          </div>
        </header>

        {/* Subheader / Breadcrumbs */}
        <div className="bg-surface/80 dark:bg-surface-dim/80 px-6 py-2.5 border-b border-outline-variant/50 dark:border-outline/50 flex items-center gap-2">
          <Link href="/" className="text-on-surface-variant hover:text-primary transition-colors font-body-md text-[13px]">Dashboard</Link>
          {pathname.split('/').filter(p => p).map((segment, index, arr) => {
            const href = `/${arr.slice(0, index + 1).join('/')}`;
            const isLast = index === arr.length - 1;
            const title = segment.charAt(0).toUpperCase() + segment.slice(1);
            return (
              <div key={href} className="flex items-center gap-2">
                <span className="text-on-surface-variant/50 material-symbols-outlined text-[14px]">chevron_right</span>
                {isLast ? (
                  <span className="text-on-surface font-medium font-body-md text-[13px]">{title}</span>
                ) : (
                  <Link href={href} className="text-on-surface-variant hover:text-primary transition-colors font-body-md text-[13px]">{title}</Link>
                )}
              </div>
            );
          })}
        </div>
        
        <main className="flex-1 p-6 md:p-8 bg-surface dark:bg-surface-dim overflow-y-auto">
          {children}
        </main>
      </div>
    </>
  );
}
