"use client";

import { useState } from 'react';

const mockAlerts = [
  { id: 1, sev: 'critical', alert: 'Suspicious PowerShell Execution', host: 'SRV-PROD-09', user: 'svc_backup', conf: '98%', status: 'Investigating', time: '14:22 UTC' },
  { id: 2, sev: 'high', alert: 'Multiple Failed Logins', host: 'WKSTN-1142', user: 'j.doe', conf: '85%', status: 'New', time: '14:15 UTC' },
  { id: 3, sev: 'medium', alert: 'Unusual Outbound Traffic', host: 'SRV-DEV-02', user: 'SYSTEM', conf: '62%', status: 'Auto-Closed', time: '13:50 UTC' },
  { id: 4, sev: 'low', alert: 'Guest Account Creation', host: 'DC-01', user: 'admin', conf: '45%', status: 'Resolved', time: '12:10 UTC' },
  { id: 5, sev: 'critical', alert: 'Ransomware Extension Detected', host: 'WKSTN-039', user: 'a.smith', conf: '99%', status: 'New', time: '11:45 UTC' },
  { id: 6, sev: 'high', alert: 'Impossible Travel', host: 'VPN-GW', user: 'm.jones', conf: '91%', status: 'Investigating', time: '10:30 UTC' },
  { id: 7, sev: 'medium', alert: 'Large Data Transfer', host: 'DB-01', user: 'svc_db', conf: '75%', status: 'Investigating', time: '09:15 UTC' },
  { id: 8, sev: 'critical', alert: 'Domain Admin Privilege Escalation', host: 'DC-02', user: 'SYSTEM', conf: '96%', status: 'New', time: '08:50 UTC' },
];

const SevDot = ({ sev }: { sev: string }) => {
  const colors: Record<string, string> = {
    critical: 'bg-error',
    high: 'bg-tertiary-container',
    medium: 'bg-secondary',
    low: 'bg-outline',
  };
  return <span className={`w-2 h-2 rounded-full inline-block ${colors[sev] || 'bg-outline'}`}></span>;
};

const StatusBadge = ({ status }: { status: string }) => {
  const styles: Record<string, string> = {
    'Investigating': 'bg-error/10 text-error',
    'New': 'bg-primary-container/20 text-primary',
    'Auto-Closed': 'bg-surface-container-high text-on-surface-variant',
    'Resolved': 'bg-secondary-container/30 text-on-surface',
  };
  return <span className={`px-2 py-0.5 rounded font-caption text-caption ${styles[status] || 'bg-surface-container text-on-surface'}`}>{status}</span>;
};

export default function AlertsPage() {
  const [selectedAlertId, setSelectedAlertId] = useState<number | null>(null);
  const [search, setSearch] = useState('');

  const selectedAlert = mockAlerts.find(a => a.id === selectedAlertId);

  return (
    <div className="flex flex-col gap-6 h-full min-h-[calc(100vh-8rem)]">
      {/* Header */}
      <header className="flex justify-between items-center">
        <div>
          <h2 className="font-display-lg text-display-lg text-on-surface">Alerts Pipeline</h2>
        </div>
        <div className="flex gap-3">
          <button className="bg-surface-container-high hover:bg-surface-container-highest text-on-surface transition-colors h-[32px] px-4 rounded flex items-center gap-2 font-title-sm text-title-sm cursor-pointer border border-outline-variant">
            <span className="material-symbols-outlined text-[18px]">tune</span>
            Filters
          </button>
          <button className="bg-primary text-on-primary hover:bg-primary-container transition-colors h-[32px] px-4 rounded flex items-center gap-2 font-title-sm text-title-sm cursor-pointer">
            <span className="material-symbols-outlined text-[18px]">add</span>
            New Query
          </button>
        </div>
      </header>

      {/* Filter Bar */}
      <div className="bg-surface-container-lowest border border-outline-variant rounded-lg p-2 flex gap-4 items-center">
        <div className="flex-1 relative">
          <span className="material-symbols-outlined absolute left-3 top-1/2 -translate-y-1/2 text-on-surface-variant text-[18px]">search</span>
          <input 
            type="text" 
            placeholder="Search investigations, alerts, hosts..." 
            className="w-full bg-surface-container-low border-none rounded-md py-1.5 pl-9 pr-4 text-sm focus:ring-1 focus:ring-primary outline-none text-on-surface"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        </div>
        <div className="flex gap-2 border-l border-outline-variant pl-4">
          <select className="bg-surface-container-low border-none rounded-md py-1.5 px-3 text-sm focus:ring-1 focus:ring-primary outline-none text-on-surface">
            <option>Severity: All</option>
            <option>Critical</option>
            <option>High</option>
          </select>
          <select className="bg-surface-container-low border-none rounded-md py-1.5 px-3 text-sm focus:ring-1 focus:ring-primary outline-none text-on-surface">
            <option>Status: All</option>
            <option>New</option>
            <option>Investigating</option>
          </select>
        </div>
      </div>

      {/* Main Content Area */}
      <div className="flex-1 flex gap-4 overflow-hidden relative">
        {/* Table Area */}
        <div className="flex-1 bg-surface-container-lowest border border-outline-variant rounded-lg overflow-hidden flex flex-col">
          <div className="overflow-auto flex-1">
            <table className="w-full text-left border-collapse">
              <thead className="sticky top-0 bg-surface-container-lowest shadow-sm z-10">
                <tr className="border-b border-outline-variant">
                  <th className="py-3 px-4 font-caption text-caption font-semibold text-on-surface-variant uppercase tracking-wider w-10">Sev</th>
                  <th className="py-3 px-4 font-caption text-caption font-semibold text-on-surface-variant uppercase tracking-wider">Alert</th>
                  <th className="py-3 px-4 font-caption text-caption font-semibold text-on-surface-variant uppercase tracking-wider">Host</th>
                  <th className="py-3 px-4 font-caption text-caption font-semibold text-on-surface-variant uppercase tracking-wider">User</th>
                  <th className="py-3 px-4 font-caption text-caption font-semibold text-on-surface-variant uppercase tracking-wider">Time</th>
                  <th className="py-3 px-4 font-caption text-caption font-semibold text-on-surface-variant uppercase tracking-wider">AI Conf</th>
                  <th className="py-3 px-4 font-caption text-caption font-semibold text-on-surface-variant uppercase tracking-wider">Status</th>
                </tr>
              </thead>
              <tbody className="font-body-md text-body-md text-on-surface">
                {mockAlerts.filter(a => a.alert.toLowerCase().includes(search.toLowerCase())).map((alert) => (
                  <tr 
                    key={alert.id} 
                    onClick={() => setSelectedAlertId(selectedAlertId === alert.id ? null : alert.id)}
                    className={`border-b border-outline-variant cursor-pointer transition-colors ${
                      selectedAlertId === alert.id 
                        ? 'bg-primary/5 border-primary/20' 
                        : alert.sev === 'critical' ? 'bg-error-container/5 hover:bg-error-container/10' : 'hover:bg-surface-container-lowest'
                    }`}
                  >
                    <td className="py-3 px-4"><SevDot sev={alert.sev} /></td>
                    <td className={`py-3 px-4 font-medium ${alert.sev === 'critical' && selectedAlertId !== alert.id ? 'text-error' : ''}`}>{alert.alert}</td>
                    <td className="py-3 px-4 font-mono-label text-mono-label">{alert.host}</td>
                    <td className="py-3 px-4">{alert.user}</td>
                    <td className="py-3 px-4 text-on-surface-variant">{alert.time}</td>
                    <td className="py-3 px-4"><span className="text-primary font-semibold">{alert.conf}</span></td>
                    <td className="py-3 px-4"><StatusBadge status={alert.status} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>


      </div>
    </div>
  );
}
