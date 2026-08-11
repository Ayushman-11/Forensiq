"use client";

import { useEffect, useState } from 'react';
import { LineChart } from '@mui/x-charts/LineChart';
import { PieChart } from '@mui/x-charts/PieChart';
import { BarChart } from '@mui/x-charts/BarChart';

export default function AlertsHub() {
  const [metrics, setMetrics] = useState<any>(null);
  const [alerts, setAlerts] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);

  const fetchDashboardData = async () => {
    try {
      const [metricsRes, alertsRes] = await Promise.all([
        fetch('http://localhost:8001/api/v1/dashboard/metrics'),
        fetch('http://localhost:8001/api/v1/alerts?limit=5')
      ]);
      if (metricsRes.ok) setMetrics(await metricsRes.json());
      if (alertsRes.ok) setAlerts(await alertsRes.json());
    } catch (error) {
      console.error('Failed to fetch dashboard data:', error);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchDashboardData();
  }, []);

  const formatTime = (seconds: number) => {
    const m = Math.floor(seconds / 60);
    const s = seconds % 60;
    return `${m}m ${s}s`;
  };

  if (loading) {
    return <div className="p-8 text-on-surface">Loading SOC Data...</div>;
  }

  return (
    <div className="flex flex-col gap-6">
      {/* Header */}
      <header className="flex justify-between items-center mb-6">
        <div>
          <h2 className="font-display-lg text-display-lg text-on-surface">SOC Overview</h2>
        </div>
        <button className="bg-primary text-on-primary hover:bg-primary-container transition-colors h-[32px] px-4 rounded flex items-center gap-2 font-title-sm text-title-sm cursor-pointer">
          <span className="material-symbols-outlined text-[18px]">play_arrow</span>
          Start Investigation
        </button>
      </header>

      <div className="flex gap-4">
        {/* Left Grid Content */}
        <div className="flex-1 flex flex-col gap-4">
          {/* KPI Row */}
          <div className="grid grid-cols-2 md:grid-cols-3 xl:grid-cols-6 gap-4">
            {/* KPI 1 */}
            <div className="bg-surface-container-lowest border border-outline-variant rounded-xl p-4 hover:shadow-sm hover:border-primary/30 transition-all group">
              <div className="flex justify-between items-start mb-2">
                <span className="font-caption text-caption font-medium text-on-surface-variant group-hover:text-primary transition-colors">Total Alerts</span>
                <span className="material-symbols-outlined text-[18px] text-on-surface-variant group-hover:text-primary transition-colors">notifications</span>
              </div>
              <div className="font-display-md text-display-md text-on-surface font-semibold">{metrics?.total_alerts || 0}</div>
            </div>
            
            {/* KPI 2 */}
            <div className="bg-surface-container-lowest border border-outline-variant rounded-xl p-4 hover:shadow-sm hover:border-error/50 transition-all relative overflow-hidden group">
              <div className="absolute left-0 top-0 bottom-0 w-1 bg-error"></div>
              <div className="flex justify-between items-start mb-2 pl-1">
                <span className="font-caption text-caption font-medium text-error">Critical</span>
                <span className="material-symbols-outlined text-[18px] text-error">warning</span>
              </div>
              <div className="font-display-md text-display-md text-error font-semibold pl-1">{metrics?.critical_alerts || 0}</div>
            </div>
            
            {/* KPI 3 */}
            <div className="bg-surface-container-lowest border border-outline-variant rounded-xl p-4 hover:shadow-sm hover:border-primary/30 transition-all group">
              <div className="flex justify-between items-start mb-2">
                <span className="font-caption text-caption font-medium text-on-surface-variant group-hover:text-primary transition-colors">Open Inv.</span>
                <span className="material-symbols-outlined text-[18px] text-on-surface-variant group-hover:text-primary transition-colors">search</span>
              </div>
              <div className="font-display-md text-display-md text-on-surface font-semibold">{metrics?.open_investigations || 0}</div>
            </div>
            
            {/* KPI 4 */}
            <div className="bg-surface-container-lowest border border-outline-variant rounded-xl p-4 hover:shadow-sm hover:border-primary/50 transition-all group">
              <div className="flex justify-between items-start mb-2">
                <span className="font-caption text-caption font-medium text-primary">AI Confidence</span>
                <span className="material-symbols-outlined text-[18px] text-primary">psychology</span>
              </div>
              <div className="font-display-md text-display-md text-primary font-semibold">{metrics?.ai_confidence_avg || 0}%</div>
            </div>
            
            {/* KPI 5 */}
            <div className="bg-surface-container-lowest border border-outline-variant rounded-xl p-4 hover:shadow-sm hover:border-primary/30 transition-all group">
              <div className="flex justify-between items-start mb-2">
                <span className="font-caption text-caption font-medium text-on-surface-variant group-hover:text-primary transition-colors">MTTD</span>
                <span className="material-symbols-outlined text-[18px] text-on-surface-variant group-hover:text-primary transition-colors">timer</span>
              </div>
              <div className="font-display-md text-display-md text-on-surface font-semibold">{formatTime(metrics?.mttd_seconds || 0)}</div>
            </div>
            
            {/* KPI 6 */}
            <div className="bg-surface-container-lowest border border-outline-variant rounded-xl p-4 hover:shadow-sm hover:border-tertiary-container/50 transition-all group">
              <div className="flex justify-between items-start mb-2">
                <span className="font-caption text-caption font-medium text-tertiary-container">Intel Hits</span>
                <span className="material-symbols-outlined text-[18px] text-tertiary-container">radar</span>
              </div>
              <div className="font-display-md text-display-md text-tertiary-container font-semibold">{metrics?.intel_hits || 0}</div>
            </div>
          </div>
          
          {/* Middle Row Charts */}
          <div className="grid grid-cols-12 gap-4">
            {/* Line Chart */}
            <div className="col-span-12 lg:col-span-6 bg-surface-container-lowest border border-outline-variant rounded-lg p-4">
              <h3 className="font-title-sm text-title-sm text-on-surface mb-4">Alert Trend (24h)</h3>
              <div className="h-60 w-full relative -ml-4 -mt-4">
                <LineChart
                  xAxis={[{ data: [1, 2, 3, 4, 5, 6, 7, 8] }]}
                  series={[
                    {
                      data: [2, 3, 2.5, 6, 4, 8, 4.5, 5],
                      area: true,
                      color: '#004ac6',
                    },
                  ]}
                  margin={{ left: 30, right: 10, top: 20, bottom: 20 }}
                />
              </div>
            </div>
            
            {/* Donut Chart */}
            <div className="col-span-12 md:col-span-6 lg:col-span-3 bg-surface-container-lowest border border-outline-variant rounded-lg p-4 flex flex-col justify-between">
              <h3 className="font-title-sm text-title-sm text-on-surface mb-2">Severity</h3>
              <div className="flex-1 flex items-center justify-center relative min-h-[200px]">
                <PieChart
                  series={[
                    {
                      data: [
                        { id: 0, value: metrics?.critical_alerts || 10, color: '#ba1a1a', label: 'Critical' },
                        { id: 1, value: 35, color: '#bc4800', label: 'High' },
                        { id: 2, value: 55, color: '#575e70', label: 'Medium' },
                      ],
                      innerRadius: 40,
                      outerRadius: 80,
                      paddingAngle: 5,
                      cornerRadius: 5,
                    },
                  ]}
                  slotProps={{
                    legend: { hidden: true }
                  }}
                  margin={{ left: 0, right: 0, top: 0, bottom: 0 }}
                />
              </div>
            </div>
            
            {/* Bar Chart */}
            <div className="col-span-12 md:col-span-6 lg:col-span-3 bg-surface-container-lowest border border-outline-variant rounded-lg p-4">
              <h3 className="font-title-sm text-title-sm text-on-surface mb-4">Investigator Load</h3>
              <div className="h-60 w-full relative -ml-4 -mt-4">
                <BarChart
                  xAxis={[{ scaleType: 'band', data: ['Auto', 'Alpha', 'Bravo'] }]}
                  series={[{ data: [65, 20, 15], color: '#004ac6' }]}
                  margin={{ left: 30, right: 10, top: 10, bottom: 30 }}
                />
              </div>
            </div>
          </div>
          
          {/* Table Section */}
          <div className="bg-surface-container-lowest border border-outline-variant rounded-lg overflow-hidden flex-1 flex flex-col">
            <div className="p-4 border-b border-outline-variant flex justify-between items-center bg-surface-bright">
              <h3 className="font-title-sm text-title-sm text-on-surface">Recent Alerts</h3>
              <button className="text-primary font-caption text-caption hover:underline cursor-pointer">View All</button>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-left border-collapse">
                <thead>
                  <tr className="bg-[#FAFAFA] dark:bg-surface-dim border-b border-outline-variant">
                    <th className="py-2 px-4 font-caption text-caption font-semibold text-on-surface-variant uppercase tracking-wider">Sev</th>
                    <th className="py-2 px-4 font-caption text-caption font-semibold text-on-surface-variant uppercase tracking-wider">Alert</th>
                    <th className="py-2 px-4 font-caption text-caption font-semibold text-on-surface-variant uppercase tracking-wider">Host</th>
                    <th className="py-2 px-4 font-caption text-caption font-semibold text-on-surface-variant uppercase tracking-wider">User</th>
                    <th className="py-2 px-4 font-caption text-caption font-semibold text-on-surface-variant uppercase tracking-wider">AI Conf</th>
                    <th className="py-2 px-4 font-caption text-caption font-semibold text-on-surface-variant uppercase tracking-wider">Status</th>
                  </tr>
                </thead>
                <tbody className="font-body-md text-body-md text-on-surface">
                  {alerts.map((alert) => (
                    <tr key={alert._id} className={`border-b border-outline-variant hover:bg-surface-container-lowest cursor-pointer transition-colors ${alert.severity === 'Critical' ? 'bg-error-container/10' : ''}`}>
                      <td className="py-2 px-4 h-[40px]">
                        <span className={`w-2 h-2 rounded-full inline-block ${alert.severity === 'Critical' ? 'bg-error' : alert.severity === 'High' ? 'bg-tertiary-container' : 'bg-secondary'}`}></span>
                      </td>
                      <td className={`py-2 px-4 h-[40px] font-medium ${alert.severity === 'Critical' ? 'text-error' : ''}`}>{alert.title}</td>
                      <td className="py-2 px-4 h-[40px] font-mono-label text-mono-label">{alert.host}</td>
                      <td className="py-2 px-4 h-[40px]">{alert.user}</td>
                      <td className="py-2 px-4 h-[40px]"><span className="text-primary font-semibold">{alert.ai_confidence}%</span></td>
                      <td className="py-2 px-4 h-[40px]">
                        <span className={`px-2 py-0.5 rounded font-caption text-caption ${alert.status === 'Investigating' ? 'bg-error/10 text-error' : alert.status === 'New' ? 'bg-primary-container/10 text-primary-container' : 'bg-surface-container-high text-on-surface-variant'}`}>{alert.status}</span>
                      </td>
                    </tr>
                  ))}
                  {alerts.length === 0 && (
                    <tr>
                      <td colSpan={6} className="py-4 text-center text-on-surface-variant">No alerts found in database. Run backend seeder to generate data.</td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
