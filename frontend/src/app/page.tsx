"use client";

import { useEffect, useState } from 'react';
import { LineChart } from '@mui/x-charts/LineChart';
import { PieChart } from '@mui/x-charts/PieChart';
import Link from 'next/link';

export default function AlertsHub() {
  const [metrics, setMetrics] = useState<any>(null);
  const [alerts, setAlerts] = useState<any[]>([]);
  const [timeline, setTimeline] = useState<any[]>([]);
  const [ruleStats, setRuleStats] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);

  const fetchDashboardData = async () => {
    try {
      const [metricsRes, alertsRes, timelineRes, ruleRes] = await Promise.all([
        fetch('http://localhost:8001/api/v1/dashboard/metrics'),
        fetch('http://localhost:8001/api/v1/alerts?limit=8'),
        fetch('http://localhost:8001/api/v1/alerts/stats/timeline'),
        fetch('http://localhost:8001/api/v1/alerts/stats/by-rule')
      ]);
      
      if (metricsRes.ok) setMetrics(await metricsRes.json());
      if (alertsRes.ok) setAlerts(await alertsRes.json());
      if (timelineRes.ok) setTimeline(await timelineRes.json());
      if (ruleRes.ok) setRuleStats(await ruleRes.json());
      
    } catch (error) {
      console.error('Failed to fetch dashboard data:', error);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    fetchDashboardData();
    const interval = setInterval(fetchDashboardData, 10000);
    return () => clearInterval(interval);
  }, []);

  if (loading && !metrics) {
    return (
      <div className="h-[60vh] flex items-center justify-center flex-col gap-4 text-[#888888]">
        <div className="w-6 h-6 border-2 border-[#888888] border-t-transparent rounded-full animate-spin" />
        <p className="font-mono-label text-sm uppercase tracking-widest">Loading SOC Data</p>
      </div>
    );
  }
  
  const xAxisData = timeline.length > 0 ? timeline.map(t => t.hour) : ['00:00', '01:00'];
  const seriesData = timeline.length > 0 ? timeline.map(t => t.count) : [0, 0];
  
  // Custom dark theme palette for charts
  const chartColors = ['#FF1E56', '#FFAC41', '#3b82f6', '#22c55e', '#888888'];
  const pieData = ruleStats.length > 0 ? ruleStats.map((r, i) => ({
    id: i,
    value: r.count,
    label: r.rule_name,
    color: chartColors[i % chartColors.length]
  })) : [{ id: 0, value: 1, label: 'No Data', color: '#383838' }];

  return (
    <div className="flex flex-col gap-6 max-w-[1600px] mx-auto pb-10">
      {/* Header */}
      <header className="flex justify-between items-end border-b border-[#2a2a2a] pb-4">
        <div>
          <h2 className="text-3xl text-white font-bold tracking-tight">Security Posture</h2>
          <p className="text-xs text-[#888888] uppercase tracking-wider font-bold mt-2">
            Real-time analytics · Last synced at {new Date().toLocaleTimeString()}
          </p>
        </div>
      </header>

      {/* KPI Row - Solid Blocks */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        
        {/* Amber Block */}
        <div className="rounded-lg p-5 flex flex-col justify-between" style={{ backgroundColor: '#FFAC41' }}>
          <div className="flex justify-between items-start mb-6">
            <span className="font-bold text-xs uppercase tracking-wider text-black">Active Alerts</span>
            <span className="bg-black text-white text-[10px] font-bold px-2 py-0.5 rounded-full uppercase">Queue</span>
          </div>
          <div className="text-black">
            <span className="text-4xl font-bold">{metrics?.total_alerts || 0}</span>
            <span className="text-sm font-bold ml-2">total</span>
          </div>
        </div>

        {/* Purple/Blue Block */}
        <div className="rounded-lg p-5 flex flex-col justify-between" style={{ backgroundColor: '#8B5CF6' }}>
          <div className="flex justify-between items-start mb-6">
            <span className="font-bold text-xs uppercase tracking-wider text-white">Open Investigations</span>
            <span className="bg-black/30 text-white text-[10px] font-bold px-2 py-0.5 rounded-full uppercase">High</span>
          </div>
          <div className="text-white">
            <span className="text-4xl font-bold">{metrics?.open_investigations || 0}</span>
            <span className="text-sm font-bold ml-2">active</span>
          </div>
        </div>

        {/* Dark Grey Block (Red Text) */}
        <div className="rounded-lg p-5 flex flex-col justify-between bg-[#232323] border border-[#383838]">
          <div className="flex justify-between items-start mb-6">
            <span className="font-bold text-xs uppercase tracking-wider text-[#f0f0f0]">Critical Findings</span>
            <span className="bg-[#FF1E56]/10 text-[#FF1E56] border border-[#FF1E56]/20 text-[10px] font-bold px-2 py-0.5 rounded-full uppercase">Sev 1</span>
          </div>
          <div className="text-[#FF1E56]">
            <span className="text-4xl font-bold">{metrics?.critical_alerts || 0}</span>
            <span className="text-sm font-bold ml-2">incidents</span>
          </div>
        </div>
      </div>
      
      {/* Charts Section */}
      <div className="grid grid-cols-12 gap-4">
        {/* Line Chart */}
        <div className="col-span-12 lg:col-span-7 bg-[#141414] border border-[#2a2a2a] rounded-lg p-5">
          <h3 className="text-[11px] font-bold uppercase tracking-wider text-[#888888] mb-4 flex items-center gap-2">
            <span className="w-1.5 h-1.5 rounded-full bg-[#FFAC41]"></span>
            Alert Trend (24h)
          </h3>
          <div className="h-64 w-full relative -ml-4 -mt-4">
            <LineChart
              xAxis={[{ scaleType: 'point', data: xAxisData, tickLabelStyle: { fill: '#888888', fontSize: 11, fontFamily: 'var(--font-jetbrains-mono)' } }]}
              yAxis={[{ tickLabelStyle: { fill: '#888888', fontSize: 11, fontFamily: 'var(--font-jetbrains-mono)' } }]}
              series={[
                {
                  data: seriesData,
                  color: '#FFAC41',
                  showMark: true,
                },
              ]}
              margin={{ left: 40, right: 10, top: 20, bottom: 20 }}
              sx={{
                '.MuiLineElement-root': { strokeWidth: 2 },
                '.MuiChartsAxis-line': { stroke: '#383838' },
                '.MuiChartsAxis-tick': { stroke: '#383838' }
              }}
            />
          </div>
        </div>
        
        {/* Donut Chart */}
        <div className="col-span-12 lg:col-span-5 bg-[#141414] border border-[#2a2a2a] rounded-lg p-5 flex flex-col">
          <h3 className="text-[11px] font-bold uppercase tracking-wider text-[#888888] mb-4 flex items-center gap-2">
            <span className="w-1.5 h-1.5 rounded-full bg-[#8B5CF6]"></span>
            Rule Distribution
          </h3>
          <div className="flex-1 flex items-center justify-center relative min-h-[220px]">
            <PieChart
              series={[
                {
                  data: pieData,
                  innerRadius: 65,
                  outerRadius: 100,
                  paddingAngle: 2,
                  cornerRadius: 2,
                },
              ]}
              sx={{ '.MuiChartsLegend-root': { display: 'none' } }}
              margin={{ left: 0, right: 0, top: 0, bottom: 0 }}
            />
            {/* Center stat */}
            <div className="absolute inset-0 flex flex-col items-center justify-center pointer-events-none">
              <span className="text-3xl font-bold text-white">{ruleStats.length}</span>
              <span className="text-[10px] uppercase font-bold text-[#888888] tracking-widest mt-1">Rules</span>
            </div>
          </div>
          {/* Custom Legend */}
          <div className="mt-6 flex flex-wrap gap-x-4 gap-y-2">
            {pieData.map((d, i) => (
              <div key={i} className="flex items-center gap-2">
                <span className="w-2 h-2 rounded-full" style={{ backgroundColor: d.color }}></span>
                <span className="text-[11px] font-mono text-[#f0f0f0]">{d.label}</span>
              </div>
            ))}
          </div>
        </div>
      </div>
      
      {/* Dense Heatmap Table */}
      <div className="bg-[#141414] border border-[#2a2a2a] rounded-lg overflow-hidden flex flex-col">
        <div className="p-4 border-b border-[#2a2a2a] flex justify-between items-center bg-[#1c1c1c]">
          <h3 className="text-[11px] font-bold uppercase tracking-wider text-[#888888] flex items-center gap-2">
            <span className="w-1.5 h-1.5 rounded-full bg-[#FF1E56]"></span>
            Recent Findings Table
          </h3>
          <div className="flex items-center gap-4 text-[10px] font-bold uppercase tracking-wider text-[#888888]">
            <span className="flex items-center gap-1.5"><span className="w-2 h-2 rounded-full bg-[#FF1E56]"></span> Critical</span>
            <span className="flex items-center gap-1.5"><span className="w-2 h-2 rounded-full bg-[#FFAC41]"></span> High</span>
            <span className="flex items-center gap-1.5"><span className="w-2 h-2 rounded-full bg-[#3b82f6]"></span> Med</span>
          </div>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse font-mono text-sm">
            <thead>
              <tr className="bg-[#0e0e0e] border-b border-[#2a2a2a]">
                <th className="py-2.5 px-4 text-[10px] text-[#555555] uppercase tracking-widest font-bold">Time</th>
                <th className="py-2.5 px-4 text-[10px] text-[#555555] uppercase tracking-widest font-bold">Severity</th>
                <th className="py-2.5 px-4 text-[10px] text-[#555555] uppercase tracking-widest font-bold w-1/3">Rule Name</th>
                <th className="py-2.5 px-4 text-[10px] text-[#555555] uppercase tracking-widest font-bold">Target</th>
                <th className="py-2.5 px-4 text-[10px] text-[#555555] uppercase tracking-widest font-bold">AI Conf</th>
                <th className="py-2.5 px-4 text-[10px] text-[#555555] uppercase tracking-widest font-bold text-right">Status</th>
              </tr>
            </thead>
            <tbody>
              {alerts.map((alert, idx) => {
                const isCrit = alert.severity === 'critical';
                const isHigh = alert.severity === 'high';
                const isMed = alert.severity === 'medium';
                
                // Splunk-style background shading for severity
                const rowBg = isCrit ? 'bg-[#FF1E56]/10' : isHigh ? 'bg-[#FFAC41]/5' : 'bg-transparent';
                const sevColor = isCrit ? '#FF1E56' : isHigh ? '#FFAC41' : isMed ? '#3b82f6' : '#525252';

                return (
                  <tr key={alert._id} className={`${rowBg} border-b border-[#2a2a2a] hover:bg-[#1c1c1c] transition-colors group cursor-pointer`}>
                    <td className="py-2.5 px-4 text-[#888888]">{new Date(alert.created_at).toLocaleTimeString([], { hour12: false })}</td>
                    <td className="py-2.5 px-4 font-bold" style={{ color: sevColor }}>{alert.severity.toUpperCase()}</td>
                    <td className="py-2.5 px-4 text-[#f0f0f0] font-sans text-[13px] group-hover:text-white truncate max-w-xs" title={alert.title}>{alert.title}</td>
                    <td className="py-2.5 px-4 text-[#888888]">{alert.host || '-'}</td>
                    <td className="py-2.5 px-4">
                      <span className={`px-2 py-0.5 rounded text-[10px] border font-bold ${
                        alert.ai_confidence > 80 ? 'border-[#FF1E56]/30 text-[#FF1E56] bg-[#FF1E56]/10' : 
                        alert.ai_confidence > 50 ? 'border-[#FFAC41]/30 text-[#FFAC41] bg-[#FFAC41]/10' : 
                        'border-[#383838] text-[#888888] bg-[#232323]'
                      }`}>
                        {alert.ai_confidence}%
                      </span>
                    </td>
                    <td className="py-2.5 px-4 text-right">
                      <span className={`text-[10px] uppercase font-bold tracking-widest ${
                        alert.status === 'Investigating' ? 'text-[#FFAC41]' : 
                        alert.status === 'New' ? 'text-[#3b82f6]' : 'text-[#555555]'
                      }`}>
                        {alert.status}
                      </span>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}
