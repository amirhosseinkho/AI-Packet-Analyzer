import React, { useEffect, useState } from 'react'
import { RefreshCw } from 'lucide-react'
import { getStatistics } from '@/services/api'
import { ProtocolPie } from '@/components/charts/ProtocolPie'
import type { TrafficStats } from '@/types'

function StatCard({ label, value, sub }: { label: string; value: string | number; sub?: string }) {
  return (
    <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
      <p className="text-xs text-gray-500 uppercase tracking-wide mb-1">{label}</p>
      <p className="text-2xl font-bold text-white">{value}</p>
      {sub && <p className="text-xs text-gray-600 mt-1">{sub}</p>}
    </div>
  )
}

export function Statistics() {
  const [stats, setStats] = useState<TrafficStats | null>(null)
  const [loading, setLoading] = useState(false)

  const load = async () => {
    setLoading(true)
    try {
      setStats(await getStatistics())
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { load() }, [])

  if (!stats) return (
    <div className="p-6 text-center text-gray-500 py-20">
      {loading ? 'Loading statistics…' : 'No data available'}
    </div>
  )

  const totalMB = (stats.total_bytes / 1_048_576).toFixed(2)

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-white">Statistics</h1>
        <button
          onClick={load}
          disabled={loading}
          className="flex items-center gap-2 bg-gray-800 hover:bg-gray-700 text-gray-300 px-3 py-2 rounded-lg text-sm"
        >
          <RefreshCw size={14} className={loading ? 'animate-spin' : ''} /> Refresh
        </button>
      </div>

      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard label="Total Packets" value={stats.total_packets.toLocaleString()} />
        <StatCard label="Total Data" value={`${totalMB} MB`} />
        <StatCard label="Total Flows" value={stats.total_flows.toLocaleString()} />
        <StatCard
          label="Anomalies"
          value={stats.total_anomalies.toLocaleString()}
          sub={`${stats.anomaly_rate.toFixed(1)}% anomaly rate`}
        />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Protocol breakdown */}
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
          <h2 className="text-sm font-semibold text-gray-300 mb-4">Protocol Breakdown</h2>
          <ProtocolPie data={stats.protocol_breakdown} />
        </div>

        {/* Top talkers */}
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
          <h2 className="text-sm font-semibold text-gray-300 mb-4">Top Talkers</h2>
          <div className="space-y-2">
            {stats.top_talkers.slice(0, 8).map((t, i) => {
              const maxPkts = stats.top_talkers[0]?.packets ?? 1
              const pct = (t.packets / maxPkts) * 100
              return (
                <div key={t.ip} className="flex items-center gap-3">
                  <span className="text-xs text-gray-500 w-4">{i + 1}</span>
                  <span className="font-mono text-xs text-gray-300 w-32">{t.ip}</span>
                  <div className="flex-1 bg-gray-800 rounded-full h-1.5">
                    <div
                      className="bg-indigo-500 h-1.5 rounded-full"
                      style={{ width: `${pct}%` }}
                    />
                  </div>
                  <span className="text-xs text-gray-500 w-16 text-right">
                    {t.packets.toLocaleString()} pkts
                  </span>
                </div>
              )
            })}
          </div>
        </div>
      </div>
    </div>
  )
}
