import React, { useEffect, useState } from 'react'
import { format } from 'date-fns'
import { RefreshCw } from 'lucide-react'
import { getFlows } from '@/services/api'
import type { Flow } from '@/types'

export function ActiveFlows() {
  const [flows, setFlows] = useState<Flow[]>([])
  const [total, setTotal] = useState(0)
  const [loading, setLoading] = useState(false)
  const [activeOnly, setActiveOnly] = useState(false)

  const load = async () => {
    setLoading(true)
    try {
      const data = await getFlows({ limit: 100, active_only: activeOnly })
      setFlows(data.flows)
      setTotal(data.total)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { load() }, [activeOnly])

  return (
    <div className="p-6 space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Active Flows</h1>
          <p className="text-gray-400 text-sm mt-1">{total} total flows</p>
        </div>
        <div className="flex items-center gap-3">
          <label className="flex items-center gap-2 text-sm text-gray-400 cursor-pointer">
            <input
              type="checkbox"
              checked={activeOnly}
              onChange={(e) => setActiveOnly(e.target.checked)}
              className="rounded border-gray-600 bg-gray-800 text-indigo-500"
            />
            Active only
          </label>
          <button
            onClick={load}
            disabled={loading}
            className="flex items-center gap-2 bg-gray-800 hover:bg-gray-700 text-gray-300 px-3 py-2 rounded-lg text-sm transition-colors disabled:opacity-50"
          >
            <RefreshCw size={14} className={loading ? 'animate-spin' : ''} />
            Refresh
          </button>
        </div>
      </div>

      <div className="overflow-x-auto rounded-xl border border-gray-800">
        <table className="w-full text-sm">
          <thead className="bg-gray-900 text-gray-400 text-xs uppercase tracking-wider">
            <tr>
              {['Protocol', 'Source', 'Destination', 'Packets', 'Bytes', 'Duration', 'Rate', 'Status'].map((h) => (
                <th key={h} className="px-4 py-3 text-left font-medium">{h}</th>
              ))}
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-800/50">
            {flows.length === 0 ? (
              <tr>
                <td colSpan={8} className="text-center py-12 text-gray-600">
                  {loading ? 'Loading flows…' : 'No flows found'}
                </td>
              </tr>
            ) : (
              flows.map((flow) => (
                <tr key={flow.flow_id} className="hover:bg-gray-800/40 transition-colors">
                  <td className="px-4 py-2">
                    <span className="px-2 py-0.5 rounded text-xs font-medium bg-indigo-500/20 text-indigo-300">
                      {flow.protocol}
                    </span>
                  </td>
                  <td className="px-4 py-2 font-mono text-xs text-gray-300">
                    {flow.src_ip}:{flow.src_port ?? '*'}
                  </td>
                  <td className="px-4 py-2 font-mono text-xs text-gray-300">
                    {flow.dst_ip}:{flow.dst_port ?? '*'}
                  </td>
                  <td className="px-4 py-2 text-gray-300">{flow.packet_count.toLocaleString()}</td>
                  <td className="px-4 py-2 text-gray-300">{(flow.byte_count / 1024).toFixed(1)} KB</td>
                  <td className="px-4 py-2 text-gray-400 text-xs">
                    {flow.duration_seconds != null ? `${flow.duration_seconds.toFixed(2)}s` : '—'}
                  </td>
                  <td className="px-4 py-2 text-gray-400 text-xs">
                    {flow.packets_per_second != null ? `${flow.packets_per_second.toFixed(1)} pps` : '—'}
                  </td>
                  <td className="px-4 py-2">
                    <span className={`w-2 h-2 rounded-full inline-block mr-2 ${flow.is_active ? 'bg-green-400' : 'bg-gray-600'}`} />
                    <span className="text-xs text-gray-400">{flow.is_active ? 'Active' : 'Closed'}</span>
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}
