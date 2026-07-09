import React, { useCallback, useEffect, useState } from 'react'
import { format } from 'date-fns'
import { AlertTriangle, RefreshCw } from 'lucide-react'
import { getAnomalies } from '@/services/api'
import { useWebSocket } from '@/hooks/useWebSocket'
import { useAppStore } from '@/store'
import type { Anomaly, WsMessage } from '@/types'
import clsx from 'clsx'

const SEVERITY_STYLES: Record<string, string> = {
  critical: 'bg-red-600/30 text-red-300 border-red-600/50',
  high: 'bg-orange-600/30 text-orange-300 border-orange-600/50',
  medium: 'bg-yellow-600/30 text-yellow-300 border-yellow-600/50',
  low: 'bg-blue-600/30 text-blue-300 border-blue-600/50',
}

export function Anomalies() {
  const [anomalies, setAnomalies] = useState<Anomaly[]>([])
  const [total, setTotal] = useState(0)
  const [loading, setLoading] = useState(false)
  const { liveAnomalies, pushAnomaly } = useAppStore()

  const onMessage = useCallback(
    (msg: WsMessage) => { if (msg.type === 'anomaly') pushAnomaly(msg.data) },
    [pushAnomaly]
  )
  useWebSocket('/ws/anomalies', onMessage)

  const load = async () => {
    setLoading(true)
    try {
      const data = await getAnomalies({ limit: 100 })
      setAnomalies(data.anomalies)
      setTotal(data.total)
    } finally {
      setLoading(false)
    }
  }
  useEffect(() => { load() }, [])

  const allAnomalies = [...liveAnomalies, ...anomalies]
    .filter((a, i, arr) => arr.findIndex((b) => b.id === a.id) === i)
    .slice(0, 200)

  return (
    <div className="p-6 space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Anomalies</h1>
          <p className="text-gray-400 text-sm mt-1">{total} detected · {liveAnomalies.length} live alerts</p>
        </div>
        <button
          onClick={load}
          disabled={loading}
          className="flex items-center gap-2 bg-gray-800 hover:bg-gray-700 text-gray-300 px-3 py-2 rounded-lg text-sm transition-colors"
        >
          <RefreshCw size={14} className={loading ? 'animate-spin' : ''} /> Refresh
        </button>
      </div>

      <div className="space-y-3">
        {allAnomalies.length === 0 ? (
          <div className="text-center py-16 text-gray-600">
            <AlertTriangle size={48} className="mx-auto mb-3 opacity-30" />
            <p>No anomalies detected yet</p>
          </div>
        ) : (
          allAnomalies.map((a, i) => (
            <div
              key={a.id ?? i}
              className="bg-gray-900 border border-gray-800 rounded-xl p-4 hover:border-gray-700 transition-colors"
            >
              <div className="flex items-start justify-between gap-4">
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-1">
                    {a.severity && (
                      <span
                        className={clsx(
                          'px-2 py-0.5 rounded text-xs font-medium border',
                          SEVERITY_STYLES[a.severity] ?? 'bg-gray-700 text-gray-300'
                        )}
                      >
                        {a.severity.toUpperCase()}
                      </span>
                    )}
                    {a.anomaly_type && (
                      <span className="text-xs text-gray-400 font-mono">{a.anomaly_type}</span>
                    )}
                    <span className="text-xs text-gray-600">{a.detector_name}</span>
                  </div>
                  <p className="text-sm font-mono text-gray-300 truncate">{a.flow_id}</p>
                  {a.explanation && (
                    <p className="mt-2 text-sm text-gray-400 leading-relaxed">{a.explanation}</p>
                  )}
                </div>
                <div className="text-right shrink-0">
                  <p className="text-lg font-bold text-red-400">
                    {((a.ensemble_score ?? a.anomaly_score) * 100).toFixed(0)}%
                  </p>
                  <p className="text-xs text-gray-600">
                    {a.detected_at ? format(new Date(a.detected_at), 'HH:mm:ss') : ''}
                  </p>
                </div>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  )
}
