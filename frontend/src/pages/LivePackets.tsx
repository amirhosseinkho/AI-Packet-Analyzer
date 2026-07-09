import React, { useCallback, useState } from 'react'
import { format } from 'date-fns'
import { Play, Square } from 'lucide-react'
import { useAppStore } from '@/store'
import { useWebSocket } from '@/hooks/useWebSocket'
import { startCapture, stopCapture } from '@/services/api'
import type { WsMessage } from '@/types'
import clsx from 'clsx'

const PROTOCOL_COLORS: Record<string, string> = {
  TCP: 'bg-blue-500/20 text-blue-300',
  UDP: 'bg-cyan-500/20 text-cyan-300',
  ICMP: 'bg-yellow-500/20 text-yellow-300',
  DNS: 'bg-purple-500/20 text-purple-300',
  HTTP: 'bg-green-500/20 text-green-300',
  HTTPS: 'bg-emerald-500/20 text-emerald-300',
  ARP: 'bg-orange-500/20 text-orange-300',
}

export function LivePackets() {
  const { livePackets, captureRunning, setCaptureRunning, pushPacket } = useAppStore()
  const [filter, setFilter] = useState('')

  const handleMessage = useCallback(
    (msg: WsMessage) => {
      if (msg.type === 'packet') pushPacket(msg.data)
    },
    [pushPacket]
  )
  const { status } = useWebSocket('/ws/packets', handleMessage)

  const handleStart = async () => {
    await startCapture()
    setCaptureRunning(true)
  }
  const handleStop = async () => {
    await stopCapture()
    setCaptureRunning(false)
  }

  const filtered = filter
    ? livePackets.filter(
        (p) =>
          p.src_ip?.includes(filter) ||
          p.dst_ip?.includes(filter) ||
          p.protocol?.toLowerCase().includes(filter.toLowerCase())
      )
    : livePackets

  return (
    <div className="p-6 space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Live Packets</h1>
          <p className="text-gray-400 text-sm mt-1">
            {livePackets.length} captured · WebSocket {status}
          </p>
        </div>
        <div className="flex items-center gap-3">
          <input
            type="text"
            placeholder="Filter by IP or protocol…"
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            className="bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-gray-200 placeholder-gray-500 w-56 focus:outline-none focus:ring-2 focus:ring-indigo-500"
          />
          {captureRunning ? (
            <button
              onClick={handleStop}
              className="flex items-center gap-2 bg-red-600 hover:bg-red-700 text-white px-4 py-2 rounded-lg text-sm font-medium transition-colors"
            >
              <Square size={14} /> Stop
            </button>
          ) : (
            <button
              onClick={handleStart}
              className="flex items-center gap-2 bg-indigo-600 hover:bg-indigo-700 text-white px-4 py-2 rounded-lg text-sm font-medium transition-colors"
            >
              <Play size={14} /> Start Capture
            </button>
          )}
        </div>
      </div>

      <div className="overflow-x-auto rounded-xl border border-gray-800">
        <table className="w-full text-sm">
          <thead className="bg-gray-900 text-gray-400 text-xs uppercase tracking-wider">
            <tr>
              {['Time', 'Protocol', 'Source', 'Destination', 'Length', 'Flags', 'Info'].map((h) => (
                <th key={h} className="px-4 py-3 text-left font-medium">
                  {h}
                </th>
              ))}
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-800/50">
            {filtered.length === 0 ? (
              <tr>
                <td colSpan={7} className="text-center py-12 text-gray-600">
                  {captureRunning ? 'Waiting for packets…' : 'Start capture to see live packets'}
                </td>
              </tr>
            ) : (
              filtered.slice(0, 200).map((pkt, i) => (
                <tr key={i} className="hover:bg-gray-800/40 transition-colors">
                  <td className="px-4 py-2 text-gray-500 font-mono text-xs whitespace-nowrap">
                    {pkt.timestamp ? format(new Date(pkt.timestamp), 'HH:mm:ss.SSS') : '—'}
                  </td>
                  <td className="px-4 py-2">
                    <span
                      className={clsx(
                        'px-2 py-0.5 rounded text-xs font-medium',
                        PROTOCOL_COLORS[pkt.protocol ?? ''] ?? 'bg-gray-700 text-gray-300'
                      )}
                    >
                      {pkt.protocol}
                    </span>
                  </td>
                  <td className="px-4 py-2 font-mono text-xs text-gray-300">
                    {pkt.src_ip}:{pkt.src_port ?? '*'}
                  </td>
                  <td className="px-4 py-2 font-mono text-xs text-gray-300">
                    {pkt.dst_ip}:{pkt.dst_port ?? '*'}
                  </td>
                  <td className="px-4 py-2 text-gray-400 text-xs">{pkt.length?.toLocaleString()}</td>
                  <td className="px-4 py-2 text-gray-500 text-xs font-mono">{pkt.tcp_flags ?? '—'}</td>
                  <td className="px-4 py-2 text-gray-500 text-xs truncate max-w-xs">
                    {pkt.dns_query ?? pkt.http_host ?? ''}
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
