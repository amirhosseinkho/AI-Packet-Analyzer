import React from 'react'
import { NavLink } from 'react-router-dom'
import {
  Activity,
  AlertTriangle,
  BarChart3,
  Brain,
  FileText,
  MessageSquare,
  Radio,
  Waves,
} from 'lucide-react'
import clsx from 'clsx'
import { useAppStore } from '@/store'

const NAV_ITEMS = [
  { to: '/', label: 'Live Packets', icon: Radio },
  { to: '/flows', label: 'Active Flows', icon: Waves },
  { to: '/anomalies', label: 'Anomalies', icon: AlertTriangle },
  { to: '/insights', label: 'AI Insights', icon: Brain },
  { to: '/statistics', label: 'Statistics', icon: BarChart3 },
  { to: '/reports', label: 'Reports', icon: FileText },
]

const TOOL_ITEMS = [
  { to: '/pcap-chat', label: 'PCAP Chat', icon: MessageSquare },
]

export function Sidebar() {
  const captureRunning = useAppStore((s) => s.captureRunning)

  return (
    <aside className="w-64 min-h-screen bg-gray-900 border-r border-gray-800 flex flex-col">
      {/* Logo */}
      <div className="px-6 py-5 border-b border-gray-800">
        <div className="flex items-center gap-3">
          <Activity className="text-indigo-400" size={24} />
          <div>
            <p className="text-white font-bold text-sm leading-tight">AI Packet Analyzer</p>
            <p className="text-gray-500 text-xs">Network Intelligence</p>
          </div>
        </div>
      </div>

      {/* Capture status */}
      <div className="px-6 py-3 border-b border-gray-800">
        <div className="flex items-center gap-2">
          <span
            className={clsx('w-2 h-2 rounded-full', captureRunning ? 'bg-green-400 animate-pulse' : 'bg-gray-600')}
          />
          <span className="text-xs text-gray-400">{captureRunning ? 'Capturing' : 'Idle'}</span>
        </div>
      </div>

      {/* Nav */}
      <nav className="flex-1 px-3 py-4 space-y-1">
        {NAV_ITEMS.map(({ to, label, icon: Icon }) => (
          <NavLink
            key={to}
            to={to}
            end={to === '/'}
            className={({ isActive }) =>
              clsx(
                'flex items-center gap-3 px-3 py-2 rounded-lg text-sm transition-colors',
                isActive
                  ? 'bg-indigo-600 text-white'
                  : 'text-gray-400 hover:bg-gray-800 hover:text-white'
              )
            }
          >
            <Icon size={16} />
            {label}
          </NavLink>
        ))}

        {/* Divider + Tools section */}
        <div className="pt-3 pb-1">
          <p className="px-3 text-xs font-semibold text-gray-600 uppercase tracking-wider">Tools</p>
        </div>
        {TOOL_ITEMS.map(({ to, label, icon: Icon }) => (
          <NavLink
            key={to}
            to={to}
            className={({ isActive }) =>
              clsx(
                'flex items-center gap-3 px-3 py-2 rounded-lg text-sm transition-colors',
                isActive
                  ? 'bg-indigo-600 text-white'
                  : 'text-gray-400 hover:bg-gray-800 hover:text-white'
              )
            }
          >
            <Icon size={16} />
            {label}
            <span className="ml-auto text-xs bg-indigo-500/20 text-indigo-400 px-1.5 py-0.5 rounded font-medium">
              RAG
            </span>
          </NavLink>
        ))}
      </nav>

      <div className="px-6 py-4 border-t border-gray-800">
        <p className="text-xs text-gray-600">v1.0.0 · Open Source</p>
      </div>
    </aside>
  )
}
