import React, { useEffect, useState } from 'react'
import { format } from 'date-fns'
import { Download, FilePlus, FileText, RefreshCw } from 'lucide-react'
import { createReport, downloadReport, getReports } from '@/services/api'
import type { Report } from '@/types'

const FORMAT_ICONS: Record<string, string> = { json: '{ }', csv: 'CSV', pdf: 'PDF' }

export function Reports() {
  const [reports, setReports] = useState<Report[]>([])
  const [loading, setLoading] = useState(false)
  const [creating, setCreating] = useState(false)
  const [form, setForm] = useState({ name: 'report', format: 'json' })

  const load = async () => {
    setLoading(true)
    try { setReports(await getReports()) } finally { setLoading(false) }
  }

  useEffect(() => { load() }, [])

  const handleCreate = async () => {
    setCreating(true)
    try {
      await createReport(form)
      await load()
    } finally {
      setCreating(false)
    }
  }

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <h1 className="text-2xl font-bold text-white">Reports</h1>
        <button
          onClick={load}
          disabled={loading}
          className="flex items-center gap-2 bg-gray-800 hover:bg-gray-700 text-gray-300 px-3 py-2 rounded-lg text-sm"
        >
          <RefreshCw size={14} className={loading ? 'animate-spin' : ''} /> Refresh
        </button>
      </div>

      {/* Generate report */}
      <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
        <h2 className="text-sm font-semibold text-gray-300 mb-4">Generate New Report</h2>
        <div className="flex items-center gap-3 flex-wrap">
          <input
            type="text"
            value={form.name}
            onChange={(e) => setForm((f) => ({ ...f, name: e.target.value }))}
            placeholder="Report name"
            className="bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-gray-200 focus:outline-none focus:ring-2 focus:ring-indigo-500 w-48"
          />
          <select
            value={form.format}
            onChange={(e) => setForm((f) => ({ ...f, format: e.target.value }))}
            className="bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-gray-200 focus:outline-none focus:ring-2 focus:ring-indigo-500"
          >
            <option value="json">JSON</option>
            <option value="csv">CSV</option>
            <option value="pdf">PDF</option>
          </select>
          <button
            onClick={handleCreate}
            disabled={creating}
            className="flex items-center gap-2 bg-indigo-600 hover:bg-indigo-700 disabled:opacity-50 text-white px-4 py-2 rounded-lg text-sm font-medium transition-colors"
          >
            <FilePlus size={14} />
            {creating ? 'Generating…' : 'Generate'}
          </button>
        </div>
      </div>

      {/* Report list */}
      <div className="space-y-3">
        {reports.length === 0 ? (
          <div className="text-center py-12 text-gray-600">
            <FileText size={40} className="mx-auto mb-2 opacity-30" />
            <p>No reports yet</p>
          </div>
        ) : (
          reports.map((r) => (
            <div
              key={r.id}
              className="bg-gray-900 border border-gray-800 rounded-xl p-4 flex items-center justify-between hover:border-gray-700 transition-colors"
            >
              <div className="flex items-center gap-4">
                <div className="w-10 h-10 rounded-lg bg-indigo-600/20 flex items-center justify-center text-xs font-bold text-indigo-400">
                  {FORMAT_ICONS[r.format] ?? r.format}
                </div>
                <div>
                  <p className="text-sm font-medium text-gray-200">{r.name}</p>
                  <p className="text-xs text-gray-500">
                    {format(new Date(r.created_at), 'MMM d, yyyy HH:mm')} ·{' '}
                    {r.packet_count.toLocaleString()} pkts · {r.anomaly_count} anomalies
                    {r.file_size_bytes && ` · ${(r.file_size_bytes / 1024).toFixed(1)} KB`}
                  </p>
                </div>
              </div>
              <a
                href={downloadReport(r.id)}
                target="_blank"
                rel="noreferrer"
                className="flex items-center gap-1.5 text-indigo-400 hover:text-indigo-300 text-sm transition-colors"
              >
                <Download size={14} /> Download
              </a>
            </div>
          ))
        )}
      </div>
    </div>
  )
}
