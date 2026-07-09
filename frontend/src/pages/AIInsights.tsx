import React, { useState } from 'react'
import { Brain, Search, Loader2 } from 'lucide-react'
import { getInsight } from '@/services/api'

interface InsightResult {
  flow_id: string
  explanation: string
  anomaly_result: Record<string, unknown> | null
}

export function AIInsights() {
  const [flowId, setFlowId] = useState('')
  const [result, setResult] = useState<InsightResult | null>(null)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  const handleQuery = async () => {
    if (!flowId.trim()) return
    setLoading(true)
    setError(null)
    try {
      const data = await getInsight(flowId.trim())
      setResult(data as InsightResult)
    } catch (err: unknown) {
      setError((err as { response?: { data?: { detail?: string } } })?.response?.data?.detail ?? 'Failed to get insight')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="p-6 space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white">AI Insights</h1>
        <p className="text-gray-400 text-sm mt-1">
          Enter a Flow ID to get an LLM-powered natural language explanation of network behavior.
        </p>
      </div>

      {/* Query input */}
      <div className="flex gap-3">
        <input
          type="text"
          placeholder="Enter flow ID (e.g. ab3f1c2d…)"
          value={flowId}
          onChange={(e) => setFlowId(e.target.value)}
          onKeyDown={(e) => e.key === 'Enter' && handleQuery()}
          className="flex-1 bg-gray-800 border border-gray-700 rounded-lg px-4 py-2.5 text-sm text-gray-200 placeholder-gray-500 focus:outline-none focus:ring-2 focus:ring-indigo-500 font-mono"
        />
        <button
          onClick={handleQuery}
          disabled={loading}
          className="flex items-center gap-2 bg-indigo-600 hover:bg-indigo-700 disabled:opacity-50 text-white px-5 py-2.5 rounded-lg text-sm font-medium transition-colors"
        >
          {loading ? <Loader2 size={15} className="animate-spin" /> : <Search size={15} />}
          Analyse
        </button>
      </div>

      {error && (
        <div className="bg-red-900/30 border border-red-800 rounded-lg px-4 py-3 text-sm text-red-300">
          {error}
        </div>
      )}

      {result && (
        <div className="space-y-4">
          {/* Explanation card */}
          <div className="bg-gray-900 border border-indigo-800/50 rounded-xl p-5">
            <div className="flex items-center gap-2 mb-3">
              <Brain size={18} className="text-indigo-400" />
              <h2 className="text-sm font-semibold text-indigo-300">AI Explanation</h2>
            </div>
            <p className="text-gray-200 leading-relaxed text-sm">{result.explanation}</p>
          </div>

          {/* Anomaly result */}
          {result.anomaly_result && (
            <div className="bg-gray-900 border border-gray-800 rounded-xl p-5">
              <h3 className="text-sm font-semibold text-gray-300 mb-3">Anomaly Detection Result</h3>
              <pre className="text-xs text-gray-400 font-mono overflow-auto">
                {JSON.stringify(result.anomaly_result, null, 2)}
              </pre>
            </div>
          )}
        </div>
      )}

      {!result && !loading && !error && (
        <div className="text-center py-16 text-gray-700">
          <Brain size={56} className="mx-auto mb-3 opacity-20" />
          <p className="text-sm">Enter a flow ID to query the AI explanation engine</p>
        </div>
      )}
    </div>
  )
}
