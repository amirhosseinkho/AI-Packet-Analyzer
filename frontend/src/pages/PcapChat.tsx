import React, {
  useCallback,
  useEffect,
  useRef,
  useState,
} from 'react'
import {
  Brain,
  ChevronRight,
  FileSearch,
  Loader2,
  MessageSquare,
  Send,
  ShieldAlert,
  Trash2,
  Upload,
  X,
} from 'lucide-react'
import clsx from 'clsx'
import {
  deletePcapSession,
  getPcapHistory,
  getPcapSuggestedQuestions,
  getPcapSummary,
  sendPcapChat,
  uploadPcap,
} from '@/services/api'
import type {
  ChatMessage,
  PcapUploadResponse,
  SourceChunk,
} from '@/types'

// ── Sub-components ────────────────────────────────────────────────────────────

function DropZone({
  onFile,
  loading,
}: {
  onFile: (f: File) => void
  loading: boolean
}) {
  const [dragging, setDragging] = useState(false)
  const inputRef = useRef<HTMLInputElement>(null)

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault()
    setDragging(false)
    const f = e.dataTransfer.files[0]
    if (f) onFile(f)
  }

  return (
    <div
      onDragOver={(e) => { e.preventDefault(); setDragging(true) }}
      onDragLeave={() => setDragging(false)}
      onDrop={handleDrop}
      onClick={() => !loading && inputRef.current?.click()}
      className={clsx(
        'border-2 border-dashed rounded-2xl p-12 text-center cursor-pointer transition-all select-none',
        dragging
          ? 'border-indigo-400 bg-indigo-500/10'
          : 'border-gray-700 hover:border-gray-500 hover:bg-gray-800/40',
        loading && 'pointer-events-none opacity-60'
      )}
    >
      <input
        ref={inputRef}
        type="file"
        accept=".pcap,.pcapng,.cap"
        className="hidden"
        onChange={(e) => { const f = e.target.files?.[0]; if (f) onFile(f) }}
      />
      {loading ? (
        <div className="flex flex-col items-center gap-3">
          <Loader2 size={40} className="text-indigo-400 animate-spin" />
          <p className="text-gray-300 font-medium">Analysing PCAP…</p>
          <p className="text-gray-500 text-sm">Parsing flows, running anomaly detection, building RAG index</p>
        </div>
      ) : (
        <div className="flex flex-col items-center gap-3">
          <div className="w-16 h-16 rounded-2xl bg-indigo-600/20 flex items-center justify-center">
            <Upload size={28} className="text-indigo-400" />
          </div>
          <p className="text-gray-200 font-semibold text-lg">Drop your PCAP file here</p>
          <p className="text-gray-500 text-sm">or click to browse · .pcap .pcapng .cap · max 200 MB</p>
        </div>
      )}
    </div>
  )
}

function SummaryPanel({ summary }: { summary: PcapUploadResponse }) {
  const protocols = Object.entries(summary.protocol_counts)
    .sort(([, a], [, b]) => b - a)
    .slice(0, 6)

  return (
    <div className="bg-gray-900 border border-gray-800 rounded-xl p-5 space-y-4">
      <div className="flex items-center gap-2">
        <FileSearch size={16} className="text-indigo-400" />
        <h3 className="text-sm font-semibold text-gray-200">Capture Summary</h3>
        <span className="ml-auto text-xs text-gray-600 font-mono truncate max-w-xs">{summary.filename}</span>
      </div>

      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        {[
          { label: 'Packets', value: summary.total_packets.toLocaleString() },
          { label: 'Flows', value: summary.total_flows.toLocaleString() },
          { label: 'Anomalies', value: summary.total_anomalies.toString() },
          { label: 'Duration', value: `${summary.duration_seconds.toFixed(1)}s` },
        ].map(({ label, value }) => (
          <div key={label} className="bg-gray-800 rounded-lg px-3 py-2">
            <p className="text-xs text-gray-500">{label}</p>
            <p className="text-base font-bold text-white">{value}</p>
          </div>
        ))}
      </div>

      <div className="flex flex-wrap gap-2">
        {protocols.map(([proto, count]) => (
          <span key={proto} className="px-2 py-0.5 rounded text-xs bg-indigo-500/20 text-indigo-300">
            {proto} <span className="text-indigo-500">{count}</span>
          </span>
        ))}
        {summary.dns_query_count > 0 && (
          <span className="px-2 py-0.5 rounded text-xs bg-purple-500/20 text-purple-300">
            {summary.dns_query_count} DNS queries
          </span>
        )}
        {summary.total_anomalies > 0 && (
          <span className="px-2 py-0.5 rounded text-xs bg-red-500/20 text-red-300 flex items-center gap-1">
            <ShieldAlert size={10} /> {summary.total_anomalies} anomalies
          </span>
        )}
      </div>

      <div className="flex items-center gap-2 pt-1 border-t border-gray-800">
        <div className={clsx('w-1.5 h-1.5 rounded-full', summary.embedding_index ? 'bg-green-400' : 'bg-yellow-400')} />
        <p className="text-xs text-gray-500">
          {summary.embedding_index
            ? 'Semantic (embedding) index active'
            : 'Keyword (TF-IDF) index active — Ollama embeddings unavailable'}
        </p>
      </div>
    </div>
  )
}

function SourcesPanel({ sources }: { sources: SourceChunk[] }) {
  const [open, setOpen] = useState(false)
  if (sources.length === 0) return null
  return (
    <div className="mt-2">
      <button
        onClick={() => setOpen(!open)}
        className="flex items-center gap-1.5 text-xs text-gray-500 hover:text-gray-400 transition-colors"
      >
        <ChevronRight size={12} className={clsx('transition-transform', open && 'rotate-90')} />
        {sources.length} source{sources.length > 1 ? 's' : ''} retrieved
      </button>
      {open && (
        <div className="mt-2 space-y-2">
          {sources.slice(0, 4).map((s, i) => (
            <div key={i} className="bg-gray-900 border border-gray-800 rounded-lg p-3">
              <div className="flex items-center gap-2 mb-1">
                <span className="px-1.5 py-0.5 rounded text-xs bg-indigo-500/20 text-indigo-400 font-mono">
                  {s.category}
                </span>
                <span className="text-xs text-gray-600">score {s.score.toFixed(3)}</span>
              </div>
              <p className="text-xs text-gray-400 leading-relaxed">{s.content}</p>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

function ChatBubble({ msg }: { msg: ChatMessage }) {
  const isUser = msg.role === 'user'
  return (
    <div className={clsx('flex', isUser ? 'justify-end' : 'justify-start')}>
      <div className={clsx('max-w-[85%]', isUser ? 'order-2' : 'order-1')}>
        {!isUser && (
          <div className="flex items-center gap-1.5 mb-1.5 ml-1">
            <Brain size={12} className="text-indigo-400" />
            <span className="text-xs text-gray-500">AI Analyst</span>
          </div>
        )}
        <div
          className={clsx(
            'px-4 py-3 rounded-2xl text-sm leading-relaxed',
            isUser
              ? 'bg-indigo-600 text-white rounded-br-sm'
              : 'bg-gray-800 text-gray-200 rounded-bl-sm border border-gray-700'
          )}
        >
          {msg.content}
        </div>
        {!isUser && msg.sources && msg.sources.length > 0 && (
          <SourcesPanel sources={msg.sources} />
        )}
      </div>
    </div>
  )
}

// ── Main page ─────────────────────────────────────────────────────────────────

export function PcapChat() {
  const [uploadState, setUploadState] = useState<'idle' | 'uploading' | 'ready'>('idle')
  const [uploadError, setUploadError] = useState<string | null>(null)
  const [summary, setSummary] = useState<PcapUploadResponse | null>(null)
  const [sessionId, setSessionId] = useState<string | null>(null)
  const [messages, setMessages] = useState<ChatMessage[]>([])
  const [suggestedQuestions, setSuggestedQuestions] = useState<string[]>([])
  const [input, setInput] = useState('')
  const [answering, setAnswering] = useState(false)
  const bottomRef = useRef<HTMLDivElement>(null)
  const inputRef = useRef<HTMLTextAreaElement>(null)

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [messages])

  // ── Upload handler ─────────────────────────────────────────────────────────
  const handleFile = useCallback(async (file: File) => {
    setUploadError(null)
    setUploadState('uploading')
    setSummary(null)
    setMessages([])
    setSuggestedQuestions([])

    try {
      const result = await uploadPcap(file)
      setSummary(result)
      setSessionId(result.session_id)
      setUploadState('ready')

      // Load suggested questions
      try {
        const { questions } = await getPcapSuggestedQuestions(result.session_id)
        setSuggestedQuestions(questions)
      } catch { /* non-fatal */ }

      if (result.error) {
        setUploadError(`Warning: ${result.error}`)
      }
    } catch (err: unknown) {
      const msg = (err as { response?: { data?: { detail?: string } } })?.response?.data?.detail
        ?? (err as Error).message
        ?? 'Upload failed'
      setUploadError(msg)
      setUploadState('idle')
    }
  }, [])

  // ── Send message ───────────────────────────────────────────────────────────
  const handleSend = useCallback(async (question: string) => {
    if (!sessionId || !question.trim() || answering) return

    const userMsg: ChatMessage = { role: 'user', content: question.trim(), sources: [] }
    setMessages((prev) => [...prev, userMsg])
    setInput('')
    setAnswering(true)

    try {
      const res = await sendPcapChat(sessionId, question.trim())
      const assistantMsg: ChatMessage = {
        role: 'assistant',
        content: res.answer,
        sources: res.sources,
      }
      setMessages((prev) => [...prev, assistantMsg])
    } catch (err: unknown) {
      const detail = (err as { response?: { data?: { detail?: string } } })?.response?.data?.detail
        ?? 'Failed to get answer'
      setMessages((prev) => [
        ...prev,
        { role: 'assistant', content: `Error: ${detail}`, sources: [] },
      ])
    } finally {
      setAnswering(false)
      setTimeout(() => inputRef.current?.focus(), 50)
    }
  }, [sessionId, answering])

  const handleKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault()
      handleSend(input)
    }
  }

  const handleReset = async () => {
    if (sessionId) await deletePcapSession(sessionId).catch(() => {})
    setUploadState('idle')
    setSummary(null)
    setSessionId(null)
    setMessages([])
    setSuggestedQuestions([])
    setUploadError(null)
    setInput('')
  }

  // ── Render ─────────────────────────────────────────────────────────────────
  return (
    <div className="flex flex-col h-screen p-6 gap-4 max-w-5xl mx-auto w-full">
      {/* Header */}
      <div className="flex items-center justify-between shrink-0">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <MessageSquare size={22} className="text-indigo-400" />
            PCAP Chat
          </h1>
          <p className="text-gray-400 text-sm mt-0.5">
            Upload a capture file and ask questions in plain English
          </p>
        </div>
        {uploadState === 'ready' && (
          <button
            onClick={handleReset}
            className="flex items-center gap-2 text-gray-500 hover:text-gray-300 text-sm transition-colors"
          >
            <Trash2 size={14} /> New session
          </button>
        )}
      </div>

      {/* Error banner */}
      {uploadError && (
        <div className="flex items-start gap-2 bg-red-900/30 border border-red-800 rounded-lg px-4 py-3 text-sm text-red-300 shrink-0">
          <X size={14} className="mt-0.5 shrink-0" />
          {uploadError}
        </div>
      )}

      {/* Drop zone or summary */}
      {uploadState !== 'ready' ? (
        <div className="flex-1 flex items-center justify-center">
          <div className="w-full max-w-2xl">
            <DropZone onFile={handleFile} loading={uploadState === 'uploading'} />
          </div>
        </div>
      ) : (
        <div className="flex flex-col gap-3 flex-1 min-h-0">
          {/* Summary */}
          {summary && <SummaryPanel summary={summary} />}

          {/* Chat area */}
          <div className="flex-1 overflow-y-auto rounded-xl border border-gray-800 bg-gray-950 p-4 space-y-4 min-h-0">
            {messages.length === 0 ? (
              <div className="h-full flex flex-col items-center justify-center text-center gap-6 py-4">
                <div className="w-14 h-14 rounded-2xl bg-indigo-600/20 flex items-center justify-center">
                  <Brain size={26} className="text-indigo-400" />
                </div>
                <div>
                  <p className="text-gray-300 font-medium mb-1">Ready to answer your questions</p>
                  <p className="text-gray-600 text-sm">Ask anything about the capture below, or pick a suggestion</p>
                </div>
                {suggestedQuestions.length > 0 && (
                  <div className="w-full max-w-xl grid gap-2">
                    {suggestedQuestions.slice(0, 6).map((q, i) => (
                      <button
                        key={i}
                        onClick={() => handleSend(q)}
                        className="text-left text-sm text-gray-400 hover:text-gray-200 bg-gray-900 hover:bg-gray-800 border border-gray-800 hover:border-gray-700 rounded-lg px-4 py-2.5 transition-all"
                      >
                        {q}
                      </button>
                    ))}
                  </div>
                )}
              </div>
            ) : (
              <>
                {messages.map((msg, i) => (
                  <ChatBubble key={i} msg={msg} />
                ))}
                {answering && (
                  <div className="flex justify-start">
                    <div className="bg-gray-800 border border-gray-700 rounded-2xl rounded-bl-sm px-4 py-3">
                      <div className="flex items-center gap-1.5">
                        <span className="w-1.5 h-1.5 rounded-full bg-indigo-400 animate-bounce [animation-delay:0ms]" />
                        <span className="w-1.5 h-1.5 rounded-full bg-indigo-400 animate-bounce [animation-delay:150ms]" />
                        <span className="w-1.5 h-1.5 rounded-full bg-indigo-400 animate-bounce [animation-delay:300ms]" />
                      </div>
                    </div>
                  </div>
                )}
                <div ref={bottomRef} />
              </>
            )}
          </div>

          {/* Input bar */}
          <div className="shrink-0 flex gap-3 items-end">
            <textarea
              ref={inputRef}
              value={input}
              onChange={(e) => setInput(e.target.value)}
              onKeyDown={handleKeyDown}
              placeholder="Ask about this capture… (Enter to send, Shift+Enter for new line)"
              rows={2}
              disabled={answering}
              className="flex-1 resize-none bg-gray-800 border border-gray-700 rounded-xl px-4 py-3 text-sm text-gray-200 placeholder-gray-600 focus:outline-none focus:ring-2 focus:ring-indigo-500 disabled:opacity-50 leading-relaxed"
            />
            <button
              onClick={() => handleSend(input)}
              disabled={!input.trim() || answering}
              className="flex items-center justify-center w-11 h-11 rounded-xl bg-indigo-600 hover:bg-indigo-500 disabled:opacity-40 disabled:pointer-events-none text-white transition-colors shrink-0"
            >
              {answering
                ? <Loader2 size={16} className="animate-spin" />
                : <Send size={16} />
              }
            </button>
          </div>
        </div>
      )}
    </div>
  )
}
