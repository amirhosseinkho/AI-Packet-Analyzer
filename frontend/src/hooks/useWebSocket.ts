import { useEffect, useRef, useState, useCallback } from 'react'
import type { WsMessage } from '@/types'

const WS_BASE = import.meta.env.VITE_WS_URL ?? `ws://${window.location.host}`

type Status = 'connecting' | 'open' | 'closed' | 'error'

export function useWebSocket(path: string, onMessage: (msg: WsMessage) => void) {
  const [status, setStatus] = useState<Status>('closed')
  const wsRef = useRef<WebSocket | null>(null)
  const reconnectTimer = useRef<ReturnType<typeof setTimeout> | null>(null)
  const onMessageRef = useRef(onMessage)
  onMessageRef.current = onMessage

  const connect = useCallback(() => {
    if (wsRef.current?.readyState === WebSocket.OPEN) return

    setStatus('connecting')
    const ws = new WebSocket(`${WS_BASE}${path}`)
    wsRef.current = ws

    ws.onopen = () => setStatus('open')
    ws.onclose = () => {
      setStatus('closed')
      reconnectTimer.current = setTimeout(connect, 3000)
    }
    ws.onerror = () => setStatus('error')
    ws.onmessage = (ev) => {
      try {
        const parsed = JSON.parse(ev.data) as WsMessage
        onMessageRef.current(parsed)
      } catch {
        // ignore malformed messages
      }
    }
  }, [path])

  useEffect(() => {
    connect()
    return () => {
      if (reconnectTimer.current) clearTimeout(reconnectTimer.current)
      wsRef.current?.close()
    }
  }, [connect])

  return { status }
}
