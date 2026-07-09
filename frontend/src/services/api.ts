import axios from 'axios'
import type {
  Anomaly,
  Flow,
  Packet,
  PcapChatResponse,
  PcapUploadResponse,
  Report,
  TrafficStats,
} from '@/types'

const BASE = import.meta.env.VITE_API_URL ?? ''

const http = axios.create({ baseURL: `${BASE}/api/v1` })

// ── Packets ───────────────────────────────────────────────────────────────────
export const getPackets = (params?: Record<string, unknown>) =>
  http.get<{ total: number; packets: Packet[] }>('/packets', { params }).then((r) => r.data)

// ── Flows ─────────────────────────────────────────────────────────────────────
export const getFlows = (params?: Record<string, unknown>) =>
  http.get<{ total: number; flows: Flow[] }>('/flows', { params }).then((r) => r.data)

export const getFlow = (flowId: string) =>
  http.get<Flow>(`/flows/${flowId}`).then((r) => r.data)

// ── Anomalies ─────────────────────────────────────────────────────────────────
export const getAnomalies = (params?: Record<string, unknown>) =>
  http.get<{ total: number; anomalies: Anomaly[] }>('/anomalies', { params }).then((r) => r.data)

// ── Insights ──────────────────────────────────────────────────────────────────
export const getInsight = (flowId: string) =>
  http
    .post<{ flow_id: string; explanation: string; anomaly_result: unknown | null }>('/insights', {
      flow_id: flowId,
    })
    .then((r) => r.data)

// ── Statistics ────────────────────────────────────────────────────────────────
export const getStatistics = () =>
  http.get<TrafficStats>('/statistics').then((r) => r.data)

// ── Reports ───────────────────────────────────────────────────────────────────
export const getReports = () =>
  http.get<Report[]>('/reports').then((r) => r.data)

export const createReport = (payload: { name: string; format: string }) =>
  http.post<Report>('/reports', payload).then((r) => r.data)

export const downloadReport = (id: number) =>
  `${BASE}/api/v1/reports/${id}/download`

// ── Capture control ───────────────────────────────────────────────────────────
export const startCapture = (payload?: { interface?: string; bpf_filter?: string }) =>
  http.post('/packets/capture/start', payload ?? {}).then((r) => r.data)

export const stopCapture = () =>
  http.post('/packets/capture/stop').then((r) => r.data)

export const getCaptureStatus = () =>
  http
    .get<{
      running: boolean
      interface: string
      total_captured: number
      total_dropped: number
      queue_size: number
    }>('/packets/capture/status')
    .then((r) => r.data)

// ── PCAP Chat ─────────────────────────────────────────────────────────────────

export const uploadPcap = (file: File) => {
  const form = new FormData()
  form.append('file', file)
  return http
    .post<PcapUploadResponse>('/pcap/upload', form, {
      headers: { 'Content-Type': 'multipart/form-data' },
      timeout: 120_000,  // 2 min — large PCAPs may take a while
    })
    .then((r) => r.data)
}

export const sendPcapChat = (sessionId: string, question: string) =>
  http
    .post<PcapChatResponse>(`/pcap/${sessionId}/chat`, { question })
    .then((r) => r.data)

export const getPcapSummary = (sessionId: string) =>
  http.get(`/pcap/${sessionId}`).then((r) => r.data)

export const getPcapHistory = (sessionId: string) =>
  http.get(`/pcap/${sessionId}/history`).then((r) => r.data)

export const getPcapSuggestedQuestions = (sessionId: string) =>
  http
    .get<{ session_id: string; questions: string[] }>(`/pcap/${sessionId}/questions`)
    .then((r) => r.data)

export const deletePcapSession = (sessionId: string) =>
  http.delete(`/pcap/${sessionId}`).then((r) => r.data)
