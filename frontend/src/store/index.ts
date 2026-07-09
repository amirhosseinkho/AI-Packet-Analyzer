import { create } from 'zustand'
import type { Anomaly, Packet, TrafficStats } from '@/types'

interface AppState {
  livePackets: Packet[]
  liveAnomalies: Anomaly[]
  stats: TrafficStats | null
  captureRunning: boolean

  pushPacket: (p: Partial<Packet>) => void
  pushAnomaly: (a: Partial<Anomaly>) => void
  setStats: (s: TrafficStats) => void
  setCaptureRunning: (v: boolean) => void
}

const MAX_LIVE_PACKETS = 500

export const useAppStore = create<AppState>((set) => ({
  livePackets: [],
  liveAnomalies: [],
  stats: null,
  captureRunning: false,

  pushPacket: (p) =>
    set((state) => ({
      livePackets: [p as Packet, ...state.livePackets].slice(0, MAX_LIVE_PACKETS),
    })),

  pushAnomaly: (a) =>
    set((state) => ({
      liveAnomalies: [a as Anomaly, ...state.liveAnomalies].slice(0, 100),
    })),

  setStats: (s) => set({ stats: s }),
  setCaptureRunning: (v) => set({ captureRunning: v }),
}))
