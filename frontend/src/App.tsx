import React from 'react'
import { BrowserRouter, Route, Routes } from 'react-router-dom'
import { Layout } from '@/components/layout/Layout'
import { LivePackets } from '@/pages/LivePackets'
import { ActiveFlows } from '@/pages/ActiveFlows'
import { Anomalies } from '@/pages/Anomalies'
import { AIInsights } from '@/pages/AIInsights'
import { Statistics } from '@/pages/Statistics'
import { Reports } from '@/pages/Reports'
import { PcapChat } from '@/pages/PcapChat'

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route element={<Layout />}>
          <Route path="/" element={<LivePackets />} />
          <Route path="/flows" element={<ActiveFlows />} />
          <Route path="/anomalies" element={<Anomalies />} />
          <Route path="/insights" element={<AIInsights />} />
          <Route path="/statistics" element={<Statistics />} />
          <Route path="/reports" element={<Reports />} />
          <Route path="/pcap-chat" element={<PcapChat />} />
        </Route>
      </Routes>
    </BrowserRouter>
  )
}
