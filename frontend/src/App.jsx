import { useEffect, useState } from 'react'
import StatsCards from './components/StatsCards'
import AlertsPanel from './components/AlertsPanel'
import TopIPsChart from './components/TopIPsChart'
import SeverityChart from './components/SeverityChart'
import EventsByServiceChart from './components/EventsByServiceChart'
import EventFeed from './components/EventFeed'

const API = ''  // empty = same origin (nginx proxies /api to backend)

async function fetchAll(setData) {
  try {
    const [stats, alerts, topIPs, severity, byService, events] = await Promise.all([
      fetch(`${API}/api/stats`).then(r => r.json()),
      fetch(`${API}/api/alerts`).then(r => r.json()),
      fetch(`${API}/api/top-ips`).then(r => r.json()),
      fetch(`${API}/api/severity-breakdown`).then(r => r.json()),
      fetch(`${API}/api/events-by-service`).then(r => r.json()),
      fetch(`${API}/api/recent-events?size=25`).then(r => r.json()),
    ])
    setData({ stats, alerts, topIPs, severity, byService, events, error: null })
  } catch (e) {
    setData(prev => ({ ...prev, error: e.message }))
  }
}

export default function App() {
  const [data, setData] = useState({
    stats: null, alerts: [], topIPs: [], severity: [],
    byService: [], events: [], error: null,
  })
  const [lastUpdated, setLastUpdated] = useState(null)

  useEffect(() => {
    fetchAll(setData)
    setLastUpdated(new Date())
    const interval = setInterval(() => {
      fetchAll(setData)
      setLastUpdated(new Date())
    }, 15000)
    return () => clearInterval(interval)
  }, [])

  return (
    <div className="app">
      <header className="header">
        <div className="header-left">
          <span className="header-icon">⬡</span>
          <h1>SIEM Security Dashboard</h1>
        </div>
        <div className="header-right">
          <span className="live-badge">● LIVE</span>
          {lastUpdated && (
            <span className="last-updated">
              Updated {lastUpdated.toLocaleTimeString()}
            </span>
          )}
        </div>
      </header>

      {data.error && (
        <div className="error-banner">
          Cannot reach backend: {data.error}
        </div>
      )}

      <main className="main">
        <StatsCards stats={data.stats} />

        {data.alerts.length > 0 && (
          <AlertsPanel alerts={data.alerts} />
        )}

        <div className="row-2col">
          <EventsByServiceChart data={data.byService} />
          <SeverityChart data={data.severity} />
        </div>

        <TopIPsChart data={data.topIPs} />

        <EventFeed events={data.events} />
      </main>
    </div>
  )
}
