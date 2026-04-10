export default function StatsCards({ stats }) {
  const s = stats || {}
  const failRate = s.total ? Math.round((s.failed / s.total) * 100) : 0

  return (
    <div className="stats-grid">
      <div className="stat-card green">
        <span className="stat-label">Total Events</span>
        <span className="stat-value">{s.total ?? '—'}</span>
        <span className="stat-sub">All log entries processed</span>
      </div>
      <div className="stat-card blue">
        <span className="stat-label">Accepted Logins</span>
        <span className="stat-value">{s.accepted ?? '—'}</span>
        <span className="stat-sub">Successful authentications</span>
      </div>
      <div className="stat-card red">
        <span className="stat-label">Failed Attempts</span>
        <span className="stat-value">{s.failed ?? '—'}</span>
        <span className="stat-sub">{failRate}% failure rate</span>
      </div>
      <div className="stat-card orange">
        <span className="stat-label">Critical Alerts</span>
        <span className="stat-value">{s.critical ?? '—'}</span>
        <span className="stat-sub">Root / privileged logins</span>
      </div>
    </div>
  )
}
