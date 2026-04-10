export default function AlertsPanel({ alerts }) {
  return (
    <div className="alerts-panel">
      <div className="alerts-header">
        <span className="alerts-icon">🚨</span>
        <span className="alerts-title">Brute Force Alerts</span>
        <span className="alerts-count">{alerts.length} IPs flagged</span>
      </div>
      <div className="alert-list">
        {alerts.map(a => (
          <div key={a.ip} className="alert-item">
            <div>
              <div className="alert-ip">{a.ip}</div>
              <div className="alert-meta">
                Targeted users: <strong>{a.usernames.join(', ')}</strong>
                &nbsp;·&nbsp;
                Last seen: {a.last_seen ? new Date(a.last_seen).toLocaleString() : '—'}
              </div>
            </div>
            <span className="alert-badge">{a.count} failed attempts</span>
          </div>
        ))}
      </div>
    </div>
  )
}
