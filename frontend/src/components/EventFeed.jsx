function SeverityBadge({ severity }) {
  return <span className={`badge badge-${severity}`}>{severity}</span>
}

function EventBadge({ type }) {
  return <span className={`badge badge-${type}`}>{type}</span>
}

export default function EventFeed({ events }) {
  return (
    <div className="card">
      <div className="card-title">Recent Events — Audit Trail</div>
      <div className="table-wrap">
        <table>
          <thead>
            <tr>
              <th>Timestamp</th>
              <th>Service</th>
              <th>Event</th>
              <th>Username</th>
              <th>Source IP</th>
              <th>Port</th>
              <th>Severity</th>
            </tr>
          </thead>
          <tbody>
            {events.map((e, i) => (
              <tr key={i}>
                <td className="mono">
                  {e['@timestamp']
                    ? new Date(e['@timestamp']).toLocaleString()
                    : '—'}
                </td>
                <td>{e.service}</td>
                <td><EventBadge type={e.event_type} /></td>
                <td className="mono">{e.username}</td>
                <td className="mono">{e.src_ip}</td>
                <td className="mono">{e.src_port}</td>
                <td><SeverityBadge severity={e.severity} /></td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
