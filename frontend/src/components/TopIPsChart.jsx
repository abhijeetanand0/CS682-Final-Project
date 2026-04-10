import {
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Cell, ResponsiveContainer,
} from 'recharts'

// Gradient from orange → red based on rank
const color = (index, total) => {
  const ratio = index / Math.max(total - 1, 1)
  const r = Math.round(239 - ratio * 0)
  const g = Math.round(68  - ratio * 68)
  const b = Math.round(68  - ratio * 68)
  return `rgb(${r},${g},${b})`
}

export default function TopIPsChart({ data }) {
  const sorted = [...data].sort((a, b) => b.count - a.count)

  return (
    <div className="card">
      <div className="card-title">Top Attacking IP Addresses (Failed Logins)</div>
      <ResponsiveContainer width="100%" height={220}>
        <BarChart
          data={sorted}
          layout="vertical"
          margin={{ top: 4, right: 24, left: 60, bottom: 0 }}
        >
          <CartesianGrid strokeDasharray="3 3" stroke="#1f2937" horizontal={false} />
          <XAxis type="number" tick={{ fill: '#9ca3af', fontSize: 12 }} allowDecimals={false} />
          <YAxis
            type="category"
            dataKey="ip"
            tick={{ fill: '#9ca3af', fontSize: 12, fontFamily: 'monospace' }}
            width={80}
          />
          <Tooltip
            contentStyle={{ background: '#111827', border: '1px solid #374151', borderRadius: 8 }}
            labelStyle={{ color: '#e5e7eb', fontFamily: 'monospace' }}
            formatter={v => [`${v} attempts`, 'Failed logins']}
          />
          <Bar dataKey="count" radius={[0, 4, 4, 0]} name="Failed attempts">
            {sorted.map((entry, i) => (
              <Cell key={entry.ip} fill={color(i, sorted.length)} />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  )
}
