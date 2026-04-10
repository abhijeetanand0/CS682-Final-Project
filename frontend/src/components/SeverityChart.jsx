import { PieChart, Pie, Cell, Tooltip, Legend, ResponsiveContainer } from 'recharts'

const COLORS = {
  info:     '#3b82f6',
  warning:  '#f59e0b',
  high:     '#f97316',
  critical: '#ef4444',
}

export default function SeverityChart({ data }) {
  return (
    <div className="card">
      <div className="card-title">Severity Breakdown</div>
      <ResponsiveContainer width="100%" height={260}>
        <PieChart>
          <Pie
            data={data}
            dataKey="count"
            nameKey="severity"
            cx="50%" cy="50%"
            innerRadius={60}
            outerRadius={95}
            paddingAngle={3}
            label={({ severity, percent }) =>
              `${severity} ${(percent * 100).toFixed(0)}%`
            }
            labelLine={false}
          >
            {data.map(entry => (
              <Cell
                key={entry.severity}
                fill={COLORS[entry.severity] || '#6b7280'}
              />
            ))}
          </Pie>
          <Tooltip
            contentStyle={{ background: '#111827', border: '1px solid #374151', borderRadius: 8 }}
            formatter={(value, name) => [value, name]}
          />
          <Legend wrapperStyle={{ fontSize: 12 }} />
        </PieChart>
      </ResponsiveContainer>
    </div>
  )
}
