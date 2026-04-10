const express = require('express');
const cors = require('cors');
const { Client } = require('@elastic/elasticsearch');

const app = express();
app.use(cors());
app.use(express.json());

const es = new Client({ node: process.env.ES_URL || 'http://elasticsearch:9200' });
const INDEX = 'siem-logs-*';

async function waitForES() {
  for (let i = 0; i < 20; i++) {
    try {
      await es.ping();
      console.log('Connected to Elasticsearch');
      return;
    } catch {
      console.log(`Waiting for Elasticsearch... (${i + 1}/20)`);
      await new Promise(r => setTimeout(r, 3000));
    }
  }
  throw new Error('Could not connect to Elasticsearch');
}

// Total, accepted, failed, critical counts
app.get('/api/stats', async (req, res) => {
  try {
    const [total, accepted, failed, critical] = await Promise.all([
      es.count({ index: INDEX }),
      es.count({ index: INDEX, query: { term: { 'event_type.keyword': 'accepted' } } }),
      es.count({ index: INDEX, query: { term: { 'event_type.keyword': 'failed' } } }),
      es.count({ index: INDEX, query: { term: { 'severity.keyword': 'critical' } } }),
    ]);
    res.json({
      total: total.count,
      accepted: accepted.count,
      failed: failed.count,
      critical: critical.count,
    });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Recent events sorted by time desc
app.get('/api/recent-events', async (req, res) => {
  try {
    const size = Math.min(parseInt(req.query.size) || 20, 100);
    const result = await es.search({
      index: INDEX,
      size,
      sort: [{ '@timestamp': 'desc' }],
      _source: ['@timestamp', 'server', 'service', 'event_type', 'username', 'src_ip', 'severity', 'user_validity', 'src_port'],
    });
    res.json(result.hits.hits.map(h => h._source));
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Top 10 IPs by failed attempt count
app.get('/api/top-ips', async (req, res) => {
  try {
    const result = await es.search({
      index: INDEX,
      size: 0,
      query: { term: { 'event_type.keyword': 'failed' } },
      aggs: {
        top_ips: { terms: { field: 'src_ip.keyword', size: 10 } },
      },
    });
    res.json(result.aggregations.top_ips.buckets.map(b => ({ ip: b.key, count: b.doc_count })));
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Count per severity level
app.get('/api/severity-breakdown', async (req, res) => {
  try {
    const result = await es.search({
      index: INDEX,
      size: 0,
      aggs: {
        by_severity: { terms: { field: 'severity.keyword', size: 10 } },
      },
    });
    res.json(result.aggregations.by_severity.buckets.map(b => ({ severity: b.key, count: b.doc_count })));
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Accepted vs Failed broken down by service (sshd / auth / app)
app.get('/api/events-by-service', async (req, res) => {
  try {
    const result = await es.search({
      index: INDEX,
      size: 0,
      aggs: {
        by_service: {
          terms: { field: 'service.keyword', size: 10 },
          aggs: {
            by_event_type: { terms: { field: 'event_type.keyword', size: 2 } },
          },
        },
      },
    });
    const data = result.aggregations.by_service.buckets.map(b => {
      const item = { service: b.key, accepted: 0, failed: 0 };
      b.by_event_type.buckets.forEach(t => { item[t.key] = t.doc_count; });
      return item;
    });
    res.json(data);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Brute force alerts: IPs with >= 3 failed attempts
app.get('/api/alerts', async (req, res) => {
  try {
    const result = await es.search({
      index: INDEX,
      size: 0,
      query: { term: { 'event_type.keyword': 'failed' } },
      aggs: {
        by_ip: {
          terms: { field: 'src_ip.keyword', size: 100, min_doc_count: 3 },
          aggs: {
            usernames: { terms: { field: 'username.keyword', size: 5 } },
            first_seen: { min: { field: '@timestamp' } },
            last_seen:  { max: { field: '@timestamp' } },
          },
        },
      },
    });
    res.json(
      result.aggregations.by_ip.buckets.map(b => ({
        ip:         b.key,
        count:      b.doc_count,
        usernames:  b.usernames.buckets.map(u => u.key),
        first_seen: b.first_seen.value_as_string,
        last_seen:  b.last_seen.value_as_string,
      }))
    );
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

waitForES().then(() => {
  app.listen(4000, () => console.log('SIEM Backend running on port 4000'));
});
