import http from 'k6/http';
import { check, sleep } from 'k6';
import { Trend, Rate } from 'k6/metrics';

// Custom metrics for endpoint budgets
const alertsDuration = new Trend('duration_alerts');
const summaryDuration = new Trend('duration_summary');
const incidentsDuration = new Trend('duration_incidents');
const mitreDuration = new Trend('duration_mitre');
const errorRate = new Rate('perf_errors');

export const options = {
  stages: [
    { duration: '10s', target: 20 }, // Ramp up to 20 analysts
    { duration: '30s', target: 50 }, // Ramp up to 50 concurrent analysts
    { duration: '30s', target: 50 }, // Sustained load at 50 analysts
    { duration: '10s', target: 0 },  // Graceful ramp down
  ],
  thresholds: {
    // CI Performance Budgets
    'duration_summary': ['p(95)<100'],   // Dashboard summary under 100ms
    'duration_alerts': ['p(95)<200'],    // Cursor paginated alerts under 200ms
    'duration_incidents': ['p(95)<200'], // Paginated incidents under 200ms
    'duration_mitre': ['p(95)<150'],     // MITRE full aggregation under 150ms
    'http_req_failed': ['rate<0.01'],    // Under 1% errors
    'perf_errors': ['rate<0.01'],
  },
};

const BASE_URL = __ENV.BASE_URL || 'http://localhost:8000';

export default function () {
  const headers = {
    'Accept': 'application/json',
    'Content-Type': 'application/json',
    'Authorization': 'Bearer ' + (__ENV.AUTH_TOKEN || 'test_token'),
  };

  // 1. Dashboard Summary (High frequency poll)
  {
    const res = http.get(`${BASE_URL}/api/v1/dashboard/summary`, {
      headers,
      tags: { endpoint: 'summary' },
    });
    summaryDuration.add(res.timings.duration);
    const ok = check(res, {
      'summary status is 200': (r) => r.status === 200,
      'summary duration < 100ms': (r) => r.timings.duration < 100,
    });
    errorRate.add(!ok);
  }

  sleep(1);

  // 2. Cursor-paginated Alerts (Triage Queue)
  let cursor = null;
  {
    const res = http.get(`${BASE_URL}/api/v1/alerts?limit=50&sort=severity&status=open`, {
      headers,
      tags: { endpoint: 'alerts' },
    });
    alertsDuration.add(res.timings.duration);
    const ok = check(res, {
      'alerts status is 200': (r) => r.status === 200,
      'alerts duration < 200ms': (r) => r.timings.duration < 200,
    });
    errorRate.add(!ok);
    cursor = res.headers['X-Next-Cursor'];
  }

  // Follow next cursor page
  if (cursor) {
    sleep(0.5);
    const res2 = http.get(`${BASE_URL}/api/v1/alerts?limit=50&sort=severity&status=open&cursor=${encodeURIComponent(cursor)}`, {
      headers,
      tags: { endpoint: 'alerts' },
    });
    alertsDuration.add(res2.timings.duration);
    check(res2, { 'cursor page 2 status is 200': (r) => r.status === 200 });
  }

  sleep(1);

  // 3. Paginated Incidents with DB Aggregation
  {
    const res = http.get(`${BASE_URL}/api/v1/incidents?limit=20&state=open`, {
      headers,
      tags: { endpoint: 'incidents' },
    });
    incidentsDuration.add(res.timings.duration);
    const ok = check(res, {
      'incidents status is 200': (r) => r.status === 200,
      'incidents duration < 200ms': (r) => r.timings.duration < 200,
    });
    errorRate.add(!ok);
  }

  sleep(1);

  // 4. MITRE ATT&CK Matrix Analytics
  {
    const res = http.get(`${BASE_URL}/api/v1/alerts/stats/mitre`, {
      headers,
      tags: { endpoint: 'mitre' },
    });
    mitreDuration.add(res.timings.duration);
    const ok = check(res, {
      'mitre status is 200': (r) => r.status === 200,
      'mitre duration < 150ms': (r) => r.timings.duration < 150,
    });
    errorRate.add(!ok);
  }

  sleep(2);
}
