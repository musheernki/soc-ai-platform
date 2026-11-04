(async function () {
  const res = await SOC.api('/api/dashboard/admin');
  if (res.status === 403) {
    location.href = '/app/user';
    return;
  }
  const data = await res.json();
  const k = data.kpis || {};
  const items = [
    ['Registered users', k.registered_users],
    ['Login attempts', k.total_login_attempts],
    ['Successful logins', k.successful_logins],
    ['Failed logins', k.failed_logins],
    ['Suspicious activities', k.suspicious_activities],
    ['High-risk threats', k.high_risk_threats],
    ['Critical alerts', k.critical_alerts]
  ];
  document.getElementById('kpis').innerHTML = items.map(([label, val]) =>
    `<div class="col-6 col-xl-3"><div class="glass kpi"><div class="muted small">${label}</div><div class="value">${val ?? 0}</div></div></div>`
  ).join('');

  const c = data.charts || { labels: [], successful: [], failed: [], threats: [], severity: {} };
  new Chart(document.getElementById('activityChart'), {
    type: 'line',
    data: { labels: c.labels, datasets: [
      { label: 'Successful', data: c.successful, borderColor: '#3ee0a0', tension: 0.35 },
      { label: 'Failed', data: c.failed, borderColor: '#ff5d7a', tension: 0.35 }
    ]},
    options: { plugins: { legend: { labels: { color: '#e8f1ff' } } }, scales: { x: { ticks: { color: '#8aa0c0' } }, y: { ticks: { color: '#8aa0c0' } } } }
  });
  new Chart(document.getElementById('successFailChart'), {
    type: 'bar',
    data: { labels: ['Successful', 'Failed'], datasets: [{ data: [k.successful_logins || 0, k.failed_logins || 0], backgroundColor: ['#3ee0a0', '#ff5d7a'] }] },
    options: { plugins: { legend: { display: false } } }
  });
  new Chart(document.getElementById('severityChart'), {
    type: 'doughnut',
    data: { labels: ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL'], datasets: [{ data: [c.severity.LOW, c.severity.MEDIUM, c.severity.HIGH, c.severity.CRITICAL], backgroundColor: ['#3ee0a0', '#ffb020', '#ff8aa0', '#ff3b5c'] }] }
  });
  new Chart(document.getElementById('threatTrendChart'), {
    type: 'line',
    data: { labels: c.labels, datasets: [{ label: 'Alerts', data: c.threats, borderColor: '#5eeaff', tension: 0.35 }] },
    options: { plugins: { legend: { labels: { color: '#e8f1ff' } } } }
  });
  const rows = (data.recent_events || []).map((e) =>
    `<tr><td>${e.timestamp || ''}</td><td>${e.email || ''}</td><td>${e.ip_address}</td><td>${e.login_status}</td><td><span class="badge badge-${e.severity || 'LOW'}">${e.severity || '-'}</span></td><td>${e.risk_score ?? '-'}</td></tr>`
  ).join('');
  document.getElementById('recent').innerHTML = '<thead><tr><th>Time</th><th>User</th><th>IP</th><th>Status</th><th>Severity</th><th>Score</th></tr></thead><tbody>' + rows + '</tbody>';
})();
