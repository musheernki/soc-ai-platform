(async function boot() {
  const user = SOC.user();
  if (!SOC.token()) {
    location.href = '/login';
    return;
  }
  const me = await SOC.api('/api/auth/me');
  if (!me.ok) {
    SOC.clear();
    location.href = '/login';
    return;
  }
  const payload = await me.json();
  SOC.setSession({ user: payload.user, access_token: SOC.token() });
  const who = document.getElementById('who');
  if (who) who.textContent = payload.user.name + ' · ' + payload.user.role;
  document.querySelectorAll('#side-nav a[data-admin]').forEach((el) => {
    el.style.display = payload.user.role === 'admin' ? '' : 'none';
  });
  document.querySelectorAll('#side-nav a[data-user]').forEach((el) => {
    el.style.display = payload.user.role === 'user' ? '' : 'none';
  });
  document.querySelectorAll('#side-nav a').forEach((el) => {
    if (el.getAttribute('href') === location.pathname) el.classList.add('active');
  });
  const logout = document.getElementById('logout-link');
  if (logout) {
    logout.addEventListener('click', async (e) => {
      e.preventDefault();
      await SOC.api('/api/auth/logout', { method: 'POST' });
      SOC.clear();
      location.href = '/login';
    });
  }
  if (window.io) {
    const socket = io({ transports: ['websocket', 'polling'] });
    socket.on('security_alert', (alert) => {
      if (payload.user.role !== 'admin') return;
      const bar = document.createElement('div');
      bar.className = 'alert alert-danger glass mt-2';
      bar.textContent = 'Live alert: ' + alert.severity + ' · ' + (alert.email || 'unknown') + ' · score ' + alert.risk_score;
      const main = document.querySelector('.main');
      if (main) main.prepend(bar);
      setTimeout(() => bar.remove(), 8000);
    });
  }
})();
