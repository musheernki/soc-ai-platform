const SOC = {
  token() {
    return localStorage.getItem('soc_token') || '';
  },
  user() {
    try { return JSON.parse(localStorage.getItem('soc_user') || 'null'); } catch { return null; }
  },
  setSession(data) {
    if (data.access_token) localStorage.setItem('soc_token', data.access_token);
    if (data.user) localStorage.setItem('soc_user', JSON.stringify(data.user));
  },
  clear() {
    localStorage.removeItem('soc_token');
    localStorage.removeItem('soc_user');
  },
  async api(url, options = {}) {
    const headers = Object.assign({ 'Content-Type': 'application/json' }, options.headers || {});
    const token = SOC.token();
    if (token) headers.Authorization = 'Bearer ' + token;
    return fetch(url, Object.assign({ credentials: 'include' }, options, { headers }));
  }
};
