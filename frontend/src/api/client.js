const BASE = 'http://localhost:5000'

async function request(method, path, body) {
  const opts = {
    method,
    credentials: 'include',
    headers: body !== undefined ? { 'Content-Type': 'application/json' } : {},
  }
  if (body !== undefined) opts.body = JSON.stringify(body)

  const res = await fetch(`${BASE}${path}`, opts)

  if (!res.ok) {
    let message = `Request failed (${res.status})`
    try {
      const json = await res.json()
      if (json.error) message = json.error
    } catch (_) {}
    const err = new Error(message)
    err.status = res.status
    throw err
  }

  const text = await res.text()
  return text ? JSON.parse(text) : null
}

export const api = {
  get:    (path)        => request('GET',    path),
  post:   (path, body)  => request('POST',   path, body),
  delete: (path)        => request('DELETE', path),

  // Auth
  me:     ()            => api.get('/api/auth/me'),
  logout: ()            => api.post('/api/auth/logout'),

  // Clients
  listClients:   ()           => api.get('/api/clients'),
  getClient:     (id)         => api.get(`/api/clients/${id}`),
  createClient:  (data)       => api.post('/api/clients', data),
  deleteClient:  (id)         => api.delete(`/api/clients/${id}`),

  // Targets
  createTarget:       (data)  => api.post('/api/targets', data),
  getTarget:          (id)    => api.get(`/api/targets/${id}`),
  deleteTarget:       (id)    => api.delete(`/api/targets/${id}`),
  getVerificationInfo:(id)    => api.get(`/api/targets/${id}/verification-info`),
  verifyTarget:       (id, method) => api.post(`/api/targets/${id}/verify`, { method }),
  triggerScan:        (id)    => api.post(`/api/targets/${id}/scan`),

  // Scans
  getScan: (id) => api.get(`/api/scans/${id}`),
}
