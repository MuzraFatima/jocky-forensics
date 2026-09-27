/**
 * JOCKY Forensic Framework — Centralized API Client & Routing Helper
 * 
 * Dynamically resolves backend base URL for:
 * 1. Local development (Vite proxy to http://127.0.0.1:8000)
 * 2. Standalone cloud deployments (via VITE_API_URL, e.g. Render, Railway, AWS, Fly.io)
 * 3. Unified single-origin deployments (FastAPI serving static Vite build)
 */

export const getApiBaseUrl = () => {
  // 1. Explicit deployment environment variable takes highest priority
  if (import.meta.env.VITE_API_URL) {
    return import.meta.env.VITE_API_URL.replace(/\/+$/, '');
  }

  // 2. Browser runtime:
  // If Vite dev server is running, the proxy in vite.config.js maps '/api' to http://127.0.0.1:8000
  // If deployed on single origin (e.g. FastAPI serving frontend), relative path '' routes directly to backend
  return '';
};

export const API_BASE = getApiBaseUrl();

/**
 * Builds a resolved API URL for a given relative endpoint path.
 * @param {string} endpoint - e.g. "/api/auth/login" or "api/auth/register"
 * @returns {string} Fully resolved path
 */
export const apiUrl = (endpoint) => {
  const cleanEndpoint = endpoint.startsWith('/') ? endpoint : `/${endpoint}`;
  const base = getApiBaseUrl();
  return base ? `${base}${cleanEndpoint}` : cleanEndpoint;
};

/**
 * Centralized fetch wrapper that injects Content-Type, Bearer token, and handles errors.
 */
export const apiFetch = async (endpoint, options = {}) => {
  const url = apiUrl(endpoint);
  const headers = {
    'Content-Type': 'application/json',
    ...(options.headers || {}),
  };

  // Attach session token from storage if available and not explicitly provided
  if (!headers['Authorization'] && typeof window !== 'undefined') {
    try {
      const stored = localStorage.getItem('jocky_session') || sessionStorage.getItem('jocky_session');
      if (stored) {
        const parsed = JSON.parse(stored);
        if (parsed?.token) {
          headers['Authorization'] = `Bearer ${parsed.token}`;
        }
      }
    } catch {
      // Ignore JSON parse errors
    }
  }

  return fetch(url, {
    ...options,
    headers,
  });
};

/**
 * Returns the effective external server URL for endpoint agent pairing.
 */
export const getExternalServerUrl = () => {
  if (import.meta.env.VITE_API_URL) {
    return import.meta.env.VITE_API_URL.replace(/\/+$/, '');
  }
  if (typeof window !== 'undefined') {
    // If running in local Vite dev server (usually :5173 or :3000), backend is at 8000
    if (window.location.port === '5173' || window.location.port === '3000') {
      return `${window.location.protocol}//${window.location.hostname}:8000`;
    }
    return window.location.origin;
  }
  return 'http://127.0.0.1:8000';
};

export const api = {
  get: (endpoint, options = {}) => apiFetch(endpoint, { ...options, method: 'GET' }),
  post: (endpoint, body, options = {}) => apiFetch(endpoint, {
    ...options,
    method: 'POST',
    body: typeof body === 'string' ? body : JSON.stringify(body),
  }),
  login: async (credentials) => {
    const res = await apiFetch('/api/auth/login', {
      method: 'POST',
      body: JSON.stringify(credentials),
    });
    const data = await res.json();
    return { ok: res.ok, status: res.status, data };
  },
  register: async (userData) => {
    const res = await apiFetch('/api/auth/register', {
      method: 'POST',
      body: JSON.stringify(userData),
    });
    const data = await res.json();
    return { ok: res.ok, status: res.status, data };
  },
  logout: async (tokenData) => {
    const res = await apiFetch('/api/auth/logout', {
      method: 'POST',
      body: JSON.stringify(tokenData),
    });
    const data = await res.json();
    return { ok: res.ok, status: res.status, data };
  },

  // ─── Endpoint Agent API Methods ──────────────────────────────────────────
  generatePairingCode: async (deviceName = null) => {
    const payload = deviceName ? { device_name: deviceName } : {};
    const res = await apiFetch('/api/agents/pairing/generate', {
      method: 'POST',
      body: JSON.stringify(payload),
    });
    const data = await res.json();
    return { ok: res.ok, status: res.status, data };
  },
  getDevices: async () => {
    const res = await apiFetch('/api/agents/devices', {
      method: 'GET',
    });
    const data = await res.json();
    return { ok: res.ok, status: res.status, data };
  },
  revokeDevice: async (deviceId) => {
    const res = await apiFetch(`/api/agents/devices/${encodeURIComponent(deviceId)}/revoke`, {
      method: 'POST',
    });
    const data = await res.json();
    return { ok: res.ok, status: res.status, data };
  },
  executeJocky: async (script, deviceId = null, waitTimeout = 60) => {
    const payload = {
      script,
      wait_timeout: waitTimeout,
    };
    if (deviceId) {
      payload.device_id = deviceId;
    }
    const res = await apiFetch('/api/jocky/execute', {
      method: 'POST',
      body: JSON.stringify(payload),
    });
    const data = await res.json();
    return { ok: res.ok, status: res.status, data };
  },
};

export default api;
