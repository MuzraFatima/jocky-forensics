/**
 * JOCKY Forensic Framework — Centralized API Client & Routing Helper
 * 
 * Dynamically resolves backend base URL for:
 * 1. Local development (http://127.0.0.1:8000 / Vite proxy)
 * 2. Standalone cloud deployments (via VITE_API_BASE_URL / VITE_API_URL, e.g. Render)
 * 3. Production Netlify live frontend (https://jocky-forensic.netlify.app -> https://jocky-forensics.onrender.com)
 */

export const getApiBaseUrl = () => {
  // 1. Explicit deployment environment variable takes highest priority
  const envUrl = import.meta.env.VITE_API_BASE_URL || import.meta.env.VITE_API_URL;
  if (envUrl && typeof envUrl === 'string' && envUrl.trim()) {
    return envUrl.trim().replace(/\/+$/, '').replace(/\/api$/, '');
  }

  // 2. Browser runtime inspection
  if (typeof window !== 'undefined') {
    const hostname = window.location.hostname;
    // Local development
    const isLocal = hostname === 'localhost' || hostname === '127.0.0.1' || hostname === '0.0.0.0' || hostname.startsWith('192.168.');
    if (isLocal) {
      return 'http://127.0.0.1:8000';
    }

    // Live Netlify production deployment
    if (hostname.includes('netlify.app')) {
      return 'https://jocky-forensics.onrender.com';
    }
  }

  // 3. Fallback for production builds
  if (import.meta.env.PROD) {
    return 'https://jocky-forensics.onrender.com';
  }

  return 'http://127.0.0.1:8000';
};

export const API_BASE = getApiBaseUrl();

/**
 * Builds a resolved API URL for a given relative endpoint path.
 * @param {string} endpoint - e.g. "/api/auth/login" or "api/auth/register"
 * @returns {string} Fully resolved path
 */
export const apiUrl = (endpoint) => {
  if (endpoint.startsWith('http://') || endpoint.startsWith('https://')) {
    return endpoint;
  }
  const cleanEndpoint = endpoint.startsWith('/') ? endpoint : `/${endpoint}`;
  const base = getApiBaseUrl();
  return base ? `${base}${cleanEndpoint}` : cleanEndpoint;
};

/**
 * Safely parses response as JSON, falling back to a structured error if HTML/text is returned.
 */
async function parseJsonResponse(res, endpointName = 'endpoint') {
  const contentType = res.headers.get('content-type') || '';
  if (contentType.includes('application/json')) {
    try {
      return await res.json();
    } catch (e) {
      return {
        success: false,
        error: `Failed to parse backend JSON response (${res.status}): ${e.message}`,
      };
    }
  }

  // Non-JSON response received (e.g. HTML 404/502 from CDN or reverse proxy)
  const text = await res.text();
  const cleanSnippet = text.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim().slice(0, 160);
  return {
    success: false,
    error: `Backend returned non-JSON response (${res.status} ${res.statusText || 'Error'}). Target: ${apiUrl(endpointName)}. Detail: ${cleanSnippet || 'HTML page received'}`,
    raw: text,
  };
}

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
  const base = getApiBaseUrl();
  if (base && !base.includes('localhost') && !base.includes('127.0.0.1')) {
    return base;
  }
  if (typeof window !== 'undefined') {
    if (window.location.port === '5173' || window.location.port === '3000') {
      return `${window.location.protocol}//${window.location.hostname}:8000`;
    }
    if (window.location.hostname.includes('netlify.app')) {
      return 'https://jocky-forensics.onrender.com';
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
    try {
      const res = await apiFetch('/api/auth/login', {
        method: 'POST',
        body: JSON.stringify(credentials),
      });
      const data = await parseJsonResponse(res, '/api/auth/login');
      return { ok: res.ok && data?.success !== false, status: res.status, data };
    } catch (err) {
      return {
        ok: false,
        status: 0,
        data: {
          success: false,
          error: `Network error connecting to JOCKY backend at ${getApiBaseUrl() || 'local server'}: ${err.message}`,
        },
      };
    }
  },
  register: async (userData) => {
    try {
      const res = await apiFetch('/api/auth/register', {
        method: 'POST',
        body: JSON.stringify(userData),
      });
      const data = await parseJsonResponse(res, '/api/auth/register');
      return { ok: res.ok && data?.success !== false, status: res.status, data };
    } catch (err) {
      return {
        ok: false,
        status: 0,
        data: {
          success: false,
          error: `Network error connecting to JOCKY backend at ${getApiBaseUrl() || 'local server'}: ${err.message}`,
        },
      };
    }
  },
  logout: async (tokenData) => {
    try {
      const res = await apiFetch('/api/auth/logout', {
        method: 'POST',
        body: JSON.stringify(tokenData),
      });
      const data = await parseJsonResponse(res, '/api/auth/logout');
      return { ok: res.ok, status: res.status, data };
    } catch (err) {
      return { ok: false, status: 0, data: { success: false, error: err.message } };
    }
  },

  // ─── Endpoint Agent API Methods ──────────────────────────────────────────
  generatePairingCode: async (deviceName = null) => {
    try {
      const payload = deviceName ? { device_name: deviceName } : {};
      const res = await apiFetch('/api/agents/pairing/generate', {
        method: 'POST',
        body: JSON.stringify(payload),
      });
      const data = await parseJsonResponse(res, '/api/agents/pairing/generate');
      return { ok: res.ok, status: res.status, data };
    } catch (err) {
      return { ok: false, status: 0, data: { success: false, error: err.message } };
    }
  },
  getDevices: async () => {
    try {
      const res = await apiFetch('/api/agents/devices', {
        method: 'GET',
      });
      const data = await parseJsonResponse(res, '/api/agents/devices');
      return { ok: res.ok, status: res.status, data };
    } catch (err) {
      return { ok: false, status: 0, data: { success: false, error: err.message } };
    }
  },
  revokeDevice: async (deviceId) => {
    try {
      const res = await apiFetch(`/api/agents/devices/${encodeURIComponent(deviceId)}/revoke`, {
        method: 'POST',
      });
      const data = await parseJsonResponse(res, `/api/agents/devices/${deviceId}/revoke`);
      return { ok: res.ok, status: res.status, data };
    } catch (err) {
      return { ok: false, status: 0, data: { success: false, error: err.message } };
    }
  },
  executeJocky: async (script, deviceId = null, waitTimeout = 60) => {
    try {
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
      const data = await parseJsonResponse(res, '/api/jocky/execute');
      return { ok: res.ok, status: res.status, data };
    } catch (err) {
      return { ok: false, status: 0, data: { success: false, error: err.message } };
    }
  },
};

export default api;

/**
 * Session token from storage, as an Authorization header (or an empty object).
 */
export const authHeaders = () => {
  try {
    const stored = sessionStorage.getItem('jocky_session') || localStorage.getItem('jocky_session');
    const token = stored ? JSON.parse(stored)?.token : null;
    return token ? { Authorization: `Bearer ${token}` } : {};
  } catch {
    return {};
  }
};

/**
 * fetch() for an absolute API URL with the session token attached. A 401 from
 * a protected endpoint means the session is gone (for example after a backend
 * restart), so the app is told to send the user back to the login screen.
 */
export const authFetch = async (url, options = {}) => {
  const response = await fetch(url, {
    ...options,
    headers: { ...authHeaders(), ...(options.headers || {}) },
  });
  if (response.status === 401 && !String(url).includes('/api/auth/') && typeof window !== 'undefined') {
    window.dispatchEvent(new CustomEvent('jocky:session-expired'));
  }
  return response;
};

/**
 * Download a protected file. window.open() cannot send the Authorization
 * header, so the file is fetched with the token and saved from a blob.
 */
export const downloadWithAuth = async (url, fallbackName = 'jocky-download') => {
  const response = await authFetch(url);
  if (!response.ok) {
    throw new Error(`Download failed (${response.status})`);
  }
  const disposition = response.headers.get('content-disposition') || '';
  const match = disposition.match(/filename="?([^";]+)"?/i);
  const blob = await response.blob();
  const objectUrl = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = objectUrl;
  link.download = match ? match[1] : fallbackName;
  document.body.appendChild(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(objectUrl), 1000);
};
