// API Configuration
// When deployed together (single origin), API_BASE is empty string '', making requests relative (/api/...)
// When frontend is hosted separately (e.g. Vercel) from backend (e.g. Render), VITE_API_URL can be set
export const API_BASE = import.meta.env.VITE_API_URL || '';
