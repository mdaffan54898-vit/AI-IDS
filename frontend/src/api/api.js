import axios from 'axios';

const API_BASE_URL = 'http://localhost:8000'; // FastAPI backend URL

export const api = axios.create({
  baseURL: API_BASE_URL,
});

// Endpoints
export const endpoints = {
  getMetrics: '/api/metrics',
  getAlerts: '/api/alerts',
  getIDSStatus: '/api/ids-status',
  acknowledgeAlert: (id) => `/api/alerts/${id}/acknowledge`,
  blockIP: (ip) => `/api/block-ip/${ip}`,
  // generateRule removed - handled server-side via API directly when needed
  getReports: '/api/reports',
  downloadReport: '/api/reports/download',
  startIDS: '/api/start-ids',
  stopIDS: '/api/stop-ids',
  getInterfaces: '/api/interfaces',
  getSettings: '/api/settings',
  updateSettings: '/api/settings',
};

// Include optional API key from localStorage under X-API-Key header
const LOCAL_API_KEY = 'AI_IDS_API_KEY';

// Attach API key header automatically if present
api.interceptors.request.use((config) => {
  try {
    const key = localStorage.getItem(LOCAL_API_KEY);
    if (key) {
      config.headers = config.headers || {};
      config.headers['X-API-Key'] = key;
    }
  } catch (e) {
    // ignore localStorage errors (e.g., SSR)
  }
  return config;
});

// Helper to set/remove API key for the frontend client
export function setApiKey(key) {
  try {
    if (key) {
      localStorage.setItem(LOCAL_API_KEY, key);
    } else {
      localStorage.removeItem(LOCAL_API_KEY);
    }
  } catch (e) {
    // ignore
  }
}