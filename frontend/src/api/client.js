import axios from 'axios';

/**
 * Standard Axios API client configured for Sentinel AI Backend.
 * Uses environment variable `VITE_API_BASE_URL` or fallback to localhost:8000.
 */
const apiClient = axios.create({
  baseURL: import.meta.env.VITE_API_BASE_URL || import.meta.env.VITE_API_URL || 'http://localhost:8000',
  headers: {
    'Content-Type': 'application/json',
  },
});

export default apiClient;
