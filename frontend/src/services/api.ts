import type { HealthResponse } from '../types';
import { resilientFetch } from './resilientFetch.ts';

const envBackend =
  typeof import.meta !== 'undefined'
    ? (import.meta as any).env?.VITE_BACKEND_URL || (import.meta as any).env?.VITE_API_URL
    : '';

const DEFAULT_BACKEND_URL =
  (envBackend && (envBackend.endsWith('/api') ? envBackend : `${envBackend.replace(/\/+$/, '')}/api`)) ||
  (typeof window !== 'undefined'
    ? window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1'
      ? 'http://localhost:10000/api'
      : `${window.location.origin}/api`
    : 'http://localhost:10000/api');

export function getBaseApiUrl(): string {
  // The backend address comes only from the build settings (VITE_BACKEND_URL) or this site's own
  // address. A value saved in the browser can no longer redirect API calls (and sign-in tokens)
  // to another server; any old saved value is cleared.
  if (typeof localStorage !== 'undefined') {
    try {
      localStorage.removeItem('backend_url');
    } catch {
      /* storage unavailable: nothing to clear */
    }
  }
  return DEFAULT_BACKEND_URL;
}

export async function fetchHealth(): Promise<HealthResponse> {
  const base = getBaseApiUrl();
  const res = await fetch(`${base}/health`, { cache: 'no-store' });
  if (!res.ok) throw new Error(`Health check failed: HTTP ${res.status}`);
  return res.json();
}

/**
 * Fire-and-forget wake-up call, made once when the app loads. `deep=1` makes the
 * backend touch the database too, so a sleeping Render instance / Neon compute is
 * already awake (and pooled connections are fresh) by the time the first real
 * request is sent. Never throws.
 */
export function warmUpBackend(): void {
  const base = getBaseApiUrl();
  resilientFetch(`${base}/health?deep=1`, { cache: 'no-store' }, { budgetMs: 45000 }).catch(() => { });
}