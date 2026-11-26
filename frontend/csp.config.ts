/**
 * Content-Security-Policy for the Zyphra web app, written into index.html at build time.
 *
 * The page may only load its own scripts, styles and fonts, and may only talk to the backend set in
 * VITE_BACKEND_URL (https + wss). Local development additionally allows localhost. This limits the
 * damage any injected script could do: it cannot load code from elsewhere or send data to other sites.
 */

export interface CspOptions {
  /** VITE_BACKEND_URL (or VITE_API_URL), e.g. https://zyphra-chat-api.onrender.com/api */
  backendUrl?: string;
  /** true for `vite` / `vite dev`, false for production builds */
  dev: boolean;
}

/** https://x/api -> { http: 'https://x', ws: 'wss://x' }. Throws on anything unsafe in production. */
export function backendOrigins(backendUrl: string | undefined, dev: boolean): { http: string; ws: string } | null {
  const raw = (backendUrl || '').trim();
  if (!raw) return null; // backend served from the same site: 'self' covers it
  let u: URL;
  try {
    u = new URL(raw);
  } catch {
    throw new Error(`VITE_BACKEND_URL is not a valid URL: "${raw}"`);
  }
  const isLocal = ['localhost', '127.0.0.1', '[::1]'].includes(u.hostname);
  if (u.protocol !== 'https:' && !(u.protocol === 'http:' && (isLocal || dev))) {
    throw new Error(`VITE_BACKEND_URL must use https:// in production (got "${raw}")`);
  }
  const http = `${u.protocol}//${u.host}`;
  const ws = `${u.protocol === 'https:' ? 'wss:' : 'ws:'}//${u.host}`;
  return { http, ws };
}

export function buildCsp({ backendUrl, dev }: CspOptions): string {
  const backend = backendOrigins(backendUrl, dev);
  const connect = ["'self'"];
  if (backend) connect.push(backend.http, backend.ws);
  if (dev) connect.push('http://localhost:*', 'ws://localhost:*', 'http://127.0.0.1:*', 'ws://127.0.0.1:*');

  const directives: Array<[string, string[]]> = [
    ['default-src', ["'self'"]],
    // 'wasm-unsafe-eval' lets the encryption library (WebAssembly) run; no other eval is allowed.
    // Dev also needs 'unsafe-inline' for Vite's hot-reload helper.
    ['script-src', dev ? ["'self'", "'wasm-unsafe-eval'", "'unsafe-inline'"] : ["'self'", "'wasm-unsafe-eval'"]],
    // React sets inline style attributes throughout the app.
    ['style-src', ["'self'", "'unsafe-inline'"]],
    // Small font files are embedded in the stylesheet by the build (data: URLs).
    ['font-src', ["'self'", 'data:']],
    // Decrypted images and previews are shown from blob: URLs.
    ['img-src', ["'self'", 'data:', 'blob:']],
    // Decrypted videos and voice clips play from blob: URLs.
    ['media-src', ["'self'", 'blob:']],
    ['connect-src', connect],
    ['worker-src', ["'self'", 'blob:']],
    ['manifest-src', ["'self'"]],
    ['frame-src', ["'none'"]],
    ['object-src', ["'none'"]],
    ['base-uri', ["'self'"]],
    ['form-action', ["'self'"]],
  ];
  const parts = directives.map(([k, v]) => `${k} ${v.join(' ')}`);
  // Force https for every request in production, unless this is a local test build against a local backend.
  if (!dev && (!backend || backend.http.startsWith('https://'))) parts.push('upgrade-insecure-requests');
  return parts.join('; ') + ';';
}
