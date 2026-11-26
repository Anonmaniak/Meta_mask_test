import react from '@vitejs/plugin-react'
import { defineConfig, loadEnv, type Plugin } from 'vite'
import { buildCsp } from './csp.config.ts'

/** Writes the Content-Security-Policy into index.html (tight in production, relaxed for local dev). */
function zyphraCsp(backendUrl: string | undefined, dev: boolean): Plugin {
  return {
    name: 'zyphra-csp',
    transformIndexHtml(html) {
      if (!html.includes('__ZYPHRA_CSP__')) {
        throw new Error('index.html is missing the __ZYPHRA_CSP__ placeholder for the security policy')
      }
      return html.replace('__ZYPHRA_CSP__', buildCsp({ backendUrl, dev }))
    },
  }
}

// https://vite.dev/config/
export default defineConfig(({ command, mode }) => {
  const env = loadEnv(mode, process.cwd(), 'VITE_')
  const backendUrl = env.VITE_BACKEND_URL || env.VITE_API_URL
  // The site (Vercel) and the API (Render) are on different addresses. Without VITE_BACKEND_URL the app
  // would call https://<site>/api, which only returns the web page, and every user would see errors.
  // So a production build stops here. Set ZYPHRA_SAME_ORIGIN_BACKEND=1 only if the API really is served
  // from the same site.
  if (command === 'build' && !backendUrl && !process.env.ZYPHRA_SAME_ORIGIN_BACKEND) {
    throw new Error(
      'VITE_BACKEND_URL is not set. Set it in Vercel (Project Settings > Environment Variables) to ' +
      'https://<your-render-service>.onrender.com/api and build again.'
    )
  }
  return {
    plugins: [react(), zyphraCsp(backendUrl, command === 'serve')],
    optimizeDeps: {
      exclude: ['@towns-protocol/vodozemac'],
    },
    server: {
      proxy: {
        '/api': {
          target: 'http://localhost:10000',
          changeOrigin: true,
        },
        '/ws': {
          target: 'ws://localhost:10000',
          ws: true,
        },
      },
    },
  }
})