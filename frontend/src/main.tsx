import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import '@fontsource-variable/hanken-grotesk/wght.css'
import './index.css'
import App from './App.tsx'
import WelcomeSplash from './components/WelcomeSplash.tsx'
import { warmUpBackend } from './services/api.ts'

// Wake the backend + database in the background while the page (and, on a first
// visit, the welcome animation) loads, so the first real request does not fail.
warmUpBackend()

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <App />
    <WelcomeSplash />
  </StrictMode>,
)