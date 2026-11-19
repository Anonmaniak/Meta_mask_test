import { spawnSync } from 'child_process';

console.log('============================================================');
console.log('  ZYPHRA CHAT FRONTEND — AUTOMATED SETUP & DEV BOOTSTRAP');
console.log('============================================================');
console.log('[1/2] Checking & updating npm dependencies (npm install)...');

const isWin = process.platform === 'win32';
const installCommand = isWin ? 'npm.cmd install' : 'npm install';

const installResult = spawnSync(installCommand, {
  stdio: 'inherit',
  shell: true,
});

if (installResult.status !== 0) {
  console.warn('[WARN] npm install exited with a warning; continuing to Vite...');
} else {
  console.log('[OK] Frontend dependencies verified.');
}

console.log('[2/2] Launching Vite development server (http://localhost:5173)...');
console.log('============================================================');
