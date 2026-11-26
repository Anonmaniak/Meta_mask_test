import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { buildCsp, backendOrigins } from '../csp.config.ts';

const directive = (csp: string, name: string) =>
  csp.split(';').map((p) => p.trim()).find((p) => p.startsWith(`${name} `)) || '';

describe('security policy (Content-Security-Policy)', () => {
  const prod = buildCsp({ backendUrl: 'https://zyphra-chat-api.onrender.com/api', dev: false });

  it('production only talks to this site and the configured backend (https + wss)', () => {
    assert.equal(
      directive(prod, 'connect-src'),
      "connect-src 'self' https://zyphra-chat-api.onrender.com wss://zyphra-chat-api.onrender.com"
    );
    assert.ok(!prod.includes('localhost'));
    assert.ok(!/connect-src[^;]*\bhttps:(?!\/\/)/.test(prod), 'no blanket https: allowance');
  });

  it('production scripts: own files and WebAssembly only (no inline scripts, no eval)', () => {
    assert.equal(directive(prod, 'script-src'), "script-src 'self' 'wasm-unsafe-eval'");
    assert.ok(prod.includes('upgrade-insecure-requests'));
    assert.equal(directive(prod, 'object-src'), "object-src 'none'");
    assert.equal(directive(prod, 'frame-src'), "frame-src 'none'");
  });

  it('fonts embedded by the build (data: URLs) are allowed', () => {
    assert.equal(directive(prod, 'font-src'), "font-src 'self' data:");
  });

  it('decrypted videos, voice clips and images can be shown (blob: URLs)', () => {
    assert.equal(directive(prod, 'media-src'), "media-src 'self' blob:");
    assert.equal(directive(prod, 'img-src'), "img-src 'self' data: blob:");
  });

  it('local development also allows localhost and the hot-reload helper', () => {
    const dev = buildCsp({ backendUrl: 'http://localhost:10000/api', dev: true });
    assert.ok(directive(dev, 'connect-src').includes('ws://localhost:*'));
    assert.ok(directive(dev, 'script-src').includes("'unsafe-inline'"));
    assert.ok(!dev.includes('upgrade-insecure-requests'));
  });

  it('a local production build against a local backend works (no forced https)', () => {
    const local = buildCsp({ backendUrl: 'http://localhost:10000/api', dev: false });
    assert.ok(directive(local, 'connect-src').includes('http://localhost:10000'));
    assert.ok(!local.includes('upgrade-insecure-requests'));
  });

  it('refuses an insecure or broken backend address in production', () => {
    assert.throws(() => backendOrigins('http://zyphra-chat-api.onrender.com/api', false), /https/);
    assert.throws(() => backendOrigins('not a url', false), /valid URL/);
    assert.equal(backendOrigins('', false), null);
  });
});
