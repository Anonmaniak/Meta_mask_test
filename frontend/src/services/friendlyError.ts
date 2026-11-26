/**
 * Turns an error into a short, plain message that is safe to show to members.
 *
 * Members are not technical, and raw errors can reveal internals (encryption
 * protocol details, device or key identifiers, HTTP codes, server stack traces).
 * Plain server messages such as "Username already taken" are passed through;
 * anything technical is replaced with the friendly fallback. The full error is
 * still logged to the browser console for debugging.
 */
const TECHNICAL_PATTERN =
  /\b(mls|olm|e2ee|siwe|eip-?\d+|keypackage|key ?package|prekey|pre-key|ratchet|epoch|treekem|welcome message|ed25519|curve25519|x25519|hpke|sha-?\d+|ciphertext|plaintext|wireformat|wire bytes|vault|signature|nonce|digest|pickle|olm session|device_id|user_id|usr_[a-z0-9]|0x[0-9a-f]{12,}|http \d{3}|traceback|exception|stack|sql|psycopg|database|asyncpg|undefined|null|nan|json|html|typeerror|referenceerror|syntaxerror|failed to fetch|networkerror|cors|rpc|abi|payload|malformed|corrupted|wasm)\b/i;

export function friendlyError(err: unknown, fallback: string): string {
  const raw =
    typeof err === 'string'
      ? err
      : err && typeof err === 'object' && 'message' in err
        ? String((err as { message?: unknown }).message ?? '')
        : '';
  if (raw) console.warn('[zyphra]', err);
  const msg = raw.trim();
  if (!msg) return fallback;
  if (msg.length > 180) return fallback;
  if (TECHNICAL_PATTERN.test(msg)) {
    if (/failed to fetch|networkerror/i.test(msg)) {
      return 'Could not reach the server. Check your internet connection and try again.';
    }
    return fallback;
  }
  return msg;
}
