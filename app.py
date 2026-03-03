from flask import Flask, request, jsonify
from flask_cors import CORS
from web3 import Web3
import os
import json
import threading
import time
import secrets
from datetime import datetime, timezone

try:
    import psycopg2
    import psycopg2.extras
    HAS_PSYCOPG2 = True
except ImportError:
    HAS_PSYCOPG2 = False

app = Flask(__name__)

# =============================================================
# ENVIRONMENT
# =============================================================
_raw_origins = os.getenv('FRONTEND_URL', 'https://zyphra.in')
FRONTEND_URL = _raw_origins.split(',')[0].strip()
_ALLOWED_ORIGINS = (
    [u.strip() for u in _raw_origins.split(',') if u.strip()]
    + ["http://localhost:3000", "http://localhost:5500",
       "http://127.0.0.1:5500", "http://localhost:8080"]
)

RPC_URL            = os.getenv('RPC_URL')
ADMIN_PRIVATE_KEY  = os.getenv('ADMIN_PRIVATE_KEY')
ADMIN_TOKEN        = os.getenv('ADMIN_TOKEN')
EXPECTED_CHAIN_ID  = os.getenv('EXPECTED_CHAIN_ID')
RUN_MONITOR        = os.getenv('RUN_MONITOR', '0')
DATABASE_URL       = os.getenv('DATABASE_URL')
FEE_WALLET_ENV     = os.getenv('FEE_WALLET')  # separate address for your 1% fee

VERIFICATION_CONFIRMATIONS = int(os.getenv('VERIFICATION_CONFIRMATIONS', 3))
FEE_PERCENTAGE             = float(os.getenv('FEE_PERCENTAGE', 1))
POLL_INTERVAL              = int(os.getenv('POLL_INTERVAL', 15))
MAX_GAS_WAIT_RETRIES       = int(os.getenv('MAX_GAS_WAIT_RETRIES', 10))
FORWARD_DEADLINE_SECONDS   = int(os.getenv('FORWARD_DEADLINE_SECONDS', 3600))  # 1 hour

# =============================================================
# CORS
# =============================================================
CORS(app, resources={
    r"/api/*": {
        "origins": _ALLOWED_ORIGINS,
        "methods": ["GET", "POST", "OPTIONS"],
        "allow_headers": ["Content-Type", "X-Client-Token", "X-Admin-Token"]
    }
})

# =============================================================
# BLOCKCHAIN
# =============================================================
if not RPC_URL:
    raise Exception("RPC_URL environment variable not set")

w3 = Web3(Web3.HTTPProvider(RPC_URL))
if not w3.is_connected():
    raise Exception(f"Failed to connect to blockchain: {RPC_URL}")

chain_id = int(w3.eth.chain_id)
if EXPECTED_CHAIN_ID and int(EXPECTED_CHAIN_ID) != chain_id:
    raise Exception(f"RPC chain_id={chain_id} but EXPECTED_CHAIN_ID={EXPECTED_CHAIN_ID}")

print(f"\u2705 Blockchain: chain_id={chain_id}, block={w3.eth.block_number}")

if not ADMIN_PRIVATE_KEY:
    raise Exception("ADMIN_PRIVATE_KEY not set")

escrow_account = w3.eth.account.from_key(ADMIN_PRIVATE_KEY)
escrow_address = escrow_account.address
balance_eth = w3.from_wei(w3.eth.get_balance(escrow_address), 'ether')
print(f"\u2705 Escrow wallet: {escrow_address}")
print(f"   Balance: {balance_eth} ETH")

fee_wallet = None
if FEE_WALLET_ENV:
    fee_wallet = Web3.to_checksum_address(FEE_WALLET_ENV)
    print(f"\u2705 Fee wallet: {fee_wallet}")
else:
    print("\u2139\ufe0f  FEE_WALLET not set — platform fees accumulate in escrow wallet")

# =============================================================
# DATABASE LAYER
# Supports PostgreSQL (production) with JSON file fallback (local dev)
# =============================================================
_json_lock = threading.Lock()
_JSON_FILE = os.path.join(os.getcwd(), 'data', 'transactions.json')
os.makedirs(os.path.dirname(_JSON_FILE), exist_ok=True)


def _now_iso():
    return datetime.now(timezone.utc).isoformat()


def _get_conn():
    if not (DATABASE_URL and HAS_PSYCOPG2):
        return None
    conn = psycopg2.connect(DATABASE_URL, sslmode='require')
    conn.autocommit = False
    return conn


def init_db():
    conn = _get_conn()
    if not conn:
        print("\u26a0\ufe0f  PostgreSQL not available — using local JSON fallback (not suitable for production)")
        return
    try:
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS transactions (
                tx_hash   TEXT PRIMARY KEY,
                data      JSONB NOT NULL,
                status    TEXT NOT NULL DEFAULT 'pending',
                updated_at TIMESTAMPTZ DEFAULT NOW()
            );
            CREATE INDEX IF NOT EXISTS idx_tx_status ON transactions(status);
        """)
        conn.commit()
        cur.close()
        print("\u2705 PostgreSQL database ready")
    except Exception as e:
        print(f"\u274c DB init error: {e}")
        conn.rollback()
    finally:
        conn.close()


def db_save(tx_data: dict):
    conn = _get_conn()
    if conn:
        try:
            cur = conn.cursor()
            cur.execute("""
                INSERT INTO transactions (tx_hash, data, status, updated_at)
                VALUES (%s, %s::jsonb, %s, NOW())
                ON CONFLICT (tx_hash) DO UPDATE
                    SET data = EXCLUDED.data,
                        status = EXCLUDED.status,
                        updated_at = NOW()
            """, (tx_data['tx_hash'], json.dumps(tx_data), tx_data.get('status', 'pending')))
            conn.commit()
            cur.close()
        except Exception as e:
            print(f"\u274c db_save: {e}")
            conn.rollback()
        finally:
            conn.close()
    else:
        with _json_lock:
            d = _json_load()
            d[tx_data['tx_hash']] = tx_data
            _json_write(d)


def db_get(tx_hash: str):
    conn = _get_conn()
    if conn:
        try:
            cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            cur.execute("SELECT data FROM transactions WHERE tx_hash = %s", (tx_hash,))
            row = cur.fetchone()
            cur.close()
            return dict(row['data']) if row else None
        except Exception as e:
            print(f"\u274c db_get: {e}")
            return None
        finally:
            conn.close()
    else:
        with _json_lock:
            return _json_load().get(tx_hash)


def db_get_active():
    """Only fetch non-terminal rows (used by monitor to avoid scanning completed txes)."""
    conn = _get_conn()
    if conn:
        try:
            cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            cur.execute("""
                SELECT data FROM transactions
                WHERE status NOT IN ('complete', 'refunded', 'failed')
                ORDER BY updated_at ASC
            """)
            rows = cur.fetchall()
            cur.close()
            return [dict(r['data']) for r in rows]
        except Exception as e:
            print(f"\u274c db_get_active: {e}")
            return []
        finally:
            conn.close()
    else:
        with _json_lock:
            d = _json_load()
        return [v for v in d.values()
                if v.get('status') not in ('complete', 'refunded', 'failed')]


def db_get_all():
    conn = _get_conn()
    if conn:
        try:
            cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            cur.execute("SELECT data FROM transactions ORDER BY updated_at DESC")
            rows = cur.fetchall()
            cur.close()
            return [dict(r['data']) for r in rows]
        except Exception as e:
            print(f"\u274c db_get_all: {e}")
            return []
        finally:
            conn.close()
    else:
        with _json_lock:
            return list(_json_load().values())


def db_update(tx_hash: str, updates: dict):
    """Merge partial updates into an existing transaction (atomic read-modify-write)."""
    conn = _get_conn()
    if conn:
        try:
            cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
            # Lock the row while we update it
            cur.execute(
                "SELECT data FROM transactions WHERE tx_hash = %s FOR UPDATE",
                (tx_hash,)
            )
            row = cur.fetchone()
            if not row:
                print(f"\u26a0\ufe0f  db_update: {tx_hash[:10]}... not found")
                conn.rollback()
                return
            tx_data = dict(row['data'])
            tx_data.update(updates)
            cur.execute("""
                UPDATE transactions
                SET data = %s::jsonb, status = %s, updated_at = NOW()
                WHERE tx_hash = %s
            """, (json.dumps(tx_data), tx_data.get('status', 'pending'), tx_hash))
            conn.commit()
            cur.close()
        except Exception as e:
            print(f"\u274c db_update: {e}")
            conn.rollback()
        finally:
            conn.close()
    else:
        with _json_lock:
            d = _json_load()
            if tx_hash in d:
                d[tx_hash].update(updates)
                _json_write(d)


def db_delete(tx_hash: str):
    conn = _get_conn()
    if conn:
        try:
            cur = conn.cursor()
            cur.execute("DELETE FROM transactions WHERE tx_hash = %s", (tx_hash,))
            conn.commit()
            cur.close()
        except Exception as e:
            print(f"\u274c db_delete: {e}")
            conn.rollback()
        finally:
            conn.close()
    else:
        with _json_lock:
            d = _json_load()
            d.pop(tx_hash, None)
            _json_write(d)


def _json_load():
    try:
        if os.path.exists(_JSON_FILE):
            with open(_JSON_FILE, 'r') as f:
                d = json.load(f)
            return d if isinstance(d, dict) else {}
    except Exception:
        pass
    return {}


def _json_write(data):
    try:
        with open(_JSON_FILE, 'w') as f:
            json.dump(data, f, indent=2)
    except Exception as e:
        print(f"\u26a0\ufe0f  JSON write error: {e}")


init_db()

# =============================================================
# AUTH
# =============================================================
def _admin_token():
    return request.headers.get('X-Admin-Token') or request.args.get('admin_token')


def _client_token():
    return request.headers.get('X-Client-Token') or request.args.get('token')


def is_admin():
    if not ADMIN_TOKEN:
        return False
    return secrets.compare_digest(str(_admin_token() or ''), str(ADMIN_TOKEN))


# =============================================================
# GAS HELPERS (EIP-1559)
# =============================================================
def get_gas_price():
    """
    Returns (max_fee_per_gas, max_priority_fee_per_gas).
    Falls back to legacy gasPrice if EIP-1559 is unavailable.
    """
    try:
        block = w3.eth.get_block('latest')
        base_fee = block.get('baseFeePerGas')
        if base_fee:
            try:
                priority = w3.eth.max_priority_fee
            except Exception:
                priority = w3.to_wei(2, 'gwei')
            max_fee = int(base_fee * 2) + priority
            return max_fee, priority
    except Exception:
        pass
    gp = w3.eth.gas_price
    return gp, 0


def estimate_gas(to_addr, value_wei):
    """Estimate gas for a plain ETH transfer with a 20% safety buffer."""
    try:
        gas = w3.eth.estimate_gas({
            'from': escrow_address,
            'to': to_addr,
            'value': value_wei
        })
        return int(gas * 1.2)
    except Exception:
        return 25000  # safe fallback for EOA transfers


def _raw_tx(signed):
    return getattr(signed, 'rawTransaction', None) or getattr(signed, 'raw_transaction', None)


# =============================================================
# MONITOR STEPS
# =============================================================

def step_pending(tx_hash, tx_data, current_block):
    """PENDING → VERIFIED: confirm escrow deposit on-chain."""
    try:
        receipt = w3.eth.get_transaction_receipt(tx_hash)
        if not receipt or receipt['status'] != 1:
            return
        confirmations = current_block - receipt['blockNumber']
        if confirmations < VERIFICATION_CONFIRMATIONS:
            return

        tx = w3.eth.get_transaction(tx_hash)

        if (tx.get('to') or '').lower() != escrow_address.lower():
            db_update(tx_hash, {'status': 'failed', 'error': 'Wrong destination address'})
            return
        if (tx.get('from') or '').lower() != tx_data['sender'].lower():
            db_update(tx_hash, {'status': 'failed', 'error': 'Sender address mismatch'})
            return
        if int(tx.get('value', 0)) != int(tx_data['total_paid_wei']):
            db_update(tx_hash, {'status': 'failed',
                                'error': f"Amount mismatch: expected {tx_data['total_paid_wei']} got {tx.get('value')}"})
            return

        db_update(tx_hash, {
            'status': 'verified',
            'escrow_block': receipt['blockNumber'],
            'verified_at': _now_iso(),
            'gas_wait_retries': 0,
        })
        print(f"\u2705 VERIFIED: {tx_hash[:10]}... ({confirmations} confirmations)")

    except Exception as e:
        print(f"\u26a0\ufe0f  step_pending {tx_hash[:10]}...: {e}")


def _check_deadline(tx_hash, tx_data):
    """If verified but stuck > FORWARD_DEADLINE_SECONDS, escalate to refund."""
    try:
        ts = tx_data.get('verified_at', '')
        if not ts:
            return False
        dt = datetime.fromisoformat(ts)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        elapsed = (datetime.now(timezone.utc) - dt).total_seconds()
        if elapsed > FORWARD_DEADLINE_SECONDS:
            db_update(tx_hash, {
                'status': 'refund_pending',
                'error': f'Deadline exceeded ({int(elapsed)}s). Initiating refund.',
                'refund_initiated_at': _now_iso(),
            })
            print(f"\u23f0 DEADLINE: {tx_hash[:10]}... → refund_pending")
            return True
    except Exception:
        pass
    return False


def step_verified(tx_hash, tx_data):
    """VERIFIED/WAIT_GAS → FORWARDING_PENDING: send escrow → destination tx."""
    try:
        destination = Web3.to_checksum_address(tx_data['destination'])
        recipient_wei = int(tx_data['recipient_amount_wei'])
        buffer_wei = int(tx_data.get('forward_gas_buffer_wei', '0'))

        max_fee, priority = get_gas_price()
        gas_limit = estimate_gas(destination, recipient_wei)
        estimated_cost = gas_limit * max_fee

        retries = int(tx_data.get('gas_wait_retries', 0))

        if estimated_cost > buffer_wei:
            if retries >= MAX_GAS_WAIT_RETRIES:
                # Too many retries — refund the user
                db_update(tx_hash, {
                    'status': 'refund_pending',
                    'error': f'Gas too high after {retries} retries. Refunding.',
                    'refund_initiated_at': _now_iso(),
                })
                print(f"\u21a9\ufe0f  {tx_hash[:10]}... max retries reached → refund_pending")
            else:
                db_update(tx_hash, {
                    'status': 'forward_wait_gas',
                    'gas_wait_retries': retries + 1,
                    'last_gas_needed_wei': str(estimated_cost),
                    'last_checked_at': _now_iso(),
                })
                print(f"\u23f8\ufe0f  {tx_hash[:10]}... gas buffer low (retry {retries+1}/{MAX_GAS_WAIT_RETRIES})")
            return

        # Funds flow:
        # user paid: recipient_wei + platform_fee_wei + forward_gas_buffer_wei
        # we forward: recipient_wei (exactly)
        # platform_fee_wei + leftover gas buffer stay in escrow wallet as revenue

        nonce = w3.eth.get_transaction_count(escrow_address, 'pending')

        # Build EIP-1559 transaction
        tx_params = {
            'to': destination,
            'value': recipient_wei,
            'nonce': nonce,
            'gas': gas_limit,
            'maxFeePerGas': max_fee,
            'maxPriorityFeePerGas': priority,
            'chainId': chain_id,
        }

        signed = w3.eth.account.sign_transaction(tx_params, ADMIN_PRIVATE_KEY)
        forward_hash = w3.eth.send_raw_transaction(_raw_tx(signed)).hex()

        platform_fee_wei = int(recipient_wei * FEE_PERCENTAGE / 100)

        db_update(tx_hash, {
            'status': 'forwarding_pending',
            'forward_tx_hash': forward_hash,
            'forwarded_at': _now_iso(),
            'platform_fee_wei': str(platform_fee_wei),
            'forward_gas_limit': gas_limit,
            'forward_max_fee_per_gas': str(max_fee),
        })
        print(f"\U0001f4e4 FORWARDED: {tx_hash[:10]}... → {forward_hash[:10]}...")

    except Exception as e:
        print(f"\u274c step_verified {tx_hash[:10]}...: {e}")
        # Don't mark as failed — retry next poll cycle


def step_forwarding(tx_hash, tx_data, current_block):
    """FORWARDING_PENDING → COMPLETE: confirm forward tx on-chain."""
    try:
        forward_hash = tx_data.get('forward_tx_hash')
        if not forward_hash:
            return

        receipt = w3.eth.get_transaction_receipt(forward_hash)
        if not receipt:
            return

        if receipt['status'] != 1:
            # Forward tx reverted on-chain — refund user
            db_update(tx_hash, {
                'status': 'refund_pending',
                'error': 'Forward transaction reverted on-chain. Initiating refund.',
                'refund_initiated_at': _now_iso(),
            })
            print(f"\u26a0\ufe0f  {tx_hash[:10]}... forward reverted → refund_pending")
            return

        confirmations = current_block - receipt['blockNumber']
        if confirmations < VERIFICATION_CONFIRMATIONS:
            return

        db_update(tx_hash, {
            'status': 'complete',
            'forward_block': receipt['blockNumber'],
            'completed_at': _now_iso(),
        })
        print(f"\U0001f389 COMPLETE: {tx_hash[:10]}...")

    except Exception as e:
        print(f"\u26a0\ufe0f  step_forwarding {tx_hash[:10]}...: {e}")


def step_refund(tx_hash, tx_data):
    """REFUND_PENDING → REFUNDING: send full refund (minus gas) back to sender."""
    try:
        sender = Web3.to_checksum_address(tx_data['sender'])
        total_paid_wei = int(tx_data['total_paid_wei'])

        max_fee, priority = get_gas_price()
        gas_limit = estimate_gas(sender, 0)
        gas_cost = gas_limit * max_fee

        refund_amount = total_paid_wei - gas_cost

        if refund_amount <= 0:
            db_update(tx_hash, {
                'status': 'failed',
                'error': f'Refund impossible: gas_cost ({gas_cost}) >= total_paid ({total_paid_wei}). Contact support.',
            })
            print(f"\u274c {tx_hash[:10]}... refund impossible (gas_cost={gas_cost} >= total={total_paid_wei})")
            return

        nonce = w3.eth.get_transaction_count(escrow_address, 'pending')
        refund_tx = {
            'to': sender,
            'value': refund_amount,
            'nonce': nonce,
            'gas': gas_limit,
            'maxFeePerGas': max_fee,
            'maxPriorityFeePerGas': priority,
            'chainId': chain_id,
        }
        signed = w3.eth.account.sign_transaction(refund_tx, ADMIN_PRIVATE_KEY)
        refund_hash = w3.eth.send_raw_transaction(_raw_tx(signed)).hex()

        db_update(tx_hash, {
            'status': 'refunding',
            'refund_tx_hash': refund_hash,
            'refund_amount_wei': str(refund_amount),
            'refund_gas_cost_wei': str(gas_cost),
        })
        print(f"\u21a9\ufe0f  REFUNDING: {tx_hash[:10]}... → {refund_hash[:10]}... ({w3.from_wei(refund_amount, 'ether')} ETH to {sender[:10]}...)")

    except Exception as e:
        print(f"\u274c step_refund {tx_hash[:10]}...: {e}")


def step_refunding(tx_hash, tx_data, current_block):
    """REFUNDING → REFUNDED: confirm refund tx on-chain."""
    try:
        refund_hash = tx_data.get('refund_tx_hash')
        if not refund_hash:
            return

        receipt = w3.eth.get_transaction_receipt(refund_hash)
        if not receipt or receipt['status'] != 1:
            return

        confirmations = current_block - receipt['blockNumber']
        if confirmations < VERIFICATION_CONFIRMATIONS:
            return

        db_update(tx_hash, {
            'status': 'refunded',
            'refunded_at': _now_iso(),
            'refund_block': receipt['blockNumber'],
        })
        print(f"\u2705 REFUNDED: {tx_hash[:10]}...")

    except Exception as e:
        print(f"\u26a0\ufe0f  step_refunding {tx_hash[:10]}...: {e}")


def auto_cleanup(tx_hash, tx_data):
    """Delete terminal transactions 5 min after completion/refund."""
    try:
        key = 'completed_at' if tx_data.get('status') == 'complete' else 'refunded_at'
        ts = tx_data.get(key, '')
        if not ts:
            return
        dt = datetime.fromisoformat(ts)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        if (datetime.now(timezone.utc) - dt).total_seconds() > 300:
            db_delete(tx_hash)
            print(f"\U0001f5d1\ufe0f  AUTO-DELETED: {tx_hash[:10]}... ({tx_data.get('status')})")
    except Exception:
        pass


# =============================================================
# MONITOR LOOP
# =============================================================
def monitor_transactions():
    print("\n\U0001f916 Transaction Monitor Started")
    print(f"\u23f3 Polling every {POLL_INTERVAL}s | deadline={FORWARD_DEADLINE_SECONDS}s | max_gas_retries={MAX_GAS_WAIT_RETRIES}\n")

    while True:
        try:
            current_block = w3.eth.block_number
            active_txs = db_get_active()

            for tx_data in active_txs:
                tx_hash = tx_data['tx_hash']
                status = tx_data.get('status')
                try:
                    if status == 'pending':
                        step_pending(tx_hash, tx_data, current_block)

                    elif status in ('verified', 'forward_wait_gas'):
                        if not _check_deadline(tx_hash, tx_data):
                            # Re-fetch after deadline check (status may have changed)
                            tx_data = db_get(tx_hash) or tx_data
                            if tx_data.get('status') in ('verified', 'forward_wait_gas'):
                                step_verified(tx_hash, tx_data)

                    elif status == 'forwarding_pending':
                        step_forwarding(tx_hash, tx_data, current_block)

                    elif status == 'refund_pending':
                        step_refund(tx_hash, tx_data)

                    elif status == 'refunding':
                        step_refunding(tx_hash, tx_data, current_block)

                    elif status in ('complete', 'refunded'):
                        auto_cleanup(tx_hash, tx_data)

                except Exception as e:
                    print(f"\u274c Monitor [{status}] {tx_hash[:10]}...: {e}")

            time.sleep(POLL_INTERVAL)

        except Exception as e:
            print(f"\u274c Monitor outer error: {e}")
            time.sleep(POLL_INTERVAL)


# =============================================================
# API ROUTES
# =============================================================

@app.route('/api/health', methods=['GET'])
def health_check():
    return jsonify({
        'status': 'healthy',
        'timestamp': _now_iso(),
        'service': 'secure-payment-backend',
        'blockchain_connected': w3.is_connected(),
        'escrow_address': escrow_address,
        'fee_wallet': fee_wallet or escrow_address,
        'chain_id': chain_id,
        'current_block': w3.eth.block_number,
        'storage': 'postgresql' if (DATABASE_URL and HAS_PSYCOPG2) else 'json',
        'allowed_origins': _ALLOWED_ORIGINS,
    })


@app.route('/api/verify', methods=['POST', 'OPTIONS'])
def trigger_verify():
    if request.method == 'OPTIONS':
        return '', 204
    return jsonify({'ok': True})


@app.route('/api/transaction', methods=['POST', 'OPTIONS'])
def create_transaction():
    if request.method == 'OPTIONS':
        return '', 204
    try:
        data = request.get_json() or {}
        tx_hash             = data.get('tx_hash')
        sender              = data.get('sender')
        destination         = data.get('destination')
        amount_wei          = data.get('amount_wei')
        recipient_amount_wei = data.get('recipient_amount_wei')
        fwd_gas_buffer      = data.get('forward_gas_buffer_wei', '0')

        if not all([tx_hash, sender, destination, amount_wei, recipient_amount_wei]):
            return jsonify({'error': 'Missing required fields'}), 400
        if not Web3.is_address(sender):
            return jsonify({'error': 'Invalid sender address'}), 400
        if not Web3.is_address(destination):
            return jsonify({'error': 'Invalid destination address'}), 400
        try:
            int(amount_wei); int(recipient_amount_wei); int(fwd_gas_buffer)
        except Exception:
            return jsonify({'error': 'Wei values must be integers'}), 400

        client_token = secrets.token_urlsafe(24)
        record = {
            'tx_hash':               tx_hash,
            'sender':                Web3.to_checksum_address(sender),
            'destination':           Web3.to_checksum_address(destination),
            'total_paid_wei':        str(amount_wei),
            'recipient_amount_wei':  str(recipient_amount_wei),
            'forward_gas_buffer_wei': str(fwd_gas_buffer),
            'status':                'pending',
            'created_at':            _now_iso(),
            'client_token':          client_token,
            'chain_id':              chain_id,
            'gas_wait_retries':      0,
        }
        db_save(record)
        print(f"\u2705 TX saved: {tx_hash[:10]}... ({record['sender'][:10]}... \u2192 {record['destination'][:10]}...)")
        return jsonify({'success': True, 'tx_hash': tx_hash, 'client_token': client_token})

    except Exception as e:
        print(f"\u274c create_transaction: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/transaction/<tx_hash>', methods=['GET'])
def get_transaction(tx_hash):
    try:
        tx_data = db_get(tx_hash)
        if not tx_data:
            return jsonify({'error': 'Transaction not found'}), 404
        if is_admin():
            return jsonify(tx_data)
        tok = _client_token()
        if not tok or not secrets.compare_digest(str(tok), str(tx_data.get('client_token') or '')):
            return jsonify({'error': 'Forbidden'}), 403
        return jsonify(tx_data)
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/transactions', methods=['GET'])
def get_all_transactions():
    try:
        if not is_admin():
            return jsonify({'error': 'Forbidden'}), 403
        return jsonify(db_get_all())
    except Exception as e:
        return jsonify({'error': str(e)}), 500


# =============================================================
# STARTUP
# =============================================================
if __name__ == '__main__':
    port = int(os.getenv('PORT', 10000))
    if str(RUN_MONITOR).strip() == '1':
        t = threading.Thread(target=monitor_transactions, daemon=True)
        t.start()
        print("\u2705 RUN_MONITOR=1 \u2192 monitor thread started in web process")
    else:
        print("\u2139\ufe0f  RUN_MONITOR=0 \u2192 monitor runs in dedicated worker")
    print(f"\n\U0001f680 Backend on port {port}")
    print(f"\U0001f30d Allowed origins: {_ALLOWED_ORIGINS}\n")
    app.run(host='0.0.0.0', port=port, debug=False)
