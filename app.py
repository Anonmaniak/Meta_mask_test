from flask import Flask, request, jsonify
from flask_cors import CORS
from web3 import Web3
import os
import threading
import time
import secrets
from datetime import datetime, timezone

try:
    from pymongo import MongoClient, ASCENDING
    from pymongo.errors import DuplicateKeyError
    HAS_MONGO = True
except ImportError:
    HAS_MONGO = False

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
MONGO_URL          = os.getenv('MONGO_URL')

# ── Business logic — all tunable from Render env vars ─────────
FEE_PERCENTAGE             = float(os.getenv('FEE_PERCENTAGE', '1'))
MIN_TX_AMOUNT_ETH          = float(os.getenv('MIN_TX_AMOUNT_ETH', '0.001'))
MAX_TX_AMOUNT_ETH          = float(os.getenv('MAX_TX_AMOUNT_ETH', '2.0'))   # NEW: amount cap
GAS_PRICE_CAP_GWEI         = int(os.getenv('GAS_PRICE_CAP_GWEI', '30'))      # NEW: gas price cap
GAS_DEADLINE_SECONDS       = int(os.getenv('GAS_DEADLINE_SECONDS', '3600'))  # NEW: 1h queue timeout
KEEP_FEE_ON_REFUND         = os.getenv('KEEP_FEE_ON_REFUND', 'true').lower() == 'true'  # NEW
VERIFICATION_CONFIRMATIONS = int(os.getenv('VERIFICATION_CONFIRMATIONS', '3'))
POLL_INTERVAL              = int(os.getenv('POLL_INTERVAL', '15'))

# Derived constants
MIN_TX_AMOUNT_WEI = int(MIN_TX_AMOUNT_ETH * 1e18)
MAX_TX_AMOUNT_WEI = int(MAX_TX_AMOUNT_ETH * 1e18)
GAS_UNIT_LIMIT    = 21_000
GAS_BUFFER_WEI    = GAS_PRICE_CAP_GWEI * GAS_UNIT_LIMIT * 10**9  # flat buffer user pays

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
balance_eth    = w3.from_wei(w3.eth.get_balance(escrow_address), 'ether')
print(f"\u2705 Escrow wallet    : {escrow_address}")
print(f"   Balance          : {balance_eth} ETH")
print(f"   Min TX amount    : {MIN_TX_AMOUNT_ETH} ETH")
print(f"   Max TX amount    : {MAX_TX_AMOUNT_ETH} ETH  <-- NEW cap")
print(f"   Gas price cap    : {GAS_PRICE_CAP_GWEI} Gwei <-- NEW cap")
print(f"   Gas deadline     : {GAS_DEADLINE_SECONDS}s")
print(f"   Gas buffer       : {w3.from_wei(GAS_BUFFER_WEI,'ether')} ETH")
print(f"   Keep fee on refund: {KEEP_FEE_ON_REFUND}")
print(f"   Platform fee     : {FEE_PERCENTAGE}%")

# =============================================================
# MONGODB DATABASE LAYER
# =============================================================
_mongo_client = None
_mongo_db     = None

def _get_db():
    global _mongo_client, _mongo_db
    if _mongo_db is not None:
        return _mongo_db
    if not (MONGO_URL and HAS_MONGO):
        raise Exception("MONGO_URL not set or pymongo not installed")
    _mongo_client = MongoClient(MONGO_URL, serverSelectionTimeoutMS=5000)
    _mongo_db     = _mongo_client['payments']
    _mongo_db.transactions.create_index([('status', ASCENDING)])
    _mongo_db.transactions.create_index([('created_at', ASCENDING)])
    print("\u2705 MongoDB connected")
    return _mongo_db


def _now_iso():
    return datetime.now(timezone.utc).isoformat()


def db_save(tx_data: dict):
    db = _get_db()
    doc = dict(tx_data)
    doc['_id'] = doc['tx_hash']
    try:
        db.transactions.insert_one(doc)
    except DuplicateKeyError:
        db.transactions.replace_one({'_id': doc['_id']}, doc)


def db_get(tx_hash: str):
    db  = _get_db()
    doc = db.transactions.find_one({'_id': tx_hash})
    if not doc:
        return None
    doc.pop('_id', None)
    return doc


def db_get_active():
    db   = _get_db()
    docs = db.transactions.find(
        {'status': {'$nin': ['complete', 'refunded', 'failed']}},
        sort=[('created_at', ASCENDING)]
    )
    result = []
    for d in docs:
        d.pop('_id', None)
        result.append(d)
    return result


def db_get_all():
    db   = _get_db()
    docs = db.transactions.find({}, sort=[('created_at', ASCENDING)])
    result = []
    for d in docs:
        d.pop('_id', None)
        result.append(d)
    return result


def db_update(tx_hash: str, updates: dict):
    db = _get_db()
    db.transactions.update_one(
        {'_id': tx_hash},
        {'$set': updates}
    )


def db_delete(tx_hash: str):
    db = _get_db()
    db.transactions.delete_one({'_id': tx_hash})


try:
    _get_db()
except Exception as e:
    print(f"\u26a0\ufe0f  MongoDB init warning: {e}")

# =============================================================
# THREAD-SAFE NONCE MANAGER
# =============================================================
_nonce_lock  = threading.Lock()
_nonce_cache = None

def get_next_nonce():
    global _nonce_cache
    with _nonce_lock:
        on_chain = w3.eth.get_transaction_count(escrow_address, 'pending')
        if _nonce_cache is None or on_chain > _nonce_cache:
            _nonce_cache = on_chain
        nonce = _nonce_cache
        _nonce_cache += 1
        return nonce

def reset_nonce():
    global _nonce_cache
    with _nonce_lock:
        _nonce_cache = None

# =============================================================
# LIVE GAS PRICE HELPER
# =============================================================
def _get_current_gas_price_gwei() -> float:
    """Return current gas price in Gwei (EIP-1559 aware)."""
    try:
        block    = w3.eth.get_block('latest')
        base_fee = block.get('baseFeePerGas')
        if base_fee:
            try:
                priority = w3.eth.max_priority_fee
            except Exception:
                priority = w3.to_wei(2, 'gwei')
            total_wei = int(base_fee * 1.2) + priority
        else:
            total_wei = w3.eth.gas_price
        return w3.from_wei(total_wei, 'gwei')
    except Exception:
        return 9999  # safe fallback — forces queue to wait


def _build_tx_params(destination, value_wei, nonce):
    """Build EIP-1559 tx params using real-time gas."""
    try:
        block    = w3.eth.get_block('latest')
        base_fee = block.get('baseFeePerGas')
        if base_fee:
            try:
                priority = w3.eth.max_priority_fee
            except Exception:
                priority = w3.to_wei(2, 'gwei')
            max_fee = int(base_fee * 2) + priority
        else:
            max_fee  = w3.eth.gas_price
            priority = 0
    except Exception:
        max_fee  = w3.eth.gas_price
        priority = 0
    return {
        'to':                  destination,
        'value':               value_wei,
        'nonce':               nonce,
        'gas':                 GAS_UNIT_LIMIT,
        'maxFeePerGas':        max_fee,
        'maxPriorityFeePerGas': priority,
        'chainId':             chain_id,
    }, max_fee


# =============================================================
# FORWARD QUEUE
# Single sender thread — sequential nonces, no collisions
# =============================================================
_fwd_queue      = []
_fwd_queue_lock = threading.Lock()

def queue_push(job: dict):
    with _fwd_queue_lock:
        _fwd_queue.append(job)
    print(f"\U0001f4e5 QUEUED [{job['type']}]: {job['tx_hash'][:10]}...")

def _queue_sender_loop():
    print("\u2705 ForwardQueue sender thread started")
    while True:
        job = None
        with _fwd_queue_lock:
            if _fwd_queue:
                job = _fwd_queue.pop(0)
        if job:
            try:
                _process_queue_job(job)
            except Exception as e:
                print(f"\u274c Queue job error [{job.get('type')}] {job.get('tx_hash','')[:10]}: {e}")
                reset_nonce()
        else:
            time.sleep(1)

def _process_queue_job(job):
    tx_hash     = job['tx_hash']
    job_type    = job['type']   # 'forward' or 'refund'
    destination = Web3.to_checksum_address(job['destination'])
    send_wei    = int(job['send_wei'])

    tx_params, max_fee = _build_tx_params(destination, send_wei, 0)  # nonce placeholder
    actual_gas_cost_wei = GAS_UNIT_LIMIT * max_fee

    if job_type == 'forward':
        buffer_wei       = int(job['gas_buffer_wei'])
        platform_fee_wei = int(job['platform_fee_wei'])

        # Gas coverage priority: buffer → fee → recipient
        if actual_gas_cost_wei <= buffer_wei:
            gas_surplus_wei  = buffer_wei - actual_gas_cost_wei   # stays in escrow = your profit
            final_send_wei   = send_wei
        elif actual_gas_cost_wei <= buffer_wei + platform_fee_wei:
            deficit          = actual_gas_cost_wei - buffer_wei
            platform_fee_wei = platform_fee_wei - deficit
            gas_surplus_wei  = 0
            final_send_wei   = send_wei
        else:
            total_available  = buffer_wei + platform_fee_wei
            shortfall        = actual_gas_cost_wei - total_available
            gas_surplus_wei  = 0
            platform_fee_wei = 0
            final_send_wei   = max(0, send_wei - shortfall)
            print(f"\u26a0\ufe0f  Extreme gas: cutting {shortfall} wei from recipient on {tx_hash[:10]}...")

        nonce = get_next_nonce()
        tx_params['value'] = final_send_wei
        tx_params['nonce'] = nonce
        signed = w3.eth.account.sign_transaction(tx_params, ADMIN_PRIVATE_KEY)
        raw    = getattr(signed, 'rawTransaction', None) or getattr(signed, 'raw_transaction', None)
        forward_hash = w3.eth.send_raw_transaction(raw).hex()

        db_update(tx_hash, {
            'status':               'forwarding_pending',
            'forward_tx_hash':      forward_hash,
            'forwarded_at':         _now_iso(),
            'platform_fee_wei':     str(platform_fee_wei),
            'gas_surplus_wei':      str(gas_surplus_wei),
            'actual_gas_cost_wei':  str(actual_gas_cost_wei),
            'final_send_wei':       str(final_send_wei),
            'forward_nonce':        nonce,
        })
        print(f"\U0001f4e4 FORWARDED: {tx_hash[:10]}... \u2192 {forward_hash[:10]}... | gas={w3.from_wei(actual_gas_cost_wei,'ether'):.6f} | surplus={w3.from_wei(gas_surplus_wei,'ether'):.6f} ETH")

    elif job_type == 'refund':
        # On refund: deduct actual gas from the refund amount
        # If KEEP_FEE_ON_REFUND=true, also deduct platform fee before refunding
        refund_amount = max(0, send_wei - actual_gas_cost_wei)

        if refund_amount <= 0:
            db_update(tx_hash, {
                'status': 'failed',
                'error':  f'Refund impossible: gas_cost ({actual_gas_cost_wei}) >= total ({send_wei})'
            })
            print(f"\u274c {tx_hash[:10]}... refund impossible")
            return

        nonce = get_next_nonce()
        tx_params['to']    = destination
        tx_params['value'] = refund_amount
        tx_params['nonce'] = nonce
        signed     = w3.eth.account.sign_transaction(tx_params, ADMIN_PRIVATE_KEY)
        raw        = getattr(signed, 'rawTransaction', None) or getattr(signed, 'raw_transaction', None)
        refund_hash = w3.eth.send_raw_transaction(raw).hex()

        db_update(tx_hash, {
            'status':             'refunding',
            'refund_tx_hash':     refund_hash,
            'refund_amount_wei':  str(refund_amount),
            'refund_gas_cost_wei': str(actual_gas_cost_wei),
        })
        print(f"\u21a9\ufe0f  REFUNDING: {tx_hash[:10]}... \u2192 {refund_hash[:10]}...")

# Start queue sender thread
_queue_thread = threading.Thread(target=_queue_sender_loop, daemon=True)
_queue_thread.start()

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
# MONITOR STEPS
# =============================================================

def step_pending(tx_hash, tx_data, current_block):
    """PENDING -> VERIFIED: confirm escrow deposit on-chain."""
    try:
        receipt = w3.eth.get_transaction_receipt(tx_hash)
        if not receipt or receipt['status'] != 1:
            return
        confirmations = current_block - receipt['blockNumber']
        if confirmations < VERIFICATION_CONFIRMATIONS:
            return

        tx = w3.eth.get_transaction(tx_hash)
        if (tx.get('to') or '').lower() != escrow_address.lower():
            db_update(tx_hash, {'status': 'failed', 'error': 'Wrong destination'})
            return
        if (tx.get('from') or '').lower() != tx_data['sender'].lower():
            db_update(tx_hash, {'status': 'failed', 'error': 'Sender mismatch'})
            return
        if int(tx.get('value', 0)) != int(tx_data['total_paid_wei']):
            db_update(tx_hash, {'status': 'failed', 'error': 'Amount mismatch'})
            return

        db_update(tx_hash, {
            'status':       'verified',
            'escrow_block': receipt['blockNumber'],
            'verified_at':  _now_iso(),
        })
        print(f"\u2705 VERIFIED: {tx_hash[:10]}... ({confirmations} confs)")

    except Exception as e:
        print(f"\u26a0\ufe0f  step_pending {tx_hash[:10]}...: {e}")


def step_verified(tx_hash, tx_data):
    """
    VERIFIED -> check gas price cap before queuing.

    NEW LOGIC:
    - If live gas price <= GAS_PRICE_CAP_GWEI  → queue forward immediately
    - If live gas price >  GAS_PRICE_CAP_GWEI  → set status = forward_wait_gas (retry each poll)
    - If been waiting > GAS_DEADLINE_SECONDS   → refund user (keep fee if KEEP_FEE_ON_REFUND)
    """
    try:
        live_gwei = _get_current_gas_price_gwei()

        # Check deadline first — has this tx been waiting too long?
        verified_at_str = tx_data.get('verified_at', tx_data.get('created_at', ''))
        if verified_at_str:
            try:
                verified_at = datetime.fromisoformat(verified_at_str)
                if verified_at.tzinfo is None:
                    verified_at = verified_at.replace(tzinfo=timezone.utc)
                waiting_seconds = (datetime.now(timezone.utc) - verified_at).total_seconds()
            except Exception:
                waiting_seconds = 0
        else:
            waiting_seconds = 0

        if waiting_seconds > GAS_DEADLINE_SECONDS:
            # Deadline exceeded → refund
            print(f"\u23f0 GAS DEADLINE exceeded for {tx_hash[:10]}... (waited {int(waiting_seconds)}s) \u2192 refund")
            db_update(tx_hash, {
                'status':              'refund_pending',
                'error':               f'Gas price stayed above cap ({GAS_PRICE_CAP_GWEI} Gwei) for {int(waiting_seconds)}s',
                'refund_initiated_at': _now_iso(),
                'refund_reason':       'gas_deadline_exceeded',
            })
            return

        if live_gwei <= GAS_PRICE_CAP_GWEI:
            # Gas is acceptable — forward now
            recipient_wei    = int(tx_data['recipient_amount_wei'])
            buffer_wei       = int(tx_data.get('gas_buffer_wei', str(GAS_BUFFER_WEI)))
            platform_fee_wei = int(recipient_wei * FEE_PERCENTAGE / 100)

            queue_push({
                'type':             'forward',
                'tx_hash':          tx_hash,
                'destination':      tx_data['destination'],
                'send_wei':         recipient_wei,
                'gas_buffer_wei':   buffer_wei,
                'platform_fee_wei': platform_fee_wei,
            })
            db_update(tx_hash, {
                'status':            'queued',
                'queued_at':         _now_iso(),
                'gas_at_queue_gwei': float(live_gwei),
                'platform_fee_wei':  str(platform_fee_wei),
            })
            print(f"\u26fd Gas OK ({live_gwei:.1f} Gwei <= cap {GAS_PRICE_CAP_GWEI}) \u2192 QUEUED {tx_hash[:10]}...")
        else:
            # Gas too high — wait, update status to show we're watching
            db_update(tx_hash, {
                'status':                'forward_wait_gas',
                'live_gas_gwei':         float(live_gwei),
                'gas_cap_gwei':          GAS_PRICE_CAP_GWEI,
                'gas_wait_updated_at':   _now_iso(),
            })
            print(f"\u26fd Gas HIGH ({live_gwei:.1f} Gwei > cap {GAS_PRICE_CAP_GWEI}) \u2014 {tx_hash[:10]}... waiting...")

    except Exception as e:
        print(f"\u274c step_verified {tx_hash[:10]}...: {e}")


def step_forwarding(tx_hash, tx_data, current_block):
    """FORWARDING_PENDING -> COMPLETE: 3 confs on forward tx."""
    try:
        forward_hash = tx_data.get('forward_tx_hash')
        if not forward_hash:
            return
        receipt = w3.eth.get_transaction_receipt(forward_hash)
        if not receipt:
            return
        if receipt['status'] != 1:
            db_update(tx_hash, {
                'status':              'refund_pending',
                'error':              'Forward tx reverted on-chain',
                'refund_initiated_at': _now_iso(),
            })
            print(f"\u26a0\ufe0f  {tx_hash[:10]}... forward reverted \u2192 refund_pending")
            return
        confirmations = current_block - receipt['blockNumber']
        if confirmations < VERIFICATION_CONFIRMATIONS:
            return
        db_update(tx_hash, {
            'status':        'complete',
            'forward_block': receipt['blockNumber'],
            'completed_at':  _now_iso(),
        })
        print(f"\U0001f389 COMPLETE: {tx_hash[:10]}...")
    except Exception as e:
        print(f"\u26a0\ufe0f  step_forwarding {tx_hash[:10]}...: {e}")


def step_refund(tx_hash, tx_data):
    """REFUND_PENDING -> push refund to queue.

    If KEEP_FEE_ON_REFUND=true and the refund reason is gas deadline,
    deduct platform fee from the refund (it stays in escrow as profit).
    Otherwise refund the full total minus gas cost.
    """
    try:
        sender         = Web3.to_checksum_address(tx_data['sender'])
        total_paid_wei = int(tx_data['total_paid_wei'])

        refund_reason  = tx_data.get('refund_reason', '')

        if KEEP_FEE_ON_REFUND and refund_reason == 'gas_deadline_exceeded':
            # Keep the 1% fee — user paid for the service attempt
            recipient_wei    = int(tx_data.get('recipient_amount_wei', 0))
            platform_fee_wei = int(recipient_wei * FEE_PERCENTAGE / 100)
            refund_base_wei  = total_paid_wei - platform_fee_wei
            print(f"\U0001f4b0 Keeping {w3.from_wei(platform_fee_wei,'ether'):.6f} ETH fee on gas-timeout refund")
        else:
            refund_base_wei = total_paid_wei

        queue_push({
            'type':        'refund',
            'tx_hash':     tx_hash,
            'destination': sender,
            'send_wei':    refund_base_wei,
        })
        db_update(tx_hash, {
            'status':           'refunding_queued',
            'refund_queued_at': _now_iso(),
            'refund_base_wei':  str(refund_base_wei),
        })
    except Exception as e:
        print(f"\u274c step_refund {tx_hash[:10]}...: {e}")


def step_refunding(tx_hash, tx_data, current_block):
    """REFUNDING -> REFUNDED: confirm refund on-chain."""
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
            'status':       'refunded',
            'refunded_at':  _now_iso(),
            'refund_block': receipt['blockNumber'],
        })
        print(f"\u2705 REFUNDED: {tx_hash[:10]}...")
    except Exception as e:
        print(f"\u26a0\ufe0f  step_refunding {tx_hash[:10]}...: {e}")


def auto_cleanup(tx_hash, tx_data):
    """Delete terminal txs 24h after completion."""
    try:
        key = 'completed_at' if tx_data.get('status') == 'complete' else 'refunded_at'
        ts  = tx_data.get(key, '')
        if not ts:
            return
        dt = datetime.fromisoformat(ts)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        if (datetime.now(timezone.utc) - dt).total_seconds() > 86400:
            db_delete(tx_hash)
            print(f"\U0001f5d1\ufe0f  AUTO-DELETED: {tx_hash[:10]}...")
    except Exception:
        pass


# =============================================================
# MONITOR LOOP
# =============================================================
_monitor_running = False
_monitor_lock    = threading.Lock()

def monitor_transactions():
    global _monitor_running
    with _monitor_lock:
        if _monitor_running:
            print("\u26a0\ufe0f  Monitor already running — skipping")
            return
        _monitor_running = True

    print(f"\n\U0001f916 Monitor started | poll={POLL_INTERVAL}s | gas_cap={GAS_PRICE_CAP_GWEI} Gwei | deadline={GAS_DEADLINE_SECONDS}s")

    while True:
        try:
            current_block = w3.eth.block_number
            active_txs    = db_get_active()
            for tx_data in active_txs:
                tx_hash = tx_data['tx_hash']
                status  = tx_data.get('status')
                try:
                    if status == 'pending':
                        step_pending(tx_hash, tx_data, current_block)
                    elif status in ('verified', 'forward_wait_gas'):
                        # Both 'verified' AND 'forward_wait_gas' retry the gas check
                        step_verified(tx_hash, tx_data)
                    elif status in ('queued', 'refunding_queued'):
                        pass  # queue thread handles these
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
            print(f"\u274c Monitor outer: {e}")
            time.sleep(POLL_INTERVAL)


# =============================================================
# API ROUTES
# =============================================================

@app.route('/api/health', methods=['GET'])
def health_check():
    return jsonify({
        'status':               'healthy',
        'timestamp':            _now_iso(),
        'service':              'secure-payment-backend',
        'blockchain_connected': w3.is_connected(),
        'escrow_address':       escrow_address,
        'chain_id':             chain_id,
        'current_block':        w3.eth.block_number,
        'storage':              'mongodb',
        'allowed_origins':      _ALLOWED_ORIGINS,
    })


@app.route('/api/config', methods=['GET'])
def get_config():
    """Public endpoint — frontend fetches this on load for live config."""
    return jsonify({
        'fee_percentage':      FEE_PERCENTAGE,
        'gas_price_cap_gwei':  GAS_PRICE_CAP_GWEI,
        'gas_deadline_seconds': GAS_DEADLINE_SECONDS,
        'min_tx_amount_eth':   MIN_TX_AMOUNT_ETH,
        'max_tx_amount_eth':   MAX_TX_AMOUNT_ETH,
        'gas_buffer_eth':      GAS_BUFFER_WEI / 1e18,
        'gas_buffer_wei':      str(GAS_BUFFER_WEI),
        'keep_fee_on_refund':  KEEP_FEE_ON_REFUND,
    })


@app.route('/api/transaction', methods=['POST', 'OPTIONS'])
def create_transaction():
    if request.method == 'OPTIONS':
        return '', 204
    try:
        data = request.get_json() or {}
        tx_hash              = data.get('tx_hash')
        sender               = data.get('sender')
        destination          = data.get('destination')
        amount_wei           = data.get('amount_wei')
        recipient_amount_wei = data.get('recipient_amount_wei')

        if not all([tx_hash, sender, destination, amount_wei, recipient_amount_wei]):
            return jsonify({'error': 'Missing required fields'}), 400
        if not Web3.is_address(sender):
            return jsonify({'error': 'Invalid sender address'}), 400
        if not Web3.is_address(destination):
            return jsonify({'error': 'Invalid destination address'}), 400
        try:
            int(amount_wei)
            int(recipient_amount_wei)
        except Exception:
            return jsonify({'error': 'Wei values must be integers'}), 400

        r_wei = int(recipient_amount_wei)

        # Server-side amount cap validation (both min AND max)
        if r_wei < MIN_TX_AMOUNT_WEI:
            return jsonify({'error': f'Amount below minimum. Min: {MIN_TX_AMOUNT_ETH} ETH'}), 400
        if r_wei > MAX_TX_AMOUNT_WEI:
            return jsonify({'error': f'Amount above maximum. Max: {MAX_TX_AMOUNT_ETH} ETH'}), 400

        client_token = secrets.token_urlsafe(24)
        record = {
            'tx_hash':              tx_hash,
            'sender':               Web3.to_checksum_address(sender),
            'destination':          Web3.to_checksum_address(destination),
            'total_paid_wei':       str(amount_wei),
            'recipient_amount_wei': str(r_wei),
            'gas_buffer_wei':       str(GAS_BUFFER_WEI),
            'status':               'pending',
            'created_at':           _now_iso(),
            'client_token':         client_token,
            'chain_id':             chain_id,
        }
        db_save(record)
        print(f"\u2705 TX saved: {tx_hash[:10]}... ({sender[:10]}... \u2192 {destination[:10]}...)")
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
        return jsonify({
            'tx_hash':        tx_data['tx_hash'],
            'status':         tx_data['status'],
            'created_at':     tx_data.get('created_at'),
            'completed_at':   tx_data.get('completed_at'),
            'forward_tx_hash': tx_data.get('forward_tx_hash'),
        })
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


@app.route('/api/verify', methods=['POST', 'OPTIONS'])
def trigger_verify():
    if request.method == 'OPTIONS':
        return '', 204
    return jsonify({'ok': True})


# =============================================================
# STARTUP
# =============================================================
if __name__ == '__main__':
    port = int(os.getenv('PORT', 10000))
    if str(RUN_MONITOR).strip() == '1':
        t = threading.Thread(target=monitor_transactions, daemon=True)
        t.start()
        print("\u2705 RUN_MONITOR=1 \u2192 monitor thread started")
    else:
        print("\u2139\ufe0f  RUN_MONITOR=0 \u2192 monitor runs in dedicated worker")
    print(f"\n\U0001f680 Backend on port {port}")
    print(f"\U0001f30d Allowed origins: {_ALLOWED_ORIGINS}\n")
    app.run(host='0.0.0.0', port=port, debug=False)
