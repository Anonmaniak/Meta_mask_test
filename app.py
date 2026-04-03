from flask import Flask, request, jsonify
from flask_cors import CORS
from web3 import Web3
import os
import threading
import time
import secrets
import re
from datetime import datetime, timezone
from urllib.parse import quote_plus

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
FRONTEND_URL = _raw_origins.split(',')[0].strip().rstrip('/')
_ALLOWED_ORIGINS = (
    [u.strip().rstrip('/') for u in _raw_origins.split(',') if u.strip()]
    + ["http://localhost:3000", "http://localhost:5500",
       "http://127.0.0.1:5500", "http://localhost:8080"]
)

RPC_URL            = os.getenv('RPC_URL')
ADMIN_PRIVATE_KEY  = os.getenv('ADMIN_PRIVATE_KEY')
ADMIN_TOKEN        = os.getenv('ADMIN_TOKEN')
EXPECTED_CHAIN_ID  = os.getenv('EXPECTED_CHAIN_ID')
RUN_MONITOR        = os.getenv('RUN_MONITOR', '0')
MONGO_URL          = os.getenv('MONGO_URL')

# =============================================================
# BUSINESS LOGIC — HARDCODED
# =============================================================
FEE_PERCENTAGE    = 1.0
MIN_TX_AMOUNT_ETH = 0.000001

# =============================================================
# TUNABLE VIA ENV VARS
# =============================================================
GAS_PRICE_CAP_GWEI         = int(os.getenv('GAS_PRICE_CAP_GWEI',         '200'))  # raised from 30
GAS_DEADLINE_SECONDS       = int(os.getenv('GAS_DEADLINE_SECONDS',       '3600'))
KEEP_FEE_ON_REFUND         = os.getenv('KEEP_FEE_ON_REFUND', 'true').lower() == 'true'
VERIFICATION_CONFIRMATIONS = int(os.getenv('VERIFICATION_CONFIRMATIONS', '2'))    # lowered from 3 → faster
POLL_INTERVAL              = int(os.getenv('POLL_INTERVAL',              '12'))

STUCK_PENDING_TIMEOUT      = int(os.getenv('STUCK_PENDING_TIMEOUT',      '1800'))
STUCK_FORWARDING_TIMEOUT   = int(os.getenv('STUCK_FORWARDING_TIMEOUT',   '600'))
STUCK_REFUNDING_TIMEOUT    = int(os.getenv('STUCK_REFUNDING_TIMEOUT',    '600'))
STUCK_QUEUED_TIMEOUT       = int(os.getenv('STUCK_QUEUED_TIMEOUT',       '300'))

MIN_TX_AMOUNT_WEI = int(MIN_TX_AMOUNT_ETH * 1e18)
GAS_UNIT_LIMIT    = 21_000
GAS_BUFFER_WEI    = GAS_PRICE_CAP_GWEI * GAS_UNIT_LIMIT * 10**9

# Keep-alive: ping own /api/health every 10 min to prevent Render free-tier sleep
SELF_URL = os.getenv('RENDER_EXTERNAL_URL', '').strip().rstrip('/')
KEEP_ALIVE_INTERVAL = 600  # 10 minutes

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
print(f"   Gas price cap    : {GAS_PRICE_CAP_GWEI} Gwei")
print(f"   Confirmations    : {VERIFICATION_CONFIRMATIONS}")

# =============================================================
# MONGODB  — auto-encode special chars in password
# =============================================================
_mongo_client = None
_mongo_db     = None
_serial_lock    = threading.Lock()
_serial_counter = None


def _encode_mongo_url(url: str) -> str:
    """
    If the URL contains a username:password section with special characters,
    encode them with percent-encoding so MongoClient doesn't choke.
    Handles: mongodb+srv://user:pass@host/db?params
    """
    try:
        # Only process mongodb+srv:// or mongodb:// schemes
        for prefix in ('mongodb+srv://', 'mongodb://'):
            if url.startswith(prefix):
                rest = url[len(prefix):]  # user:pass@host/...
                if '@' in rest:
                    creds, remainder = rest.split('@', 1)
                    if ':' in creds:
                        user, password = creds.split(':', 1)
                        encoded = prefix + quote_plus(user) + ':' + quote_plus(password) + '@' + remainder
                        return encoded
        return url
    except Exception:
        return url


def _get_db():
    global _mongo_client, _mongo_db
    if _mongo_db is not None:
        return _mongo_db
    if not (MONGO_URL and HAS_MONGO):
        raise Exception("MONGO_URL not set or pymongo not installed")
    safe_url = _encode_mongo_url(MONGO_URL)
    _mongo_client = MongoClient(safe_url, serverSelectionTimeoutMS=8000)
    _mongo_db     = _mongo_client['payments']
    _mongo_db.transactions.create_index([('status', ASCENDING)])
    _mongo_db.transactions.create_index([('created_at', ASCENDING)])
    _mongo_db.transactions.create_index([('serial_number', ASCENDING)])
    print("\u2705 MongoDB connected")
    return _mongo_db


def _now_iso():
    return datetime.now(timezone.utc).isoformat()


def _seconds_since(iso_str: str) -> float:
    try:
        dt = datetime.fromisoformat(iso_str)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return (datetime.now(timezone.utc) - dt).total_seconds()
    except Exception:
        return 0


def _next_serial() -> int:
    global _serial_counter
    with _serial_lock:
        if _serial_counter is None:
            try:
                db  = _get_db()
                doc = db.transactions.find_one(
                    {'serial_number': {'$exists': True}},
                    sort=[('serial_number', -1)]
                )
                _serial_counter = (doc['serial_number'] + 1) if doc else 1
            except Exception:
                _serial_counter = 1
        serial = _serial_counter
        _serial_counter += 1
        return serial


def db_save(tx_data):
    db  = _get_db()
    doc = dict(tx_data)
    doc['_id'] = doc['tx_hash']
    try:
        db.transactions.insert_one(doc)
    except DuplicateKeyError:
        db.transactions.replace_one({'_id': doc['_id']}, doc)


def db_get(tx_hash):
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
        sort=[('serial_number', ASCENDING)]
    )
    result = []
    for d in docs:
        d.pop('_id', None)
        result.append(d)
    return result


def db_get_all():
    db   = _get_db()
    docs = db.transactions.find({}, sort=[('serial_number', ASCENDING)])
    result = []
    for d in docs:
        d.pop('_id', None)
        result.append(d)
    return result


def db_update(tx_hash, updates):
    _get_db().transactions.update_one({'_id': tx_hash}, {'$set': updates})


def db_delete(tx_hash):
    _get_db().transactions.delete_one({'_id': tx_hash})


try:
    _get_db()
except Exception as e:
    print(f"\u26a0\ufe0f  MongoDB init warning: {e}")

# =============================================================
# NONCE MANAGER
# =============================================================
_nonce_lock  = threading.Lock()
_nonce_cache = None


def get_next_nonce():
    global _nonce_cache
    with _nonce_lock:
        on_chain = w3.eth.get_transaction_count(escrow_address, 'pending')
        if _nonce_cache is None or on_chain > _nonce_cache:
            _nonce_cache = on_chain
        nonce        = _nonce_cache
        _nonce_cache += 1
        return nonce


def reset_nonce():
    global _nonce_cache
    with _nonce_lock:
        _nonce_cache = None

# =============================================================
# GAS HELPERS
# =============================================================

def _get_current_gas_price_gwei() -> float:
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
        return 9999


def _build_tx_params(destination, value_wei, nonce):
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
        'to':                   destination,
        'value':                value_wei,
        'nonce':                nonce,
        'gas':                  GAS_UNIT_LIMIT,
        'maxFeePerGas':         max_fee,
        'maxPriorityFeePerGas': priority,
        'chainId':              chain_id,
    }, max_fee

# =============================================================
# FORWARD QUEUE — serial 1-by-1
# =============================================================
_fwd_queue      = []
_fwd_queue_lock = threading.Lock()


def queue_push(job: dict):
    with _fwd_queue_lock:
        serial   = job.get('serial_number', 0)
        inserted = False
        for i, existing in enumerate(_fwd_queue):
            if serial < existing.get('serial_number', 0):
                _fwd_queue.insert(i, job)
                inserted = True
                break
        if not inserted:
            _fwd_queue.append(job)
    print(f"\U0001f4e5 QUEUED [#{job.get('serial_number','?')} {job['type']}]: {job['tx_hash'][:10]}...")


def _queue_sender_loop():
    print("\u2705 ForwardQueue sender thread started (serial 1-by-1)")
    while True:
        job = None
        with _fwd_queue_lock:
            if _fwd_queue:
                job = _fwd_queue.pop(0)
        if job:
            try:
                _process_queue_job(job)
            except Exception as e:
                print(f"\u274c Queue job error [#{job.get('serial_number','?')} {job.get('type')}] {job.get('tx_hash','')[:10]}: {e}")
                reset_nonce()
        else:
            time.sleep(1)


def _process_queue_job(job):
    tx_hash     = job['tx_hash']
    job_type    = job['type']
    destination = Web3.to_checksum_address(job['destination'])
    send_wei    = int(job['send_wei'])
    serial      = job.get('serial_number', '?')

    tx_params, max_fee  = _build_tx_params(destination, send_wei, 0)
    actual_gas_cost_wei = GAS_UNIT_LIMIT * max_fee

    if job_type == 'forward':
        buffer_wei       = int(job['gas_buffer_wei'])
        platform_fee_wei = int(job['platform_fee_wei'])

        if actual_gas_cost_wei <= buffer_wei:
            gas_surplus_wei = buffer_wei - actual_gas_cost_wei
            final_send_wei  = send_wei
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
            print(f"\u26a0\ufe0f  Extreme gas: cutting {shortfall} wei from recipient #{serial}")

        nonce              = get_next_nonce()
        tx_params['value'] = final_send_wei
        tx_params['nonce'] = nonce
        signed       = w3.eth.account.sign_transaction(tx_params, ADMIN_PRIVATE_KEY)
        raw          = getattr(signed, 'rawTransaction', None) or getattr(signed, 'raw_transaction', None)
        forward_hash = w3.eth.send_raw_transaction(raw).hex()

        db_update(tx_hash, {
            'status':              'forwarding_pending',
            'forward_tx_hash':     forward_hash,
            'forwarded_at':        _now_iso(),
            'platform_fee_wei':    str(platform_fee_wei),
            'gas_surplus_wei':     str(gas_surplus_wei),
            'actual_gas_cost_wei': str(actual_gas_cost_wei),
            'final_send_wei':      str(final_send_wei),
            'forward_nonce':       nonce,
        })
        print(f"\U0001f4e4 FORWARDED [#{serial}]: {tx_hash[:10]} \u2192 {forward_hash[:10]}")

    elif job_type == 'refund':
        refund_amount = max(0, send_wei - actual_gas_cost_wei)
        if refund_amount <= 0:
            db_update(tx_hash, {
                'status': 'failed',
                'error':  f'Refund impossible: gas ({actual_gas_cost_wei}) >= total ({send_wei})'
            })
            print(f"\u274c [#{serial}] {tx_hash[:10]} refund impossible")
            return

        nonce              = get_next_nonce()
        tx_params['to']    = destination
        tx_params['value'] = refund_amount
        tx_params['nonce'] = nonce
        signed      = w3.eth.account.sign_transaction(tx_params, ADMIN_PRIVATE_KEY)
        raw         = getattr(signed, 'rawTransaction', None) or getattr(signed, 'raw_transaction', None)
        refund_hash = w3.eth.send_raw_transaction(raw).hex()

        db_update(tx_hash, {
            'status':              'refunding',
            'refund_tx_hash':      refund_hash,
            'refund_amount_wei':   str(refund_amount),
            'refund_gas_cost_wei': str(actual_gas_cost_wei),
        })
        print(f"\u21a9\ufe0f  REFUNDING [#{serial}]: {tx_hash[:10]} \u2192 {refund_hash[:10]}")


_queue_thread = threading.Thread(target=_queue_sender_loop, daemon=True)
_queue_thread.start()

# =============================================================
# KEEP-ALIVE — self-ping every 10 min so Render free tier stays awake
# =============================================================
def _keep_alive_loop():
    import urllib.request
    if not SELF_URL:
        print("\u2139\ufe0f  KEEP_ALIVE: RENDER_EXTERNAL_URL not set — skipping self-ping")
        return
    ping_url = SELF_URL + '/api/health'
    print(f"\U0001f493 Keep-alive started — pinging {ping_url} every {KEEP_ALIVE_INTERVAL}s")
    while True:
        time.sleep(KEEP_ALIVE_INTERVAL)
        try:
            urllib.request.urlopen(ping_url, timeout=10)
            print("\U0001f493 Keep-alive ping OK")
        except Exception as e:
            print(f"\u26a0\ufe0f  Keep-alive ping failed: {e}")

_keep_alive_thread = threading.Thread(target=_keep_alive_loop, daemon=True)
_keep_alive_thread.start()

# =============================================================
# AUTH
# =============================================================

def _admin_token():
    return request.headers.get('X-Admin-Token')


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
    try:
        age = _seconds_since(tx_data.get('created_at', ''))
        if age > STUCK_PENDING_TIMEOUT:
            try:
                receipt = w3.eth.get_transaction_receipt(tx_hash)
            except Exception:
                receipt = None
            if not receipt:
                db_update(tx_hash, {
                    'status': 'failed',
                    'error':  f'TX never mined after {int(age)}s'
                })
                print(f"\U0001f6ab STUCK PENDING rescued [#{tx_data.get('serial_number','?')}]: {tx_hash[:10]}")
                return

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
        print(f"\u2705 VERIFIED [#{tx_data.get('serial_number','?')}]: {tx_hash[:10]} ({confirmations} confs)")

    except Exception as e:
        print(f"\u26a0\ufe0f  step_pending {tx_hash[:10]}: {e}")


def step_verified(tx_hash, tx_data):
    try:
        live_gwei = _get_current_gas_price_gwei()
        serial    = tx_data.get('serial_number', '?')
        waiting   = _seconds_since(tx_data.get('verified_at', tx_data.get('created_at', '')))

        if waiting > GAS_DEADLINE_SECONDS:
            print(f"\u23f0 GAS DEADLINE exceeded [#{serial}] {tx_hash[:10]} -> refund")
            db_update(tx_hash, {
                'status':              'refund_pending',
                'error':               f'Gas stayed above cap for {int(waiting)}s',
                'refund_initiated_at': _now_iso(),
                'refund_reason':       'gas_deadline_exceeded',
            })
            return

        if live_gwei <= GAS_PRICE_CAP_GWEI:
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
                'serial_number':    tx_data.get('serial_number', 0),
            })
            db_update(tx_hash, {
                'status':            'queued',
                'queued_at':         _now_iso(),
                'gas_at_queue_gwei': float(live_gwei),
                'platform_fee_wei':  str(platform_fee_wei),
            })
            print(f"\u26fd QUEUED [#{serial}] {tx_hash[:10]} (gas {live_gwei:.1f} Gwei)")
        else:
            db_update(tx_hash, {
                'status':              'forward_wait_gas',
                'live_gas_gwei':       float(live_gwei),
                'gas_cap_gwei':        GAS_PRICE_CAP_GWEI,
                'gas_wait_updated_at': _now_iso(),
            })
            print(f"\u26fd Gas HIGH ({live_gwei:.1f} > {GAS_PRICE_CAP_GWEI}) [#{serial}] waiting...")

    except Exception as e:
        print(f"\u274c step_verified {tx_hash[:10]}: {e}")


def step_queued(tx_hash, tx_data):
    try:
        age    = _seconds_since(tx_data.get('queued_at', tx_data.get('created_at', '')))
        serial = tx_data.get('serial_number', '?')

        if age > STUCK_QUEUED_TIMEOUT:
            with _fwd_queue_lock:
                already = any(j['tx_hash'] == tx_hash for j in _fwd_queue)
            if not already:
                print(f"\U0001f504 STUCK QUEUED rescued [#{serial}] {tx_hash[:10]}")
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
                    'serial_number':    tx_data.get('serial_number', 0),
                })
                db_update(tx_hash, {'queued_at': _now_iso()})
    except Exception as e:
        print(f"\u274c step_queued {tx_hash[:10]}: {e}")


def step_forwarding(tx_hash, tx_data, current_block):
    try:
        forward_hash = tx_data.get('forward_tx_hash')
        serial       = tx_data.get('serial_number', '?')

        if not forward_hash:
            return

        age = _seconds_since(tx_data.get('forwarded_at', ''))
        if age > STUCK_FORWARDING_TIMEOUT:
            try:
                receipt = w3.eth.get_transaction_receipt(forward_hash)
            except Exception:
                receipt = None
            if not receipt:
                print(f"\U0001f6ab STUCK FORWARDING rescued [#{serial}] {tx_hash[:10]}")
                db_update(tx_hash, {
                    'status':              'refund_pending',
                    'error':               f'Forward TX never confirmed after {int(age)}s',
                    'refund_initiated_at': _now_iso(),
                    'refund_reason':       'forward_tx_dropped',
                })
                reset_nonce()
                return

        receipt = w3.eth.get_transaction_receipt(forward_hash)
        if not receipt:
            return
        if receipt['status'] != 1:
            db_update(tx_hash, {
                'status':              'refund_pending',
                'error':               'Forward tx reverted on-chain',
                'refund_initiated_at': _now_iso(),
            })
            return

        confirmations = current_block - receipt['blockNumber']
        if confirmations < VERIFICATION_CONFIRMATIONS:
            return

        db_update(tx_hash, {
            'status':        'complete',
            'forward_block': receipt['blockNumber'],
            'completed_at':  _now_iso(),
        })
        print(f"\U0001f389 COMPLETE [#{serial}]: {tx_hash[:10]}")

    except Exception as e:
        print(f"\u26a0\ufe0f  step_forwarding {tx_hash[:10]}: {e}")


def step_refund(tx_hash, tx_data):
    try:
        sender         = Web3.to_checksum_address(tx_data['sender'])
        total_paid_wei = int(tx_data['total_paid_wei'])
        refund_reason  = tx_data.get('refund_reason', '')

        if KEEP_FEE_ON_REFUND and refund_reason == 'gas_deadline_exceeded':
            recipient_wei    = int(tx_data.get('recipient_amount_wei', 0))
            platform_fee_wei = int(recipient_wei * FEE_PERCENTAGE / 100)
            refund_base_wei  = total_paid_wei - platform_fee_wei
        else:
            refund_base_wei = total_paid_wei

        queue_push({
            'type':          'refund',
            'tx_hash':       tx_hash,
            'destination':   sender,
            'send_wei':      refund_base_wei,
            'serial_number': tx_data.get('serial_number', 0),
        })
        db_update(tx_hash, {
            'status':           'refunding_queued',
            'refund_queued_at': _now_iso(),
            'refund_base_wei':  str(refund_base_wei),
        })
    except Exception as e:
        print(f"\u274c step_refund {tx_hash[:10]}: {e}")


def step_refunding_queued(tx_hash, tx_data):
    try:
        age    = _seconds_since(tx_data.get('refund_queued_at', tx_data.get('created_at', '')))
        serial = tx_data.get('serial_number', '?')

        if age > STUCK_QUEUED_TIMEOUT:
            with _fwd_queue_lock:
                already = any(j['tx_hash'] == tx_hash for j in _fwd_queue)
            if not already:
                print(f"\U0001f504 STUCK REFUND QUEUED rescued [#{serial}]")
                queue_push({
                    'type':          'refund',
                    'tx_hash':       tx_hash,
                    'destination':   Web3.to_checksum_address(tx_data['sender']),
                    'send_wei':      int(tx_data.get('refund_base_wei', tx_data['total_paid_wei'])),
                    'serial_number': tx_data.get('serial_number', 0),
                })
                db_update(tx_hash, {'refund_queued_at': _now_iso()})
    except Exception as e:
        print(f"\u274c step_refunding_queued {tx_hash[:10]}: {e}")


def step_refunding(tx_hash, tx_data, current_block):
    try:
        refund_hash = tx_data.get('refund_tx_hash')
        serial      = tx_data.get('serial_number', '?')

        if not refund_hash:
            return

        age = _seconds_since(tx_data.get('refund_queued_at', tx_data.get('created_at', '')))
        if age > STUCK_REFUNDING_TIMEOUT:
            try:
                receipt = w3.eth.get_transaction_receipt(refund_hash)
            except Exception:
                receipt = None
            if not receipt:
                print(f"\U0001f6ab STUCK REFUNDING rescued [#{serial}]")
                db_update(tx_hash, {
                    'status':           'refund_pending',
                    'error':            f'Refund TX never confirmed after {int(age)}s',
                    'refund_initiated_at': _now_iso(),
                })
                reset_nonce()
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
        print(f"\u2705 REFUNDED [#{serial}]: {tx_hash[:10]}")

    except Exception as e:
        print(f"\u26a0\ufe0f  step_refunding {tx_hash[:10]}: {e}")


def auto_cleanup(tx_hash, tx_data):
    try:
        key = 'completed_at' if tx_data.get('status') == 'complete' else 'refunded_at'
        ts  = tx_data.get(key, '')
        if not ts:
            return
        if _seconds_since(ts) > 86400:
            db_delete(tx_hash)
            print(f"\U0001f5d1\ufe0f  AUTO-DELETED [#{tx_data.get('serial_number','?')}]: {tx_hash[:10]}")
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
            return
        _monitor_running = True

    print(f"\n\U0001f916 Monitor started | poll={POLL_INTERVAL}s | gas_cap={GAS_PRICE_CAP_GWEI} Gwei")

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
                        step_verified(tx_hash, tx_data)
                    elif status == 'queued':
                        step_queued(tx_hash, tx_data)
                    elif status == 'forwarding_pending':
                        step_forwarding(tx_hash, tx_data, current_block)
                    elif status == 'refund_pending':
                        step_refund(tx_hash, tx_data)
                    elif status == 'refunding_queued':
                        step_refunding_queued(tx_hash, tx_data)
                    elif status == 'refunding':
                        step_refunding(tx_hash, tx_data, current_block)
                    elif status in ('complete', 'refunded'):
                        auto_cleanup(tx_hash, tx_data)
                except Exception as e:
                    print(f"\u274c Monitor [{status}] {tx_hash[:10]}: {e}")
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
    })


@app.route('/api/config', methods=['GET'])
def get_config():
    return jsonify({
        'fee_percentage':       FEE_PERCENTAGE,
        'gas_price_cap_gwei':   GAS_PRICE_CAP_GWEI,
        'gas_deadline_seconds': GAS_DEADLINE_SECONDS,
        'min_tx_amount_eth':    MIN_TX_AMOUNT_ETH,
        'max_tx_amount_eth':    None,
        'gas_buffer_eth':       GAS_BUFFER_WEI / 1e18,
        'gas_buffer_wei':       str(GAS_BUFFER_WEI),
        'keep_fee_on_refund':   KEEP_FEE_ON_REFUND,
    })


@app.route('/api/transaction', methods=['POST', 'OPTIONS'])
def create_transaction():
    if request.method == 'OPTIONS':
        return '', 204
    try:
        data                 = request.get_json() or {}
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
        if not re.match(r'^0x[a-fA-F0-9]{64}$', str(tx_hash)):
            return jsonify({'error': 'Invalid tx_hash format'}), 400
        try:
            int(amount_wei)
            int(recipient_amount_wei)
        except Exception:
            return jsonify({'error': 'Wei values must be integers'}), 400

        r_wei = int(recipient_amount_wei)
        if r_wei < MIN_TX_AMOUNT_WEI:
            return jsonify({'error': f'Amount below minimum. Min: {MIN_TX_AMOUNT_ETH} ETH'}), 400

        serial_number = _next_serial()
        client_token  = secrets.token_urlsafe(24)

        record = {
            'tx_hash':              tx_hash,
            'serial_number':        serial_number,
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
        print(f"\u2705 TX saved [#{serial_number}]: {tx_hash[:10]} ({sender[:10]} -> {destination[:10]})")
        return jsonify({'success': True, 'tx_hash': tx_hash, 'client_token': client_token, 'serial_number': serial_number})

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
            'tx_hash':         tx_data['tx_hash'],
            'serial_number':   tx_data.get('serial_number'),
            'status':          tx_data['status'],
            'created_at':      tx_data.get('created_at'),
            'completed_at':    tx_data.get('completed_at'),
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
        print("\u2705 RUN_MONITOR=1 -> monitor thread started")
    else:
        print("\u2139\ufe0f  RUN_MONITOR=0 -> monitor in dedicated worker")
    print(f"\n\U0001f680 Backend on port {port}")
    print(f"\U0001f30d Allowed origins: {_ALLOWED_ORIGINS}\n")
    app.run(host='0.0.0.0', port=port, debug=False)
