from flask import Flask, request, jsonify
from flask_cors import CORS
from web3 import Web3
import os
import json
import threading
import time
import secrets
from datetime import datetime

app = Flask(__name__)

# Get environment variables
FRONTEND_URL = os.getenv('FRONTEND_URL', 'http://localhost:3000')
RPC_URL = os.getenv('RPC_URL')
ADMIN_PRIVATE_KEY = os.getenv('ADMIN_PRIVATE_KEY')
ADMIN_TOKEN = os.getenv('ADMIN_TOKEN')  # set this in Render to protect admin endpoints

# Enable CORS
CORS(app, resources={
    r"/api/*": {
        "origins": [FRONTEND_URL, "http://localhost:*"],
        "methods": ["GET", "POST", "OPTIONS"],
        "allow_headers": ["Content-Type", "X-Client-Token", "X-Admin-Token"]
    }
})

# Connect to blockchain
if not RPC_URL:
    raise Exception("RPC_URL environment variable not set")

w3 = Web3(Web3.HTTPProvider(RPC_URL))

if not w3.is_connected():
    raise Exception(f"Failed to connect to blockchain: {RPC_URL}")

print(f"✅ Connected to blockchain: {RPC_URL}")
print(f"   Current block: {w3.eth.block_number}")

# Initialize escrow account
if not ADMIN_PRIVATE_KEY:
    raise Exception("ADMIN_PRIVATE_KEY environment variable not set")

escrow_account = w3.eth.account.from_key(ADMIN_PRIVATE_KEY)
escrow_address = escrow_account.address

print(f"✅ Escrow wallet: {escrow_address}")
balance = w3.eth.get_balance(escrow_address)
print(f"   Balance: {w3.from_wei(balance, 'ether')} ETH")

# Configuration
VERIFICATION_CONFIRMATIONS = int(os.getenv('VERIFICATION_CONFIRMATIONS', 3))
FEE_PERCENTAGE = float(os.getenv('FEE_PERCENTAGE', 1))
POLL_INTERVAL = int(os.getenv('POLL_INTERVAL', 30))

# Thread-safe storage
transactions = {}
transactions_lock = threading.Lock()

# Data directory for persistence
DATA_DIR = os.path.join(os.getcwd(), 'data')
os.makedirs(DATA_DIR, exist_ok=True)
TRANSACTIONS_FILE = os.path.join(DATA_DIR, 'transactions.json')

print(f"📁 Data directory: {DATA_DIR}")

# Load existing transactions
if os.path.exists(TRANSACTIONS_FILE):
    try:
        with open(TRANSACTIONS_FILE, 'r') as f:
            transactions = json.load(f)
        print(f"📥 Loaded {len(transactions)} existing transactions")
    except Exception as e:
        print(f"⚠️  Could not load transactions: {e}")
        transactions = {}

def save_transactions():
    """Save transactions to disk (thread-safe)"""
    try:
        with transactions_lock:
            with open(TRANSACTIONS_FILE, 'w') as f:
                json.dump(transactions, f, indent=2)
    except Exception as e:
        print(f"⚠️  Could not save transactions: {e}")

# ===========================
# AUTH HELPERS
# ===========================

def _admin_token_from_request():
    return request.headers.get('X-Admin-Token') or request.args.get('admin_token')

def _client_token_from_request():
    return request.headers.get('X-Client-Token') or request.args.get('token')

def is_admin_request():
    # If ADMIN_TOKEN isn't set, we treat admin endpoints as locked (fail-closed)
    if not ADMIN_TOKEN:
        return False
    return secrets.compare_digest(str(_admin_token_from_request() or ''), str(ADMIN_TOKEN))

# ===========================
# TRANSACTION MONITOR (Background)
# ===========================

def monitor_transactions():
    """Background thread to monitor and process transactions"""
    print("\n🤖 Transaction Monitor Started (Background Thread)")
    print("⏳ Monitoring for transactions...\n")

    while True:
        try:
            current_block = w3.eth.block_number

            # Process each transaction (thread-safe)
            with transactions_lock:
                tx_list = list(transactions.items())

            for tx_hash, tx_data in tx_list:
                status = tx_data.get('status')

                # Process based on status
                if status == 'pending':
                    process_pending_transaction(tx_hash, tx_data, current_block)
                elif status == 'verified':
                    process_verified_transaction(tx_hash, tx_data)
                elif status == 'forwarding_pending':
                    process_forwarding_transaction(tx_hash, tx_data, current_block)
                elif status == 'complete':
                    auto_delete_completed(tx_hash, tx_data)

            # Sleep before next check
            time.sleep(POLL_INTERVAL)

        except Exception as e:
            print(f"❌ Monitor error: {e}")
            time.sleep(POLL_INTERVAL)

def process_pending_transaction(tx_hash, tx_data, current_block):
    """Check if pending transaction is verified with STRICT validation"""
    try:
        receipt = w3.eth.get_transaction_receipt(tx_hash)

        if receipt and receipt['status'] == 1:
            confirmations = current_block - receipt['blockNumber']

            if confirmations >= VERIFICATION_CONFIRMATIONS:
                # STRICT VERIFICATION: Fetch original transaction
                tx = w3.eth.get_transaction(tx_hash)

                # Validate: to address matches escrow
                if (tx.get('to') or '').lower() != escrow_address.lower():
                    print(f"❌ INVALID: {tx_hash[:10]}... sent to wrong address")
                    with transactions_lock:
                        transactions[tx_hash]['status'] = 'failed'
                        transactions[tx_hash]['error'] = 'Transaction sent to wrong address'
                    save_transactions()
                    return

                # Validate: from address matches sender
                if (tx.get('from') or '').lower() != tx_data['sender'].lower():
                    print(f"❌ INVALID: {tx_hash[:10]}... from address mismatch")
                    with transactions_lock:
                        transactions[tx_hash]['status'] = 'failed'
                        transactions[tx_hash]['error'] = 'Sender address mismatch'
                    save_transactions()
                    return

                # Validate: amount matches deposit
                expected_amount = int(tx_data['deposit_wei'])
                if int(tx.get('value', 0)) != expected_amount:
                    print(f"❌ INVALID: {tx_hash[:10]}... amount mismatch (expected {expected_amount}, got {tx.get('value')})")
                    with transactions_lock:
                        transactions[tx_hash]['status'] = 'failed'
                        transactions[tx_hash]['error'] = f'Amount mismatch: expected {expected_amount} wei, got {tx.get("value")} wei'
                    save_transactions()
                    return

                print(f"✅ Escrow VERIFIED: {tx_hash[:10]}... ({confirmations} confirmations) - All checks passed")
                with transactions_lock:
                    transactions[tx_hash]['status'] = 'verified'
                    transactions[tx_hash]['escrow_block'] = receipt['blockNumber']
                    transactions[tx_hash]['verified_at'] = datetime.utcnow().isoformat()
                save_transactions()

    except Exception as e:
        print(f"⚠️  Error checking {tx_hash[:10]}...: {e}")

def _get_signed_raw_tx(signed_tx):
    """Compatibility across eth-account/web3.py versions."""
    # Some versions expose rawTransaction (camelCase), others raw_transaction (snake_case)
    if hasattr(signed_tx, 'rawTransaction'):
        return signed_tx.rawTransaction
    if hasattr(signed_tx, 'raw_transaction'):
        return signed_tx.raw_transaction
    raise AttributeError("SignedTransaction has no rawTransaction/raw_transaction attribute")

def process_verified_transaction(tx_hash, tx_data):
    """Forward verified transaction to destination using ONLY client-prepaid gas."""
    try:
        destination = Web3.to_checksum_address(tx_data['destination'])
        
        deposit_wei = int(tx_data['deposit_wei'])
        recipient_wei = int(tx_data['recipient_amount_wei'])
        buffer_wei = int(tx_data.get('forward_gas_buffer_wei', '0'))

        # Recompute 1% platform fee from deposit (don't trust client blindly)
        platform_fee_wei = int(deposit_wei * FEE_PERCENTAGE / 100)

        # Ensure recipient is not more than what deposit can logically support
        max_recipient = deposit_wei - platform_fee_wei - buffer_wei
        if recipient_wei > max_recipient:
            recipient_wei = max(0, max_recipient)

        forward_amount = recipient_wei

        print(f"🚀 Forwarding {tx_hash[:10]}... to {destination[:10]}...")
        print(f"   Amount: {w3.from_wei(forward_amount, 'ether')} ETH")

        # Get current gas price (dynamic, tracks network changes)
        gas_price = int(w3.eth.gas_price)
        gas_limit = 21000
        estimated_cost = gas_limit * gas_price

        # CRITICAL: Only forward if prepaid buffer covers gas
        if estimated_cost > buffer_wei:
            print(f"❌ Not enough prepaid gas for {tx_hash[:10]}... "
                  f"(needed {estimated_cost} wei, have {buffer_wei} wei)")
            with transactions_lock:
                transactions[tx_hash]['status'] = 'forward_failed'
                transactions[tx_hash]['error'] = 'Insufficient gas buffer for forward'
            save_transactions()
            return

        # Get PENDING nonce (important for multiple transactions)
        nonce = w3.eth.get_transaction_count(escrow_address, 'pending')

        # Build forward transaction
        forward_tx = {
            'to': destination,
            'value': forward_amount,
            'nonce': nonce,
            'gas': gas_limit,
            'gasPrice': gas_price,
            'chainId': int(w3.eth.chain_id),
        }

        # Sign and send
        signed_forward = w3.eth.account.sign_transaction(forward_tx, ADMIN_PRIVATE_KEY)
        raw_tx = _get_signed_raw_tx(signed_forward)
        forward_hash = w3.eth.send_raw_transaction(raw_tx)
        forward_hash_hex = forward_hash.hex()

        print(f"✅ Forward transaction sent: {forward_hash_hex}")

        # Update transaction (thread-safe)
        with transactions_lock:
            transactions[tx_hash]['status'] = 'forwarding_pending'
            transactions[tx_hash]['forward_tx_hash'] = forward_hash_hex
            transactions[tx_hash]['forwarded_at'] = datetime.utcnow().isoformat()
            transactions[tx_hash]['fee_amount'] = str(platform_fee_wei)
        save_transactions()

    except Exception as e:
        print(f"❌ Forward error for {tx_hash[:10]}...: {e}")
        with transactions_lock:
            transactions[tx_hash]['status'] = 'forward_failed'
            transactions[tx_hash]['error'] = str(e)
        save_transactions()

def process_forwarding_transaction(tx_hash, tx_data, current_block):
    """Check if forward transaction is verified"""
    try:
        forward_hash = tx_data.get('forward_tx_hash')
        if not forward_hash:
            return

        receipt = w3.eth.get_transaction_receipt(forward_hash)

        if receipt and receipt['status'] == 1:
            confirmations = current_block - receipt['blockNumber']

            if confirmations >= VERIFICATION_CONFIRMATIONS:
                print(f"🎉 COMPLETE: {tx_hash[:10]}... (forward verified)")
                with transactions_lock:
                    transactions[tx_hash]['status'] = 'complete'
                    transactions[tx_hash]['forward_block'] = receipt['blockNumber']
                    transactions[tx_hash]['completed_at'] = datetime.utcnow().isoformat()
                save_transactions()
    except Exception as e:
        print(f"⚠️  Error checking forward {tx_hash[:10]}...: {e}")

def auto_delete_completed(tx_hash, tx_data):
    """Auto-delete completed transactions after 60 seconds"""
    try:
        completed_at = datetime.fromisoformat(tx_data.get('completed_at', ''))
        elapsed = (datetime.utcnow() - completed_at).total_seconds()

        if elapsed > 60:
            print(f"🗑️  AUTO-DELETED: {tx_hash[:10]}... (completed {int(elapsed)}s ago)")
            with transactions_lock:
                del transactions[tx_hash]
            save_transactions()
    except Exception:
        pass

# ===========================
# API ROUTES
# ===========================

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.utcnow().isoformat(),
        'service': 'secure-payment-backend',
        'blockchain_connected': w3.is_connected(),
        'escrow_address': escrow_address,
        'current_block': w3.eth.block_number
    })

@app.route('/api/transaction', methods=['POST', 'OPTIONS'])
def create_transaction():
    """Create new transaction record.

    Returns a client_token that is required to read this transaction status later.
    """
    if request.method == 'OPTIONS':
        return '', 204

    try:
        data = request.get_json() or {}

        tx_hash = data.get('tx_hash')
        sender = data.get('sender')
        destination = data.get('destination')
        amount_wei = data.get('amount_wei')  # deposit from sender
        recipient_amount_wei = data.get('recipient_amount_wei')
        forward_gas_buffer_wei = data.get('forward_gas_buffer_wei', '0')

        if not all([tx_hash, sender, destination, amount_wei, recipient_amount_wei]):
            return jsonify({'error': 'Missing required fields'}), 400

        # Validate addresses
        if not Web3.is_address(sender):
            return jsonify({'error': 'Invalid sender address'}), 400

        if not Web3.is_address(destination):
            return jsonify({'error': 'Invalid destination address'}), 400

        # Normalize to checksum to prevent downstream signing issues
        sender_checksum = Web3.to_checksum_address(sender)
        destination_checksum = Web3.to_checksum_address(destination)

        # Generate per-transaction read token (prevents public status scraping by tx_hash)
        client_token = secrets.token_urlsafe(24)

        # Store transaction (thread-safe)
        with transactions_lock:
            transactions[tx_hash] = {
                'tx_hash': tx_hash,
                'sender': sender_checksum,
                'destination': destination_checksum,
                'deposit_wei': str(amount_wei),
                'recipient_amount_wei': str(recipient_amount_wei),
                'forward_gas_buffer_wei': str(forward_gas_buffer_wei),
                'status': 'pending',
                'created_at': datetime.utcnow().isoformat(),
                'client_token': client_token,
            }

        save_transactions()

        print(f"✅ Transaction saved: {tx_hash[:10]}... ({sender_checksum[:10]}... → {destination_checksum[:10]}...)")

        return jsonify({
            'success': True,
            'message': 'Transaction recorded',
            'tx_hash': tx_hash,
            'client_token': client_token,
        })

    except Exception as e:
        print(f"❌ Error creating transaction: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/transaction/<tx_hash>', methods=['GET'])
def get_transaction(tx_hash):
    """Get transaction status (requires client token or admin token)."""
    try:
        with transactions_lock:
            if tx_hash not in transactions:
                return jsonify({'error': 'Transaction not found'}), 404
            tx_data = transactions[tx_hash].copy()

        # auth: admin OR correct client_token
        if is_admin_request():
            return jsonify(tx_data)

        client_token = _client_token_from_request()
        if not client_token or not secrets.compare_digest(str(client_token), str(tx_data.get('client_token') or '')):
            return jsonify({'error': 'Forbidden'}), 403

        return jsonify(tx_data)

    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/transactions', methods=['GET'])
def get_all_transactions():
    """Admin-only: list all transactions."""
    try:
        if not is_admin_request():
            # fail closed even if ADMIN_TOKEN missing
            return jsonify({'error': 'Forbidden'}), 403

        with transactions_lock:
            tx_list = list(transactions.values())
        return jsonify(tx_list)

    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ===========================
# START SERVER
# ===========================

if __name__ == '__main__':
    # Start monitor in background thread
    monitor_thread = threading.Thread(target=monitor_transactions, daemon=True)
    monitor_thread.start()

    # Start Flask app
    port = int(os.getenv('PORT', 10000))
    print(f"\n🚀 Starting Secure Payment Backend on port {port}")
    print(f"🌍 Frontend URL: {FRONTEND_URL}\n")

    app.run(host='0.0.0.0', port=port, debug=False)
