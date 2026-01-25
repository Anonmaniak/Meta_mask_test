from flask import Flask, request, jsonify
from flask_cors import CORS
from web3 import Web3
import os
import json
import threading
import time
from datetime import datetime

app = Flask(__name__)

# Get environment variables
FRONTEND_URL = os.getenv('FRONTEND_URL', 'http://localhost:3000')
RPC_URL = os.getenv('RPC_URL')
ADMIN_PRIVATE_KEY = os.getenv('ADMIN_PRIVATE_KEY')

# Enable CORS
CORS(app, resources={
    r"/api/*": {
        "origins": [FRONTEND_URL, "http://localhost:*"],
        "methods": ["GET", "POST", "OPTIONS"],
        "allow_headers": ["Content-Type"]
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

# In-memory storage (use a database in production)
transactions = {}

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
    """Save transactions to disk"""
    try:
        with open(TRANSACTIONS_FILE, 'w') as f:
            json.dump(transactions, f, indent=2)
    except Exception as e:
        print(f"⚠️  Could not save transactions: {e}")

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
            
            # Process each transaction
            for tx_hash, tx_data in list(transactions.items()):
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
    """Check if pending transaction is verified"""
    try:
        receipt = w3.eth.get_transaction_receipt(tx_hash)
        
        if receipt and receipt['status'] == 1:
            confirmations = current_block - receipt['blockNumber']
            
            if confirmations >= VERIFICATION_CONFIRMATIONS:
                print(f"✅ Escrow VERIFIED: {tx_hash[:10]}... ({confirmations} confirmations)")
                transactions[tx_hash]['status'] = 'verified'
                transactions[tx_hash]['escrow_block'] = receipt['blockNumber']
                transactions[tx_hash]['verified_at'] = datetime.utcnow().isoformat()
                save_transactions()
    except Exception as e:
        print(f"⚠️  Error checking {tx_hash[:10]}...: {e}")

def process_verified_transaction(tx_hash, tx_data):
    """Forward verified transaction to destination"""
    try:
        destination = tx_data['destination']
        amount_wei = int(tx_data['amount_wei'])
        
        # Calculate amount after fee
        fee_amount = int(amount_wei * FEE_PERCENTAGE / 100)
        forward_amount = amount_wei - fee_amount
        
        print(f"🚀 Forwarding {tx_hash[:10]}... to {destination[:10]}...")
        print(f"   Amount: {w3.from_wei(forward_amount, 'ether')} ETH (fee: {w3.from_wei(fee_amount, 'ether')} ETH)")
        
        # Get current nonce
        nonce = w3.eth.get_transaction_count(escrow_address)
        
        # Build forward transaction
        forward_tx = {
            'from': escrow_address,
            'to': destination,
            'value': forward_amount,
            'nonce': nonce,
            'gas': 21000,
            'gasPrice': w3.eth.gas_price
        }
        
        # Sign and send
        signed_forward = w3.eth.account.sign_transaction(forward_tx, ADMIN_PRIVATE_KEY)
        forward_hash = w3.eth.send_raw_transaction(signed_forward.raw_transaction)
        forward_hash_hex = forward_hash.hex()
        
        print(f"✅ Forward transaction sent: {forward_hash_hex}")
        
        # Update transaction
        transactions[tx_hash]['status'] = 'forwarding_pending'
        transactions[tx_hash]['forward_tx_hash'] = forward_hash_hex
        transactions[tx_hash]['forwarded_at'] = datetime.utcnow().isoformat()
        transactions[tx_hash]['fee_amount'] = str(fee_amount)
        save_transactions()
        
    except Exception as e:
        print(f"❌ Forward error for {tx_hash[:10]}...: {e}")
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
            del transactions[tx_hash]
            save_transactions()
    except Exception as e:
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
        'escrow_address': escrow_address
    })

@app.route('/api/transaction', methods=['POST', 'OPTIONS'])
def create_transaction():
    """Create new transaction record"""
    if request.method == 'OPTIONS':
        return '', 204
    
    try:
        data = request.get_json()
        
        tx_hash = data.get('tx_hash')
        sender = data.get('sender')
        destination = data.get('destination')
        amount_wei = data.get('amount_wei')
        
        if not all([tx_hash, sender, destination, amount_wei]):
            return jsonify({'error': 'Missing required fields'}), 400
        
        # Store transaction
        transactions[tx_hash] = {
            'tx_hash': tx_hash,
            'sender': sender,
            'destination': destination,
            'amount_wei': str(amount_wei),
            'status': 'pending',
            'created_at': datetime.utcnow().isoformat()
        }
        
        save_transactions()
        
        print(f"✅ Transaction saved: {tx_hash[:10]}... ({sender[:10]}... → {destination[:10]}...)")
        
        return jsonify({
            'success': True,
            'message': 'Transaction recorded',
            'tx_hash': tx_hash
        })
        
    except Exception as e:
        print(f"❌ Error creating transaction: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/transaction/<tx_hash>', methods=['GET'])
def get_transaction(tx_hash):
    """Get transaction status"""
    try:
        if tx_hash not in transactions:
            return jsonify({'error': 'Transaction not found'}), 404
        
        return jsonify(transactions[tx_hash])
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/transactions', methods=['GET'])
def get_all_transactions():
    """Get all transactions"""
    try:
        return jsonify(list(transactions.values()))
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
