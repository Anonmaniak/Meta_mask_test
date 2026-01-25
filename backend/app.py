from flask import Flask, request, jsonify
from flask_cors import CORS
import os
import json
from datetime import datetime
import uuid
from pathlib import Path

app = Flask(__name__)
CORS(app)

# Configuration
FRONTEND_URL = os.getenv('FRONTEND_URL', 'http://localhost:3000')
DATA_DIR = Path('data')
DATA_DIR.mkdir(exist_ok=True)
TRANSACTIONS_FILE = DATA_DIR / 'transactions.json'

# Initialize transactions file
if not TRANSACTIONS_FILE.exists():
    with open(TRANSACTIONS_FILE, 'w') as f:
        json.dump([], f)

def load_transactions():
    """Load all transactions from file"""
    try:
        with open(TRANSACTIONS_FILE, 'r') as f:
            return json.load(f)
    except:
        return []

def save_transactions(transactions):
    """Save all transactions to file"""
    with open(TRANSACTIONS_FILE, 'w') as f:
        json.dump(transactions, f, indent=2)

@app.route('/api/health', methods=['GET'])
def health():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.utcnow().isoformat(),
        'service': 'secure-payment-backend'
    })

@app.route('/api/transaction', methods=['POST'])
def create_transaction():
    """Save a new transaction"""
    try:
        data = request.get_json()
        
        # Validate required fields
        required_fields = ['senderAddress', 'destinationAddress', 'amount', 'escrowTxHash', 'escrowWallet']
        for field in required_fields:
            if field not in data:
                return jsonify({'error': f'Missing required field: {field}'}), 400
        
        # Create transaction object
        transaction = {
            'id': str(uuid.uuid4()),
            'senderAddress': data['senderAddress'],
            'destinationAddress': data['destinationAddress'],
            'amount': float(data['amount']),
            'securityFee': float(data.get('securityFee', data['amount'] * 0.01)),
            'escrowTxHash': data['escrowTxHash'],
            'escrowWallet': data['escrowWallet'],
            'chainId': data.get('chainId'),
            'status': 'pending',
            'createdAt': datetime.utcnow().isoformat(),
            'updatedAt': datetime.utcnow().isoformat(),
            'escrowVerified': False,
            'forwardTxHash': None,
            'forwardVerified': False
        }
        
        # Load existing transactions
        transactions = load_transactions()
        
        # Add new transaction
        transactions.append(transaction)
        
        # Save to file
        save_transactions(transactions)
        
        print(f"✅ Transaction saved: {transaction['id']}")
        print(f"   From: {transaction['senderAddress']}")
        print(f"   To: {transaction['destinationAddress']}")
        print(f"   Amount: {transaction['amount']} ETH")
        print(f"   Escrow TX: {transaction['escrowTxHash']}")
        
        return jsonify({
            'success': True,
            'transaction': transaction
        }), 201
        
    except Exception as e:
        print(f"❌ Error creating transaction: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/transactions', methods=['GET'])
def get_transactions():
    """Get all transactions (admin endpoint)"""
    try:
        transactions = load_transactions()
        return jsonify({
            'success': True,
            'count': len(transactions),
            'transactions': transactions
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/verify', methods=['POST'])
def verify_transaction():
    """Get transaction status (called by frontend)"""
    try:
        data = request.get_json()
        tx_id = data.get('txId')
        
        if not tx_id:
            return jsonify({'error': 'Transaction ID required'}), 400
        
        transactions = load_transactions()
        transaction = next((tx for tx in transactions if tx['id'] == tx_id), None)
        
        if not transaction:
            return jsonify({'error': 'Transaction not found'}), 404
        
        # Return current status
        # The actual verification and forwarding is done by the background worker
        return jsonify({
            'success': True,
            'transaction': transaction
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    print(f"🚀 Starting Secure Payment Backend on port {port}")
    print(f"📁 Data directory: {DATA_DIR.absolute()}")
    print(f"🌍 Frontend URL: {FRONTEND_URL}")
    app.run(host='0.0.0.0', port=port, debug=False)
