#!/usr/bin/env python3
"""
Background worker to monitor blockchain transactions and auto-forward payments

This script:
1. Monitors pending transactions
2. Verifies escrow transactions (3+ confirmations)
3. Automatically forwards to destination (minus 1% fee)
4. Verifies forward transactions
5. Deletes completed transactions after verification
"""

import os
import json
import time
from datetime import datetime
from pathlib import Path
from web3 import Web3
from decimal import Decimal

# Configuration
RPC_URL = os.getenv('RPC_URL', 'https://eth-sepolia.g.alchemy.com/v2/demo')
ADMIN_PRIVATE_KEY = os.getenv('ADMIN_PRIVATE_KEY')  # Escrow wallet private key
VERIFICATION_CONFIRMATIONS = int(os.getenv('VERIFICATION_CONFIRMATIONS', '3'))
FEE_PERCENTAGE = float(os.getenv('FEE_PERCENTAGE', '1'))  # 1%
POLL_INTERVAL = int(os.getenv('POLL_INTERVAL', '30'))  # seconds
DATA_DIR = Path('data')
TRANSACTIONS_FILE = DATA_DIR / 'transactions.json'

# Initialize Web3
w3 = Web3(Web3.HTTPProvider(RPC_URL))

if not w3.is_connected():
    print("❌ Failed to connect to blockchain RPC")
    exit(1)

print(f"✅ Connected to blockchain: {RPC_URL}")
print(f"   Current block: {w3.eth.block_number}")

# Initialize escrow wallet
if ADMIN_PRIVATE_KEY:
    escrow_account = w3.eth.account.from_key(ADMIN_PRIVATE_KEY)
    print(f"✅ Escrow wallet: {escrow_account.address}")
    balance = w3.eth.get_balance(escrow_account.address)
    print(f"   Balance: {w3.from_wei(balance, 'ether')} ETH")
else:
    print("⚠️  WARNING: ADMIN_PRIVATE_KEY not set - forwarding will not work!")
    escrow_account = None

def load_transactions():
    """Load transactions from file"""
    try:
        if not TRANSACTIONS_FILE.exists():
            return []
        with open(TRANSACTIONS_FILE, 'r') as f:
            return json.load(f)
    except Exception as e:
        print(f"❌ Error loading transactions: {e}")
        return []

def save_transactions(transactions):
    """Save transactions to file"""
    try:
        with open(TRANSACTIONS_FILE, 'w') as f:
            json.dump(transactions, f, indent=2)
    except Exception as e:
        print(f"❌ Error saving transactions: {e}")

def verify_transaction(tx_hash):
    """Verify a transaction has enough confirmations"""
    try:
        receipt = w3.eth.get_transaction_receipt(tx_hash)
        
        if not receipt:
            return {'verified': False, 'status': 'pending', 'confirmations': 0}
        
        if receipt['status'] == 0:
            return {'verified': False, 'status': 'failed', 'receipt': receipt}
        
        current_block = w3.eth.block_number
        confirmations = current_block - receipt['blockNumber']
        
        if confirmations >= VERIFICATION_CONFIRMATIONS:
            return {'verified': True, 'status': 'verified', 'confirmations': confirmations}
        
        return {'verified': False, 'status': 'confirming', 'confirmations': confirmations}
        
    except Exception as e:
        print(f"   ❌ Verification error for {tx_hash}: {e}")
        return {'verified': False, 'status': 'error', 'error': str(e)}

def forward_to_destination(transaction):
    """Forward funds from escrow to destination"""
    if not escrow_account:
        return {'success': False, 'error': 'Escrow wallet not configured'}
    
    try:
        # Calculate amounts
        amount = Decimal(str(transaction['amount']))
        fee = amount * Decimal(str(FEE_PERCENTAGE)) / Decimal('100')
        forward_amount = amount - fee
        
        # Convert to Wei
        forward_wei = w3.to_wei(forward_amount, 'ether')
        
        # Get current gas price
        gas_price = w3.eth.gas_price
        
        # Get nonce
        nonce = w3.eth.get_transaction_count(escrow_account.address)
        
        # Build transaction
        tx = {
            'nonce': nonce,
            'to': transaction['destinationAddress'],
            'value': forward_wei,
            'gas': 21000,
            'gasPrice': gas_price,
            'chainId': w3.eth.chain_id
        }
        
        # Sign transaction
        signed_tx = w3.eth.account.sign_transaction(tx, ADMIN_PRIVATE_KEY)
        
        # Send transaction
        tx_hash = w3.eth.send_raw_transaction(signed_tx.rawTransaction)
        tx_hash_hex = tx_hash.hex()
        
        print(f"   ✅ Forward transaction sent: {tx_hash_hex}")
        print(f"      Amount: {forward_amount} ETH")
        print(f"      Fee kept: {fee} ETH")
        
        return {
            'success': True,
            'txHash': tx_hash_hex,
            'forwardedAmount': float(forward_amount),
            'feeKept': float(fee)
        }
        
    except Exception as e:
        print(f"   ❌ Forward error: {e}")
        return {'success': False, 'error': str(e)}

def process_transaction(transaction, all_transactions):
    """Process a single transaction through its lifecycle"""
    tx_id = transaction['id']
    status = transaction['status']
    
    print(f"\n🔍 Processing: {tx_id[:8]}... (status: {status})")
    
    # STEP 1: Verify escrow transaction
    if status == 'pending' and not transaction.get('escrowVerified'):
        print(f"   📋 Verifying escrow transaction...")
        result = verify_transaction(transaction['escrowTxHash'])
        
        print(f"      Status: {result['status']} ({result.get('confirmations', 0)}/{VERIFICATION_CONFIRMATIONS} confirmations)")
        
        if result['verified']:
            transaction['escrowVerified'] = True
            transaction['status'] = 'verified'
            transaction['verifiedAt'] = datetime.utcnow().isoformat()
            transaction['escrowConfirmations'] = result['confirmations']
            print(f"   ✅ Escrow VERIFIED ({result['confirmations']} confirmations)")
            return True  # Modified
            
        elif result['status'] == 'failed':
            transaction['status'] = 'failed'
            transaction['error'] = 'Escrow transaction failed'
            transaction['failedAt'] = datetime.utcnow().isoformat()
            print(f"   ❌ Escrow FAILED")
            return True
    
    # STEP 2: Forward to destination
    elif status == 'verified' and not transaction.get('forwardTxHash'):
        print(f"   🚀 Initiating forward to destination...")
        result = forward_to_destination(transaction)
        
        if result['success']:
            transaction['status'] = 'forwarding_pending'
            transaction['forwardTxHash'] = result['txHash']
            transaction['forwardedAmount'] = result['forwardedAmount']
            transaction['feeKept'] = result['feeKept']
            transaction['forwardInitiatedAt'] = datetime.utcnow().isoformat()
            return True
        else:
            transaction['status'] = 'failed'
            transaction['error'] = result.get('error', 'Forward failed')
            transaction['failedAt'] = datetime.utcnow().isoformat()
            return True
    
    # STEP 3: Verify forward transaction
    elif status == 'forwarding_pending' and not transaction.get('forwardVerified'):
        print(f"   📋 Verifying forward transaction...")
        result = verify_transaction(transaction['forwardTxHash'])
        
        print(f"      Status: {result['status']} ({result.get('confirmations', 0)}/{VERIFICATION_CONFIRMATIONS} confirmations)")
        
        if result['verified']:
            transaction['forwardVerified'] = True
            transaction['status'] = 'completed'
            transaction['completedAt'] = datetime.utcnow().isoformat()
            transaction['forwardConfirmations'] = result['confirmations']
            print(f"   🎉 BOTH TRANSACTIONS VERIFIED - COMPLETE!")
            print(f"      Escrow: {transaction.get('escrowConfirmations')} confirmations")
            print(f"      Forward: {result['confirmations']} confirmations")
            return True
            
        elif result['status'] == 'failed':
            transaction['status'] = 'failed'
            transaction['error'] = 'Forward transaction failed'
            transaction['failedAt'] = datetime.utcnow().isoformat()
            print(f"   ❌ Forward FAILED")
            return True
    
    return False

def cleanup_old_transactions(transactions):
    """Remove completed and failed transactions after retention period"""
    now = datetime.utcnow()
    to_remove = []
    
    for tx in transactions:
        if tx['status'] == 'completed':
            completed_at = datetime.fromisoformat(tx.get('completedAt', tx['createdAt']))
            age_seconds = (now - completed_at).total_seconds()
            
            # Delete after 60 seconds
            if age_seconds > 60:
                to_remove.append(tx['id'])
                print(f"🗑️  Deleting completed transaction: {tx['id'][:8]}... (age: {int(age_seconds)}s)")
        
        elif tx['status'] == 'failed':
            failed_at = datetime.fromisoformat(tx.get('failedAt', tx['createdAt']))
            age_seconds = (now - failed_at).total_seconds()
            
            # Delete failed after 5 minutes
            if age_seconds > 300:
                to_remove.append(tx['id'])
                print(f"🗑️  Deleting failed transaction: {tx['id'][:8]}... (age: {int(age_seconds)}s)")
    
    # Remove transactions
    if to_remove:
        transactions[:] = [tx for tx in transactions if tx['id'] not in to_remove]
        return True
    
    return False

def main():
    """Main monitoring loop"""
    print(f"\n🤖 Transaction Monitor Started")
    print(f"   Poll interval: {POLL_INTERVAL}s")
    print(f"   Required confirmations: {VERIFICATION_CONFIRMATIONS}")
    print(f"   Fee percentage: {FEE_PERCENTAGE}%")
    print(f"   Data file: {TRANSACTIONS_FILE.absolute()}")
    print(f"\n⏳ Monitoring for transactions...\n")
    
    while True:
        try:
            # Load current transactions
            transactions = load_transactions()
            
            if not transactions:
                print(".", end="", flush=True)
                time.sleep(POLL_INTERVAL)
                continue
            
            print(f"\n📊 Found {len(transactions)} transaction(s) to process")
            
            # Process each transaction
            modified = False
            for tx in transactions:
                if tx['status'] not in ['completed', 'failed']:
                    if process_transaction(tx, transactions):
                        modified = True
            
            # Cleanup old transactions
            if cleanup_old_transactions(transactions):
                modified = True
            
            # Save if modified
            if modified:
                save_transactions(transactions)
                print(f"💾 Transactions saved")
            
        except KeyboardInterrupt:
            print("\n\n🛑 Monitor stopped by user")
            break
        except Exception as e:
            print(f"\n❌ Monitor error: {e}")
        
        # Wait before next poll
        time.sleep(POLL_INTERVAL)

if __name__ == '__main__':
    main()
