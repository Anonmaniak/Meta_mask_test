// Vercel Serverless Function - Verify Escrow & Forward with Fee Deduction
const { ethers } = require('ethers');

// Shared in-memory storage
let transactions = [];

// Configuration
const CONFIG = {
  ADMIN_PRIVATE_KEY: process.env.ADMIN_PRIVATE_KEY,
  RPC_URL: process.env.RPC_URL || 'https://eth-sepolia.g.alchemy.com/v2/demo',
  VERIFICATION_CONFIRMATIONS: 3,
  FEE_PERCENTAGE: 1
};

let provider = null;
let wallet = null;

function initializeWallet() {
  if (!provider) {
    provider = new ethers.JsonRpcProvider(CONFIG.RPC_URL);
  }
  
  if (!wallet && CONFIG.ADMIN_PRIVATE_KEY) {
    wallet = new ethers.Wallet(CONFIG.ADMIN_PRIVATE_KEY, provider);
    console.log('✅ Escrow wallet initialized:', wallet.address);
  }
  
  return wallet;
}

async function verifyTransaction(txHash) {
  try {
    if (!provider) {
      provider = new ethers.JsonRpcProvider(CONFIG.RPC_URL);
    }

    const receipt = await provider.getTransactionReceipt(txHash);
    
    if (!receipt) {
      return { verified: false, status: 'pending' };
    }

    if (receipt.status === 0) {
      return { verified: false, status: 'failed', receipt };
    }

    const currentBlock = await provider.getBlockNumber();
    const confirmations = currentBlock - receipt.blockNumber;

    if (confirmations >= CONFIG.VERIFICATION_CONFIRMATIONS) {
      return { verified: true, status: 'verified', confirmations, receipt };
    }

    return { verified: false, status: 'confirming', confirmations, receipt };

  } catch (error) {
    console.error('Verification error:', error);
    return { verified: false, status: 'error', error: error.message };
  }
}

async function forwardToDestination(transaction) {
  try {
    const senderWallet = initializeWallet();
    
    if (!senderWallet) {
      throw new Error('Escrow wallet not configured');
    }

    // Calculate amount to forward (original amount minus fee)
    const feeAmount = transaction.amount * (CONFIG.FEE_PERCENTAGE / 100);
    const forwardAmount = transaction.amount - feeAmount;
    
    const amountInWei = ethers.parseEther(forwardAmount.toString());

    console.log(`💸 Forwarding ${forwardAmount} ETH to ${transaction.destinationAddress} (fee: ${feeAmount} ETH)`);

    const tx = await senderWallet.sendTransaction({
      to: transaction.destinationAddress,
      value: amountInWei,
      gasLimit: 21000
    });

    console.log('✅ Forwarded to destination:', tx.hash);

    const receipt = await tx.wait();

    return {
      success: true,
      txHash: tx.hash,
      forwardedAmount: forwardAmount,
      feeKept: feeAmount,
      receipt
    };

  } catch (error) {
    console.error('Error forwarding to destination:', error);
    return {
      success: false,
      error: error.message
    };
  }
}

module.exports = async (req, res) => {
  // Enable CORS
  res.setHeader('Access-Control-Allow-Credentials', true);
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,OPTIONS,POST');
  res.setHeader('Access-Control-Allow-Headers', 'X-CSRF-Token, X-Requested-With, Accept, Accept-Version, Content-Length, Content-MD5, Content-Type, Date, X-Api-Version');

  if (req.method === 'OPTIONS') {
    res.status(200).end();
    return;
  }

  if (req.method === 'POST') {
    try {
      const { txId } = req.body;

      if (!txId) {
        return res.status(400).json({ error: 'Transaction ID required' });
      }

      // Find transaction
      const transaction = transactions.find(tx => tx.id === txId);

      if (!transaction) {
        return res.status(404).json({ error: 'Transaction not found' });
      }

      // Step 1: Verify escrow transaction
      const escrowVerification = await verifyTransaction(transaction.escrowTxHash);

      console.log(`📋 Verifying ${txId}: Escrow=${escrowVerification.status}`);

      // Update transaction based on verification
      if (escrowVerification.verified && transaction.status === 'pending') {
        transaction.status = 'verified';
        transaction.verifiedAt = new Date().toISOString();
        transaction.escrowVerification = escrowVerification;
        console.log(`✅ Escrow verified: ${txId}`);
      }

      // Step 2: Forward to destination (with fee deduction)
      if (transaction.status === 'verified' && !transaction.forwardTxHash) {
        transaction.status = 'forwarding';
        
        const result = await forwardToDestination(transaction);

        if (result.success) {
          transaction.status = 'completed';
          transaction.forwardTxHash = result.txHash;
          transaction.forwardedAmount = result.forwardedAmount;
          transaction.feeKept = result.feeKept;
          transaction.completedAt = new Date().toISOString();
          
          console.log(`✅ Transaction completed: ${txId}`);
          console.log(`   Forwarded: ${result.forwardedAmount} ETH`);
          console.log(`   Fee kept: ${result.feeKept} ETH`);
          
          // AUTO-DELETE after 60 seconds (privacy!)
          setTimeout(() => {
            const index = transactions.findIndex(tx => tx.id === txId);
            if (index > -1) {
              transactions.splice(index, 1);
              console.log(`🗑️ AUTO-DELETED transaction: ${txId}`);
            }
          }, 60000);
          
        } else {
          transaction.status = 'failed';
          transaction.error = result.error;
          transaction.failedAt = new Date().toISOString();
          
          // Auto-delete failed after 5 minutes
          setTimeout(() => {
            const index = transactions.findIndex(tx => tx.id === txId);
            if (index > -1) {
              transactions.splice(index, 1);
              console.log(`🗑️ Deleted failed transaction: ${txId}`);
            }
          }, 300000);
        }
      }

      // Handle failed escrow
      if (escrowVerification.status === 'failed') {
        transaction.status = 'failed';
        transaction.error = 'Escrow transaction failed on blockchain';
        transaction.failedAt = new Date().toISOString();
      }

      res.status(200).json({
        success: true,
        transaction,
        escrowVerification
      });

    } catch (error) {
      console.error('Error processing transaction:', error);
      res.status(500).json({ 
        error: 'Failed to process transaction',
        details: error.message 
      });
    }
  } else {
    res.status(405).json({ error: 'Method not allowed' });
  }
};
