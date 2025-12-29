// Vercel Serverless Function - Verify and Forward Transaction
const { ethers } = require('ethers');

// Shared in-memory storage
let transactions = [];

// Configuration from environment
const CONFIG = {
  ADMIN_PRIVATE_KEY: process.env.ADMIN_PRIVATE_KEY,
  RPC_URL: process.env.RPC_URL || 'https://eth-sepolia.g.alchemy.com/v2/demo',
  VERIFICATION_CONFIRMATIONS: 3
};

let provider = null;
let wallet = null;

function initializeWallet() {
  if (!provider) {
    provider = new ethers.JsonRpcProvider(CONFIG.RPC_URL);
  }
  
  if (!wallet && CONFIG.ADMIN_PRIVATE_KEY) {
    wallet = new ethers.Wallet(CONFIG.ADMIN_PRIVATE_KEY, provider);
    console.log('✅ Wallet initialized:', wallet.address);
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

async function sendToDestination(transaction) {
  try {
    const senderWallet = initializeWallet();
    
    if (!senderWallet) {
      throw new Error('Admin wallet not configured');
    }

    const amountInWei = ethers.parseEther(transaction.amount.toString());

    const tx = await senderWallet.sendTransaction({
      to: transaction.destinationAddress,
      value: amountInWei,
      gasLimit: 21000
    });

    console.log('📤 Sent to destination:', tx.hash);

    const receipt = await tx.wait();

    return {
      success: true,
      txHash: tx.hash,
      receipt
    };

  } catch (error) {
    console.error('Error sending to destination:', error);
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

      // Verify both transactions
      const feeVerification = await verifyTransaction(transaction.feeTxHash);
      const mainVerification = await verifyTransaction(transaction.mainTxHash);

      console.log(`Verifying ${txId}: Fee=${feeVerification.status}, Main=${mainVerification.status}`);

      // Update transaction based on verification
      if (feeVerification.verified && mainVerification.verified) {
        if (transaction.status === 'pending') {
          transaction.status = 'verified';
          transaction.verifiedAt = new Date().toISOString();
          console.log(`✅ Transaction verified: ${txId}`);
        }

        // Send to destination if verified and not already sent
        if (transaction.status === 'verified' && !transaction.finalTxHash) {
          const result = await sendToDestination(transaction);

          if (result.success) {
            transaction.status = 'completed';
            transaction.finalTxHash = result.txHash;
            transaction.completedAt = new Date().toISOString();
            
            console.log(`✅ Transaction completed: ${txId}`);
            
            // AUTO-DELETE after completion (temporary storage!)
            setTimeout(() => {
              const index = transactions.findIndex(tx => tx.id === txId);
              if (index > -1) {
                transactions.splice(index, 1);
                console.log(`🗑️ Auto-deleted completed transaction: ${txId}`);
              }
            }, 60000); // Delete after 1 minute
            
          } else {
            transaction.status = 'failed';
            transaction.error = result.error;
            transaction.failedAt = new Date().toISOString();
          }
        }
      } else if (feeVerification.status === 'failed' || mainVerification.status === 'failed') {
        transaction.status = 'failed';
        transaction.error = 'One or more blockchain transactions failed';
        transaction.failedAt = new Date().toISOString();
        
        // AUTO-DELETE failed transactions after 5 minutes
        setTimeout(() => {
          const index = transactions.findIndex(tx => tx.id === txId);
          if (index > -1) {
            transactions.splice(index, 1);
            console.log(`🗑️ Auto-deleted failed transaction: ${txId}`);
          }
        }, 300000); // Delete after 5 minutes
      }

      res.status(200).json({
        success: true,
        transaction,
        feeVerification,
        mainVerification
      });

    } catch (error) {
      console.error('Error verifying transaction:', error);
      res.status(500).json({ 
        error: 'Failed to verify transaction',
        details: error.message 
      });
    }
  } else {
    res.status(405).json({ error: 'Method not allowed' });
  }
};
