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
      return { verified: false, status: 'pending', confirmations: 0 };
    }

    if (receipt.status === 0) {
      return { verified: false, status: 'failed', receipt };
    }

    const currentBlock = await provider.getBlockNumber();
    const confirmations = currentBlock - receipt.blockNumber;

    console.log(`   📊 TX ${txHash.substring(0, 10)}... has ${confirmations} confirmations (need ${CONFIG.VERIFICATION_CONFIRMATIONS})`);

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

    // Wait for transaction to be mined
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

      console.log(`\n🔍 Processing transaction: ${txId}`);
      console.log(`   Current status: ${transaction.status}`);

      // =====================================================
      // STEP 1: VERIFY ESCROW TRANSACTION (User → Escrow)
      // =====================================================
      const escrowVerification = await verifyTransaction(transaction.escrowTxHash);
      console.log(`   📋 Escrow TX status: ${escrowVerification.status}`);

      // If escrow transaction verified and we haven't marked it yet
      if (escrowVerification.verified && transaction.status === 'pending') {
        transaction.status = 'verified';
        transaction.verifiedAt = new Date().toISOString();
        transaction.escrowVerification = escrowVerification;
        console.log(`   ✅ Escrow transaction VERIFIED (${escrowVerification.confirmations} confirmations)`);
      }

      // If escrow transaction failed
      if (escrowVerification.status === 'failed') {
        transaction.status = 'failed';
        transaction.error = 'Escrow transaction failed on blockchain';
        transaction.failedAt = new Date().toISOString();
        console.log(`   ❌ Escrow transaction FAILED`);
        
        // Delete failed transactions after 5 minutes
        setTimeout(() => {
          const index = transactions.findIndex(tx => tx.id === txId);
          if (index > -1) {
            transactions.splice(index, 1);
            console.log(`🗑️ Deleted failed transaction: ${txId}`);
          }
        }, 300000);
      }

      // =====================================================
      // STEP 2: FORWARD TO DESTINATION (Escrow → Destination)
      // =====================================================
      if (transaction.status === 'verified' && !transaction.forwardTxHash) {
        transaction.status = 'forwarding';
        console.log(`   🚀 Initiating forward to destination...`);
        
        const result = await forwardToDestination(transaction);

        if (result.success) {
          transaction.status = 'forwarding_pending';
          transaction.forwardTxHash = result.txHash;
          transaction.forwardedAmount = result.forwardedAmount;
          transaction.feeKept = result.feeKept;
          transaction.forwardInitiatedAt = new Date().toISOString();
          
          console.log(`   ✅ Forward transaction sent: ${result.txHash}`);
          console.log(`   💰 Forwarded: ${result.forwardedAmount} ETH`);
          console.log(`   💵 Fee kept: ${result.feeKept} ETH`);
          console.log(`   ⏳ Waiting for forward transaction confirmation...`);
          
        } else {
          transaction.status = 'failed';
          transaction.error = result.error;
          transaction.failedAt = new Date().toISOString();
          console.log(`   ❌ Forward transaction FAILED: ${result.error}`);
          
          // Delete failed after 5 minutes
          setTimeout(() => {
            const index = transactions.findIndex(tx => tx.id === txId);
            if (index > -1) {
              transactions.splice(index, 1);
              console.log(`🗑️ Deleted failed transaction: ${txId}`);
            }
          }, 300000);
        }
      }

      // =====================================================
      // STEP 3: VERIFY FORWARD TRANSACTION (Escrow → Destination)
      // =====================================================
      let forwardVerification = null;
      
      if (transaction.forwardTxHash && transaction.status === 'forwarding_pending') {
        forwardVerification = await verifyTransaction(transaction.forwardTxHash);
        console.log(`   📋 Forward TX status: ${forwardVerification.status}`);

        // BOTH TRANSACTIONS MUST BE VERIFIED BEFORE MARKING AS COMPLETE
        if (forwardVerification.verified) {
          transaction.status = 'completed';
          transaction.forwardVerification = forwardVerification;
          transaction.completedAt = new Date().toISOString();
          
          console.log(`   ✅ Forward transaction VERIFIED (${forwardVerification.confirmations} confirmations)`);
          console.log(`   🎉 BOTH TRANSACTIONS CONFIRMED - Transaction COMPLETE!`);
          console.log(`   📊 Summary:`);
          console.log(`      - Escrow TX: ${escrowVerification.confirmations} confirmations`);
          console.log(`      - Forward TX: ${forwardVerification.confirmations} confirmations`);
          console.log(`      - Amount forwarded: ${transaction.forwardedAmount} ETH`);
          console.log(`      - Fee collected: ${transaction.feeKept} ETH`);
          
          // ===================================================
          // ONLY DELETE AFTER BOTH TRANSACTIONS ARE VERIFIED!
          // ===================================================
          setTimeout(() => {
            const index = transactions.findIndex(tx => tx.id === txId);
            if (index > -1) {
              transactions.splice(index, 1);
              console.log(`🗑️ AUTO-DELETED completed transaction: ${txId}`);
              console.log(`   ✅ Both escrow and forward transactions were verified before deletion`);
            }
          }, 60000); // Delete after 60 seconds
        } else {
          console.log(`   ⏳ Forward transaction still pending (${forwardVerification.confirmations}/${CONFIG.VERIFICATION_CONFIRMATIONS} confirmations)`);
        }

        // If forward transaction failed
        if (forwardVerification.status === 'failed') {
          transaction.status = 'failed';
          transaction.error = 'Forward transaction failed on blockchain';
          transaction.failedAt = new Date().toISOString();
          console.log(`   ❌ Forward transaction FAILED on blockchain`);
        }
      }

      // Return response with both verification statuses
      res.status(200).json({
        success: true,
        transaction,
        verifications: {
          escrow: escrowVerification,
          forward: forwardVerification
        }
      });

    } catch (error) {
      console.error('❌ Error processing transaction:', error);
      res.status(500).json({ 
        error: 'Failed to process transaction',
        details: error.message 
      });
    }
  } else {
    res.status(405).json({ error: 'Method not allowed' });
  }
};
