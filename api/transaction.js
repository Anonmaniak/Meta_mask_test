// Vercel Serverless Function - Save Transaction
const { ethers } = require('ethers');

// In-memory storage (auto-clears on cold start)
let transactions = [];

module.exports = async (req, res) => {
  // Enable CORS
  res.setHeader('Access-Control-Allow-Credentials', true);
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,OPTIONS,PATCH,DELETE,POST,PUT');
  res.setHeader('Access-Control-Allow-Headers', 'X-CSRF-Token, X-Requested-With, Accept, Accept-Version, Content-Length, Content-MD5, Content-Type, Date, X-Api-Version');

  if (req.method === 'OPTIONS') {
    res.status(200).end();
    return;
  }

  if (req.method === 'POST') {
    try {
      const transaction = req.body;

      // Validate required fields
      if (!transaction.senderAddress || !transaction.destinationAddress || 
          !transaction.amount || !transaction.feeTxHash || !transaction.mainTxHash) {
        return res.status(400).json({ 
          error: 'Missing required transaction fields' 
        });
      }

      // Add server-side fields
      transaction.id = `tx_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
      transaction.receivedAt = new Date().toISOString();
      transaction.status = 'pending';

      // Add to memory (temporary storage)
      transactions.unshift(transaction);

      // Keep only last 50 transactions
      if (transactions.length > 50) {
        transactions = transactions.slice(0, 50);
      }

      console.log('✅ Transaction saved temporarily:', transaction.id);

      res.status(200).json({ 
        success: true, 
        transaction,
        message: 'Transaction saved temporarily and queued for verification'
      });

    } catch (error) {
      console.error('Error saving transaction:', error);
      res.status(500).json({ 
        error: 'Failed to save transaction',
        details: error.message 
      });
    }
  } else {
    res.status(405).json({ error: 'Method not allowed' });
  }
};
