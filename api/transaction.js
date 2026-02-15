// Vercel Serverless Function - Save Transaction
const { ethers } = require('ethers');
const store = require('./_store');

module.exports = async (req, res) => {
  // Enable CORS
  res.setHeader('Access-Control-Allow-Credentials', true);
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,OPTIONS,PATCH,DELETE,POST,PUT');
  res.setHeader('Access-Control-Allow-Headers', 'X-CSRF-Token, X-Requested-With, Accept, Accept-Version, Content-Length, Content-MD5, Content-Type, Date, X-Api-Version, X-Client-Token');

  if (req.method === 'OPTIONS') {
    res.status(200).end();
    return;
  }

  if (req.method === 'POST') {
    try {
      const data = req.body;

      // Map frontend fields to backend format
      const transaction = {
        // Frontend sends: tx_hash, sender, destination, amount_wei, recipient_amount_wei, forward_gas_buffer_wei
        escrowTxHash: data.tx_hash,
        senderAddress: data.sender,
        destinationAddress: data.destination,
        amountWei: data.amount_wei,                    // Total sent (includes all fees)
        recipientAmountWei: data.recipient_amount_wei, // What recipient should get
        forwardGasBufferWei: data.forward_gas_buffer_wei || '0',
        
        // Server-side fields
        id: `tx_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`,
        receivedAt: new Date().toISOString(),
        status: 'pending'
      };

      // Validate required fields
      if (!transaction.escrowTxHash || !transaction.senderAddress || 
          !transaction.destinationAddress || !transaction.recipientAmountWei) {
        return res.status(400).json({ 
          error: 'Missing required transaction fields',
          required: ['tx_hash', 'sender', 'destination', 'recipient_amount_wei'],
          received: Object.keys(data)
        });
      }

      // Generate client token for secure status checks
      const clientToken = `token_${Date.now()}_${Math.random().toString(36).substr(2, 16)}`;
      transaction.clientToken = clientToken;

      // Add to shared storage
      store.addTransaction(transaction);

      console.log('✅ Transaction saved:', transaction.id);
      console.log('   Sender:', transaction.senderAddress);
      console.log('   Destination:', transaction.destinationAddress);
      console.log('   Recipient Amount:', transaction.recipientAmountWei, 'wei');
      console.log('   Escrow TX:', transaction.escrowTxHash);

      res.status(200).json({ 
        success: true, 
        transaction_id: transaction.id,
        client_token: clientToken,
        message: 'Transaction saved and queued for verification'
      });

    } catch (error) {
      console.error('Error saving transaction:', error);
      res.status(500).json({ 
        error: 'Failed to save transaction',
        details: error.message 
      });
    }
  } else if (req.method === 'GET') {
    // GET /:txHash - Get transaction status by escrow tx hash
    try {
      const txHash = req.url.split('/').pop()?.split('?')[0];
      const clientToken = req.headers['x-client-token'];

      if (!txHash || txHash === 'transaction') {
        return res.status(400).json({ error: 'Transaction hash required' });
      }

      const transaction = store.findTransaction({ escrowTxHash: txHash });

      if (!transaction) {
        // Return 404 if not found (frontend treats this as complete/deleted)
        return res.status(404).json({ error: 'Transaction not found or already completed' });
      }

      // Verify client token
      if (transaction.clientToken && transaction.clientToken !== clientToken) {
        return res.status(403).json({ error: 'Invalid client token' });
      }

      // Return transaction without sensitive server fields
      const safeTransaction = {
        id: transaction.id,
        status: transaction.status,
        escrowTxHash: transaction.escrowTxHash,
        forwardTxHash: transaction.forwardTxHash,
        destinationAddress: transaction.destinationAddress,
        recipientAmountWei: transaction.recipientAmountWei,
        error: transaction.error,
        receivedAt: transaction.receivedAt,
        verifiedAt: transaction.verifiedAt,
        forwardInitiatedAt: transaction.forwardInitiatedAt,
        completedAt: transaction.completedAt
      };

      res.status(200).json(safeTransaction);

    } catch (error) {
      console.error('Error fetching transaction:', error);
      res.status(500).json({ 
        error: 'Failed to fetch transaction',
        details: error.message 
      });
    }
  } else {
    res.status(405).json({ error: 'Method not allowed' });
  }
};
