// Vercel Serverless Function - Get Transactions by Address

// Shared in-memory storage
let transactions = [];

module.exports = async (req, res) => {
  // Enable CORS
  res.setHeader('Access-Control-Allow-Credentials', true);
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'X-CSRF-Token, X-Requested-With, Accept, Accept-Version, Content-Length, Content-MD5, Content-Type, Date, X-Api-Version');

  if (req.method === 'OPTIONS') {
    res.status(200).end();
    return;
  }

  if (req.method === 'GET') {
    try {
      const { address } = req.query;

      if (!address) {
        return res.status(400).json({ 
          error: 'Address parameter is required' 
        });
      }

      // Filter transactions by sender address
      const userTransactions = transactions.filter(
        tx => tx.senderAddress && tx.senderAddress.toLowerCase() === address.toLowerCase()
      );

      res.status(200).json({ 
        success: true,
        count: userTransactions.length,
        transactions: userTransactions 
      });

    } catch (error) {
      console.error('Error fetching transactions:', error);
      res.status(500).json({ 
        error: 'Failed to fetch transactions',
        details: error.message 
      });
    }
  } else {
    res.status(405).json({ error: 'Method not allowed' });
  }
};
