const express = require('express');
const cors = require('cors');
const fs = require('fs').promises;
const path = require('path');
const { ethers } = require('ethers');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());

// Configuration
const CONFIG = {
    FEE_WALLET: '0xYourFeeWalletAddress', // CHANGE THIS
    ADMIN_WALLET: '0xYourAdminWalletAddress', // CHANGE THIS
    RPC_URL: process.env.RPC_URL || 'https://eth-mainnet.g.alchemy.com/v2/YOUR_ALCHEMY_KEY', // CHANGE THIS
    PRIVATE_KEY: process.env.ADMIN_PRIVATE_KEY, // Admin wallet private key for sending final transactions
    DATA_DIR: path.join(__dirname, 'data'),
    TRANSACTIONS_FILE: path.join(__dirname, 'data', 'transactions.json'),
    VERIFICATION_CONFIRMATIONS: 3 // Number of block confirmations required
};

// Initialize provider
const provider = new ethers.JsonRpcProvider(CONFIG.RPC_URL);
let wallet;

if (CONFIG.PRIVATE_KEY) {
    wallet = new ethers.Wallet(CONFIG.PRIVATE_KEY, provider);
    console.log('✅ Admin wallet initialized:', wallet.address);
}

// Ensure data directory exists
async function initializeDataDirectory() {
    try {
        await fs.mkdir(CONFIG.DATA_DIR, { recursive: true });
        
        // Check if transactions file exists, if not create it
        try {
            await fs.access(CONFIG.TRANSACTIONS_FILE);
        } catch {
            await fs.writeFile(CONFIG.TRANSACTIONS_FILE, JSON.stringify({ transactions: [] }, null, 2));
            console.log('✅ Transactions file created');
        }
        
        console.log('✅ Data directory initialized');
    } catch (error) {
        console.error('Error initializing data directory:', error);
    }
}

// Read transactions from JSON file
async function readTransactions() {
    try {
        const data = await fs.readFile(CONFIG.TRANSACTIONS_FILE, 'utf8');
        return JSON.parse(data);
    } catch (error) {
        console.error('Error reading transactions:', error);
        return { transactions: [] };
    }
}

// Write transactions to JSON file
async function writeTransactions(data) {
    try {
        await fs.writeFile(CONFIG.TRANSACTIONS_FILE, JSON.stringify(data, null, 2));
    } catch (error) {
        console.error('Error writing transactions:', error);
        throw error;
    }
}

// Verify transaction on blockchain
async function verifyTransaction(txHash) {
    try {
        const receipt = await provider.getTransactionReceipt(txHash);
        
        if (!receipt) {
            return { verified: false, status: 'pending' };
        }

        // Check if transaction was successful
        if (receipt.status === 0) {
            return { verified: false, status: 'failed', receipt };
        }

        // Check confirmations
        const currentBlock = await provider.getBlockNumber();
        const confirmations = currentBlock - receipt.blockNumber;

        if (confirmations >= CONFIG.VERIFICATION_CONFIRMATIONS) {
            return { verified: true, status: 'verified', confirmations, receipt };
        }

        return { verified: false, status: 'confirming', confirmations, receipt };

    } catch (error) {
        console.error('Error verifying transaction:', error);
        return { verified: false, status: 'error', error: error.message };
    }
}

// Send final transaction to destination
async function sendToDestination(transaction) {
    try {
        if (!wallet) {
            throw new Error('Admin wallet not configured');
        }

        // Convert amount to Wei
        const amountInWei = ethers.parseEther(transaction.amount.toString());

        // Create transaction
        const tx = await wallet.sendTransaction({
            to: transaction.destinationAddress,
            value: amountInWei,
            gasLimit: 21000
        });

        console.log('📤 Sent to destination:', tx.hash);

        // Wait for confirmation
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

// Background worker to verify and process transactions
async function processTransactions() {
    try {
        const data = await readTransactions();
        let updated = false;

        for (let transaction of data.transactions) {
            // Skip if already completed or failed
            if (transaction.status === 'completed' || transaction.status === 'failed') {
                continue;
            }

            // Verify fee transaction
            const feeVerification = await verifyTransaction(transaction.feeTxHash);
            
            // Verify main transaction to admin wallet
            const mainVerification = await verifyTransaction(transaction.mainTxHash);

            console.log(`Checking transaction ${transaction.mainTxHash}:`);
            console.log(`Fee TX: ${feeVerification.status}, Main TX: ${mainVerification.status}`);

            // If both transactions are verified
            if (feeVerification.verified && mainVerification.verified) {
                // Update status to verified
                if (transaction.status === 'pending') {
                    transaction.status = 'verified';
                    transaction.verifiedAt = new Date().toISOString();
                    transaction.feeVerification = feeVerification;
                    transaction.mainVerification = mainVerification;
                    updated = true;

                    console.log(`✅ Transaction verified: ${transaction.mainTxHash}`);
                }

                // Send to final destination if not already sent
                if (transaction.status === 'verified' && !transaction.finalTxHash) {
                    const result = await sendToDestination(transaction);

                    if (result.success) {
                        transaction.status = 'completed';
                        transaction.finalTxHash = result.txHash;
                        transaction.completedAt = new Date().toISOString();
                        updated = true;

                        console.log(`✅ Transaction completed: ${transaction.finalTxHash}`);
                    } else {
                        transaction.status = 'failed';
                        transaction.error = result.error;
                        transaction.failedAt = new Date().toISOString();
                        updated = true;

                        console.error(`❌ Transaction failed: ${result.error}`);
                    }
                }
            }
            // If any transaction failed
            else if (feeVerification.status === 'failed' || mainVerification.status === 'failed') {
                transaction.status = 'failed';
                transaction.error = 'One or more blockchain transactions failed';
                transaction.failedAt = new Date().toISOString();
                updated = true;
            }
        }

        if (updated) {
            await writeTransactions(data);
        }

    } catch (error) {
        console.error('Error processing transactions:', error);
    }
}

// API Routes

// Health check
app.get('/api/health', (req, res) => {
    res.json({ 
        status: 'ok', 
        timestamp: new Date().toISOString(),
        walletConfigured: !!wallet
    });
});

// Save new transaction
app.post('/api/transaction', async (req, res) => {
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

        // Read current transactions
        const data = await readTransactions();

        // Add new transaction
        data.transactions.unshift(transaction);

        // Keep only last 1000 transactions
        if (data.transactions.length > 1000) {
            data.transactions = data.transactions.slice(0, 1000);
        }

        // Save to file
        await writeTransactions(data);

        console.log('✅ New transaction saved:', transaction.id);

        res.json({ 
            success: true, 
            transaction,
            message: 'Transaction saved and queued for verification'
        });

    } catch (error) {
        console.error('Error saving transaction:', error);
        res.status(500).json({ 
            error: 'Failed to save transaction',
            details: error.message 
        });
    }
});

// Get transactions by sender address
app.get('/api/transactions/:address', async (req, res) => {
    try {
        const { address } = req.params;
        const data = await readTransactions();

        // Filter transactions by sender address
        const userTransactions = data.transactions.filter(
            tx => tx.senderAddress.toLowerCase() === address.toLowerCase()
        );

        res.json({ 
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
});

// Get all transactions (admin only - add authentication in production)
app.get('/api/admin/transactions', async (req, res) => {
    try {
        const data = await readTransactions();
        
        res.json({ 
            success: true,
            count: data.transactions.length,
            transactions: data.transactions 
        });

    } catch (error) {
        console.error('Error fetching all transactions:', error);
        res.status(500).json({ 
            error: 'Failed to fetch transactions',
            details: error.message 
        });
    }
});

// Get transaction by ID
app.get('/api/transaction/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const data = await readTransactions();

        const transaction = data.transactions.find(tx => tx.id === id);

        if (!transaction) {
            return res.status(404).json({ 
                error: 'Transaction not found' 
            });
        }

        res.json({ 
            success: true,
            transaction 
        });

    } catch (error) {
        console.error('Error fetching transaction:', error);
        res.status(500).json({ 
            error: 'Failed to fetch transaction',
            details: error.message 
        });
    }
});

// Manually trigger verification for a specific transaction
app.post('/api/verify/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const data = await readTransactions();

        const transaction = data.transactions.find(tx => tx.id === id);

        if (!transaction) {
            return res.status(404).json({ 
                error: 'Transaction not found' 
            });
        }

        // Verify transactions
        const feeVerification = await verifyTransaction(transaction.feeTxHash);
        const mainVerification = await verifyTransaction(transaction.mainTxHash);

        res.json({
            success: true,
            transaction: transaction.id,
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
});

// Get statistics
app.get('/api/stats', async (req, res) => {
    try {
        const data = await readTransactions();

        const stats = {
            total: data.transactions.length,
            pending: data.transactions.filter(tx => tx.status === 'pending').length,
            verified: data.transactions.filter(tx => tx.status === 'verified').length,
            completed: data.transactions.filter(tx => tx.status === 'completed').length,
            failed: data.transactions.filter(tx => tx.status === 'failed').length,
            totalVolume: data.transactions.reduce((sum, tx) => sum + (tx.amount || 0), 0),
            totalFees: data.transactions.reduce((sum, tx) => sum + (tx.platformFee || 0), 0)
        };

        res.json({ 
            success: true,
            stats 
        });

    } catch (error) {
        console.error('Error fetching stats:', error);
        res.status(500).json({ 
            error: 'Failed to fetch statistics',
            details: error.message 
        });
    }
});

// Start server
async function startServer() {
    await initializeDataDirectory();

    app.listen(PORT, () => {
        console.log(`🚀 Server running on port ${PORT}`);
        console.log(`📊 API endpoints:`);
        console.log(`   - POST   /api/transaction`);
        console.log(`   - GET    /api/transactions/:address`);
        console.log(`   - GET    /api/admin/transactions`);
        console.log(`   - GET    /api/transaction/:id`);
        console.log(`   - POST   /api/verify/:id`);
        console.log(`   - GET    /api/stats`);
        console.log(`   - GET    /api/health`);
    });

    // Start background worker
    setInterval(processTransactions, 30000); // Check every 30 seconds
    
    // Initial check
    setTimeout(processTransactions, 5000);
}

startServer();
