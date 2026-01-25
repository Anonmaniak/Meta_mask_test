# Secure Payment Backend (Python)

Automated blockchain transaction monitoring and forwarding system.

## Features

- ✅ Automatic transaction monitoring
- ✅ Blockchain verification (3+ confirmations)
- ✅ Auto-forwarding to destination (minus 1% fee)
- ✅ Background worker for hands-free operation
- ✅ Transaction state persistence
- ✅ Auto-cleanup of completed transactions

## Architecture

```
User → MetaMask → Escrow Wallet
         ↓
    Backend API (Flask)
         ↓
  Transaction Monitor (Background Worker)
         ↓
    Verify Escrow TX (3+ confirmations)
         ↓
    Auto-forward to Destination
         ↓
    Verify Forward TX (3+ confirmations)
         ↓
    Mark Complete & Delete
```

## Setup

### 1. Install Dependencies

```bash
cd backend
pip install -r requirements.txt
```

### 2. Configure Environment

```bash
cp .env.example .env
```

Edit `.env` and set:

- `RPC_URL`: Your blockchain RPC endpoint (Alchemy/Infura)
- `ADMIN_PRIVATE_KEY`: Private key of your escrow wallet
- `FRONTEND_URL`: Your frontend URL

**⚠️ SECURITY:**
- Never commit `.env` to git
- Never share your private key
- Use a dedicated escrow wallet (not your main wallet)

### 3. Run Locally

**Terminal 1 - API Server:**
```bash
python app.py
```

**Terminal 2 - Transaction Monitor:**
```bash
python transaction_monitor.py
```

## Deploy to Render

### Option 1: Web Service + Background Worker (Recommended)

#### A. Create Web Service
1. Go to [Render Dashboard](https://dashboard.render.com/)
2. New → Web Service
3. Connect your GitHub repo
4. Select `backend` branch
5. Configure:
   - **Build Command:** `pip install -r requirements.txt`
   - **Start Command:** `python app.py`
   - **Root Directory:** `backend`
6. Add Environment Variables:
   - `RPC_URL`
   - `ADMIN_PRIVATE_KEY`
   - `FRONTEND_URL`
   - `PORT=10000`

#### B. Create Background Worker
1. New → Background Worker
2. Connect same repo
3. Select `backend` branch
4. Configure:
   - **Build Command:** `pip install -r requirements.txt`
   - **Start Command:** `python transaction_monitor.py`
   - **Root Directory:** `backend`
5. Add same Environment Variables as above

### Option 2: Cron Job (Alternative)

If you prefer scheduled monitoring:

1. New → Cron Job
2. Schedule: `*/1 * * * *` (every minute)
3. Command: `python transaction_monitor.py --once`

## API Endpoints

### `POST /api/transaction`
Create a new transaction

```json
{
  "senderAddress": "0x...",
  "destinationAddress": "0x...",
  "amount": 0.1,
  "escrowTxHash": "0x...",
  "escrowWallet": "0x...",
  "chainId": "0xaa36a7"
}
```

### `POST /api/verify`
Get transaction status

```json
{
  "txId": "uuid-here"
}
```

### `GET /api/transactions`
List all transactions (admin)

### `GET /api/health`
Health check

## Transaction Lifecycle

1. **pending** → User sends to escrow
2. **verified** → Escrow TX has 3+ confirmations
3. **forwarding_pending** → Forward TX sent, waiting for confirmations
4. **completed** → Forward TX has 3+ confirmations
5. **deleted** → Auto-deleted 60s after completion

## Monitoring

The background worker automatically:

- Polls every 30 seconds (configurable via `POLL_INTERVAL`)
- Verifies escrow transactions
- Forwards when verified
- Verifies forward transactions
- Deletes completed transactions after 60s
- Deletes failed transactions after 5 minutes

## Troubleshooting

### "Failed to connect to blockchain RPC"
- Check your `RPC_URL` is correct
- Verify your API key is valid
- Test with: `curl https://eth-sepolia.g.alchemy.com/v2/YOUR_KEY`

### "Escrow wallet not configured"
- Set `ADMIN_PRIVATE_KEY` in `.env`
- Make sure it's the private key (not address)
- Don't include `0x` prefix

### Transactions stuck in "pending"
- Check blockchain confirmations manually
- Verify `VERIFICATION_CONFIRMATIONS` is appropriate for your network
- Check if transaction failed on blockchain

### Forward transaction fails
- Ensure escrow wallet has enough ETH for gas
- Check gas prices on the network
- Verify destination address is valid

## Security Best Practices

1. **Use dedicated escrow wallet** - Don't use your main wallet
2. **Monitor balance** - Keep enough ETH for gas, but not excessive amounts
3. **Rate limiting** - Consider adding rate limits to API endpoints
4. **Logging** - Monitor logs for suspicious activity
5. **Environment variables** - Never hardcode secrets
6. **HTTPS only** - Always use HTTPS in production

## Development

```bash
# Run in development mode
export FLASK_ENV=development
python app.py

# Test transaction monitor once
python -c "from transaction_monitor import *; process_all_once()"
```

## License

MIT
