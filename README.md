# Secure Payment Backend (Python)

Automated blockchain transaction monitoring and forwarding system.

## ✨ Features

- ✅ Automatic transaction monitoring
- ✅ Blockchain verification (3+ confirmations)
- ✅ Auto-forwarding to destination (minus 1% fee)
- ✅ Background worker for hands-free operation
- ✅ Transaction state persistence
- ✅ Auto-cleanup of completed transactions

## 🏛️ Architecture

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

## 🚀 Quick Deploy to Render

### Web Service (API)
```
Name: secure-payment-api
Branch: backend
Build Command: pip install -r requirements.txt
Start Command: python app.py
```

### Background Worker (Monitor)
```
Name: transaction-monitor
Branch: backend
Build Command: pip install -r requirements.txt
Start Command: python transaction_monitor.py
```

### Environment Variables (Both Services)
```
RPC_URL=https://eth-sepolia.g.alchemy.com/v2/YOUR_KEY
ADMIN_PRIVATE_KEY=your_private_key_without_0x
FRONTEND_URL=https://your-app.vercel.app
VERIFICATION_CONFIRMATIONS=3
FEE_PERCENTAGE=1
POLL_INTERVAL=30
```

## 📚 API Endpoints

- `GET /api/health` - Health check
- `POST /api/transaction` - Create transaction
- `POST /api/verify` - Get transaction status
- `GET /api/transactions` - List all (admin)

## 🔄 Transaction Lifecycle

1. **pending** → User sends to escrow
2. **verified** → Escrow TX has 3+ confirmations
3. **forwarding_pending** → Forward TX sent, waiting confirmations
4. **completed** → Forward TX has 3+ confirmations
5. **deleted** → Auto-deleted 60s after completion

## 🐛 Troubleshooting

**Backend won't start:**
- Check `RPC_URL` is valid
- Verify `ADMIN_PRIVATE_KEY` is set (64 chars, no 0x)
- Ensure escrow wallet has ETH for gas

**Transactions stuck:**
- Check Background Worker logs
- Verify blockchain confirmations manually
- Check escrow wallet balance

**Forward fails:**
- Ensure escrow wallet has ETH
- Check destination address is valid
- View worker logs for exact error

## 🔒 Security

- ⚠️ Use dedicated escrow wallet (not main wallet)
- ⚠️ Store private key in environment variables only
- ⚠️ Never commit `.env` to Git
- ✅ Monitor wallet balance regularly
- ✅ Test on testnet first

## 📝 License

MIT
