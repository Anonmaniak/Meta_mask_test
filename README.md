# Secure Payment Gateway

Privacy-first Ethereum payment system with automated backend processing.

## 🚀 Features

- ✅ MetaMask integration (frontend)
- ✅ Automated transaction monitoring (backend)
- ✅ Auto-forwarding with fee deduction
- ✅ Full blockchain verification
- ✅ Privacy protection
- ✅ Auto-cleanup of transaction records

## 📁 Project Structure

```
├── frontend/ (branch: frontend)
│   ├── index.html          # Main user interface
│   └── admin.html          # Admin dashboard
│
└── backend/ (branch: backend)
    ├── app.py              # Flask API server
    ├── transaction_monitor.py  # Background worker
    ├── requirements.txt    # Python dependencies
    ├── .env.example        # Environment template
    └── README.md          # Backend documentation
```

## 🔧 Setup

### Frontend (Vercel)

1. Fork this repository
2. Go to [Vercel](https://vercel.com)
3. New Project → Import your fork
4. Select `frontend` branch
5. Deploy
6. Update `BACKEND_URL` in `index.html` line 397 with your Render backend URL

### Backend (Render)

See [backend/README.md](backend/README.md) for complete setup instructions.

**Quick start:**

1. Go to [Render Dashboard](https://dashboard.render.com/)
2. Create Web Service:
   - Branch: `backend`
   - Build: `pip install -r requirements.txt`
   - Start: `python app.py`
   - Root: `backend`
3. Create Background Worker:
   - Branch: `backend`
   - Build: `pip install -r requirements.txt`
   - Start: `python transaction_monitor.py`
   - Root: `backend`
4. Add environment variables to both:
   - `RPC_URL`
   - `ADMIN_PRIVATE_KEY`
   - `FRONTEND_URL`

## 🔐 Environment Variables

### Backend (.env)

```env
RPC_URL=https://eth-sepolia.g.alchemy.com/v2/YOUR_KEY
ADMIN_PRIVATE_KEY=your_escrow_wallet_private_key
FRONTEND_URL=https://your-frontend.vercel.app
VERIFICATION_CONFIRMATIONS=3
FEE_PERCENTAGE=1
POLL_INTERVAL=30
```

### Frontend (index.html)

```javascript
const CONFIG = {
    ESCROW_WALLET: '0x...', // Your escrow wallet address
    FEE_PERCENTAGE: 1,
    BACKEND_URL: 'https://your-backend.onrender.com/api'
};
```

## 🔄 Transaction Flow

1. **User Action:** Connects MetaMask, enters destination & amount
2. **User → Escrow:** MetaMask sends funds to escrow wallet
3. **Backend Monitors:** Background worker detects new transaction
4. **Backend Verifies:** Waits for 3+ blockchain confirmations
5. **Backend Forwards:** Auto-sends to destination (minus 1% fee)
6. **Backend Verifies:** Confirms forward transaction (3+ confirmations)
7. **Auto-Cleanup:** Deletes transaction records after 60s

## 🛡️ Security

- ⚠️ Never commit `.env` files
- ⚠️ Never share private keys
- ✅ Use dedicated escrow wallet (not main wallet)
- ✅ Keep escrow wallet balance minimal (just enough for gas)
- ✅ Monitor backend logs regularly
- ✅ Use HTTPS only in production

## 📊 Monitoring

Check backend logs on Render:
- Web Service logs → API requests
- Background Worker logs → Transaction processing

Key log messages:
- `✅ Escrow VERIFIED` - Deposit confirmed
- `✅ Forward transaction sent` - Payment forwarded
- `🎉 BOTH TRANSACTIONS VERIFIED` - Complete!
- `🗑️ AUTO-DELETED` - Records cleaned

## 🐛 Troubleshooting

**"Backend not configured" error:**
- Update `BACKEND_URL` in frontend `index.html`

**Transactions stuck in pending:**
- Check blockchain confirmations manually
- Verify backend worker is running
- Check RPC_URL is accessible

**Forward fails:**
- Ensure escrow wallet has ETH for gas
- Check ADMIN_PRIVATE_KEY is correct
- Verify destination address is valid

## 📄 License

MIT

## 🤝 Contributing

Feel free to open issues or submit PRs!
