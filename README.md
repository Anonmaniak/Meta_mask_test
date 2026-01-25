# Secure Payment Gateway

**Privacy-first Ethereum payment system with automated Python backend**

---

## 🚨 IMPORTANT: Branch Structure

This repository uses **separate branches** for frontend and backend:

### 🌐 Frontend Branch
**Branch:** `frontend`  
**Deploy to:** Vercel  
**Contains:**
- `index.html` - Main user interface
- `admin.html` - Admin dashboard
- Configuration for MetaMask integration

**View:** [Frontend Branch](https://github.com/Anonmaniak/Meta_mask_test/tree/frontend)

---

### 🐍 Backend Branch
**Branch:** `backend`  
**Deploy to:** Render (Web Service + Background Worker)  
**Contains:**
- `backend/app.py` - Flask REST API
- `backend/transaction_monitor.py` - Automated transaction processor
- `backend/requirements.txt` - Python dependencies
- Complete deployment documentation

**View:** [Backend Branch](https://github.com/Anonmaniak/Meta_mask_test/tree/backend)

---

## 🚀 Quick Start

### 1. Deploy Backend (Render)

```bash
# Go to dashboard.render.com
# Create Web Service:
  - Repository: this repo
  - Branch: backend
  - Root Directory: backend
  - Build Command: pip install -r requirements.txt
  - Start Command: python app.py

# Create Background Worker:
  - Repository: this repo
  - Branch: backend
  - Root Directory: backend
  - Build Command: pip install -r requirements.txt
  - Start Command: python transaction_monitor.py

# Add Environment Variables to both:
  - RPC_URL=https://eth-sepolia.g.alchemy.com/v2/YOUR_KEY
  - ADMIN_PRIVATE_KEY=your_escrow_wallet_private_key
  - FRONTEND_URL=https://your-app.vercel.app
```

### 2. Deploy Frontend (Vercel)

```bash
# Go to vercel.com
# Import this repository
# Settings:
  - Branch: frontend
  - Root Directory: ./
  - Framework Preset: Other

# Before deploying, update index.html (line ~397):
const CONFIG = {
    ESCROW_WALLET: '0xYourEscrowWalletAddress',
    BACKEND_URL: 'https://your-backend.onrender.com/api'
};
```

---

## 📚 Documentation

- **Backend Setup Guide:** [backend/README.md](https://github.com/Anonmaniak/Meta_mask_test/blob/backend/backend/README.md)
- **Complete Deployment Guide:** [backend/DEPLOYMENT.md](https://github.com/Anonmaniak/Meta_mask_test/blob/backend/backend/DEPLOYMENT.md)
- **Frontend Documentation:** [README.md (frontend)](https://github.com/Anonmaniak/Meta_mask_test/blob/frontend/README.md)

---

## 🔄 How It Works

```
1. User sends ETH → Escrow Wallet (via MetaMask)
   ↓
2. Frontend saves transaction to Backend API
   ↓
3. Python Background Worker detects new transaction
   ↓
4. Worker verifies escrow TX (3+ confirmations)
   ↓
5. Worker AUTO-FORWARDS to destination (minus 1% fee) ✨
   ↓
6. Worker verifies forward TX (3+ confirmations)
   ↓
7. Worker deletes transaction record (after 60s)
```

**Key Feature:** User only approves **ONE** MetaMask transaction. The second transaction is sent automatically by the Python backend using the escrow wallet's private key!

---

## ✨ Features

- ✅ **Automated Processing** - Python background worker handles everything
- ✅ **Single User Transaction** - User only approves one MetaMask payment
- ✅ **Privacy Protection** - Destination never sees sender's address
- ✅ **Automatic Fee Deduction** - 1% fee taken during forwarding
- ✅ **Full Verification** - 3+ confirmations for both transactions
- ✅ **Auto-Cleanup** - Records deleted 60s after completion
- ✅ **24/7 Monitoring** - Background worker runs continuously
- ✅ **Free Hosting** - Vercel (frontend) + Render (backend)

---

## 📊 Project Structure

```
Meta_mask_test/
├── main (you are here)
│   └── README.md (this file)
│
├── frontend (branch)
│   ├── index.html
│   ├── admin.html
│   └── README.md
│
└── backend (branch)
    └── backend/
        ├── app.py
        ├── transaction_monitor.py
        ├── requirements.txt
        ├── .env.example
        ├── README.md
        ├── DEPLOYMENT.md
        └── render.yaml
```

---

## 🔒 Security

- ⚠️ Use a **dedicated escrow wallet** (not your main wallet)
- ⚠️ Store private key **only in Render environment variables**
- ⚠️ Never commit `.env` files to Git
- ⚠️ Test on Sepolia testnet first
- ✅ All sensitive data in environment variables
- ✅ HTTPS enforced (Vercel + Render default)

---

## 🐛 Troubleshooting

### Backend not responding?
- Render free tier sleeps after 15 min inactivity
- First request may take 30-60 seconds to wake up

### Transactions stuck?
- Check Render Background Worker logs
- Verify escrow wallet has ETH for gas
- Check blockchain confirmations manually

### Frontend can't connect?
- Verify `BACKEND_URL` in index.html
- Check CORS settings (should be enabled)
- Test backend health: `https://your-backend.onrender.com/api/health`

---

## 📞 Support

1. Check the [Deployment Guide](https://github.com/Anonmaniak/Meta_mask_test/blob/backend/backend/DEPLOYMENT.md)
2. Review Render logs (Web Service + Background Worker)
3. Check browser console for errors
4. Open a GitHub issue with error details

---

## 📝 License

MIT

---

## 🚀 Get Started

1. **Read the [Deployment Guide](https://github.com/Anonmaniak/Meta_mask_test/blob/backend/backend/DEPLOYMENT.md)**
2. Deploy backend to Render (Web Service + Background Worker)
3. Deploy frontend to Vercel
4. Test on Sepolia testnet
5. Monitor Render logs
6. Go live on mainnet!

**Good luck!** 🎉
