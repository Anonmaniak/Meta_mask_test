# Deployment Guide

Complete step-by-step guide to deploy your secure payment system.

## 🎯 Overview

You'll deploy:
1. **Frontend** (Vercel) - User interface
2. **Backend API** (Render Web Service) - REST API
3. **Background Worker** (Render Background Worker) - Auto-forwarding system

---

## 🔑 Prerequisites

### 1. Get Your RPC URL

**Option A: Alchemy (Recommended)**
1. Go to [alchemy.com](https://www.alchemy.com/)
2. Sign up / Log in
3. Create New App
4. Select network (e.g., "Ethereum Sepolia")
5. Copy the HTTPS URL

**Option B: Infura**
1. Go to [infura.io](https://infura.io/)
2. Sign up / Log in
3. Create New Project
4. Copy the endpoint URL

### 2. Create Escrow Wallet

**IMPORTANT: Use a NEW wallet, NOT your main wallet!**

1. Open MetaMask
2. Click account icon → "Add account or hardware wallet" → "Add a new account"
3. Name it "Escrow Wallet"
4. Copy the address (0x...)
5. Export private key:
   - Click ⋮ menu → Account details
   - Click "Show private key"
   - Enter password
   - Copy private key (without 0x prefix)
6. Send small amount of ETH for gas (~$5-10)

**Security:**
- ⚠️ Never share this private key
- ⚠️ Keep minimal balance (just for gas)
- ⚠️ Don't use for personal funds

---

## 🚀 Part 1: Deploy Backend (Render)

### Step 1: Create Render Account

1. Go to [render.com](https://render.com)
2. Sign up with GitHub
3. Authorize Render to access your repos

### Step 2: Deploy API Web Service

1. Click "New +" → "Web Service"
2. Select your repository
3. Configure:
   ```
   Name: secure-payment-api
   Region: Oregon (US West)
   Branch: backend
   Root Directory: backend
   Runtime: Python 3
   Build Command: pip install -r requirements.txt
   Start Command: python app.py
   Instance Type: Free
   ```

4. Add Environment Variables:
   ```
   RPC_URL = https://eth-sepolia.g.alchemy.com/v2/YOUR_API_KEY
   ADMIN_PRIVATE_KEY = your_private_key_without_0x_prefix
   FRONTEND_URL = https://your-app.vercel.app
   PORT = 10000
   ```

5. Click "Create Web Service"

6. Wait for deployment (~2 minutes)

7. **Copy your API URL** (e.g., `https://secure-payment-api.onrender.com`)

### Step 3: Deploy Background Worker

1. Click "New +" → "Background Worker"
2. Select same repository
3. Configure:
   ```
   Name: transaction-monitor
   Region: Oregon (US West)
   Branch: backend
   Root Directory: backend
   Runtime: Python 3
   Build Command: pip install -r requirements.txt
   Start Command: python transaction_monitor.py
   Instance Type: Free
   ```

4. Add same Environment Variables:
   ```
   RPC_URL = https://eth-sepolia.g.alchemy.com/v2/YOUR_API_KEY
   ADMIN_PRIVATE_KEY = your_private_key_without_0x_prefix
   VERIFICATION_CONFIRMATIONS = 3
   FEE_PERCENTAGE = 1
   POLL_INTERVAL = 30
   ```

5. Click "Create Background Worker"

6. Check logs - you should see:
   ```
   ✅ Connected to blockchain
   ✅ Escrow wallet: 0x...
   🤖 Transaction Monitor Started
   ⏳ Monitoring for transactions...
   ```

---

## 🌐 Part 2: Deploy Frontend (Vercel)

### Step 1: Update Frontend Config

1. Go to your repo on GitHub
2. Switch to `frontend` branch
3. Edit `index.html`
4. Find line ~397 (CONFIG object):
   ```javascript
   const CONFIG = {
       ESCROW_WALLET: '0x7e4692aaa29fe7632fa0bdc8effd25cc70867d33', // UPDATE THIS
       FEE_PERCENTAGE: 1,
       BACKEND_URL: 'https://your-backend-url.onrender.com/api' // UPDATE THIS
   };
   ```
5. Replace:
   - `ESCROW_WALLET` with your escrow wallet address
   - `BACKEND_URL` with your Render API URL + `/api`
6. Commit changes

### Step 2: Deploy to Vercel

1. Go to [vercel.com](https://vercel.com)
2. Sign up with GitHub
3. Click "Add New..." → "Project"
4. Import your repository
5. Configure:
   ```
   Framework Preset: Other
   Root Directory: ./
   Build Command: (leave empty)
   Output Directory: (leave empty)
   Branch: frontend
   ```
6. Click "Deploy"
7. Wait (~1 minute)
8. **Copy your Vercel URL** (e.g., `https://your-app.vercel.app`)

### Step 3: Update Backend FRONTEND_URL

1. Go back to Render Dashboard
2. Open your Web Service
3. Go to "Environment" tab
4. Update `FRONTEND_URL` to your Vercel URL
5. Click "Save Changes"
6. Service will auto-redeploy

---

## ✅ Part 3: Test Your System

### 1. Check Backend Health

Visit: `https://your-backend.onrender.com/api/health`

Should see:
```json
{
  "status": "healthy",
  "timestamp": "...",
  "service": "secure-payment-backend"
}
```

### 2. Check Frontend

1. Visit your Vercel URL
2. Should see "Secure Payment Gateway" page
3. Click "Connect MetaMask"
4. Approve connection
5. Should see your wallet info

### 3. Test Full Flow (Testnet)

1. Get testnet ETH:
   - For Sepolia: [sepoliafaucet.com](https://sepoliafaucet.com)
   - Or [faucet.quicknode.com](https://faucet.quicknode.com)

2. On your app:
   - Enter a destination address (use another wallet you control)
   - Enter amount (e.g., 0.001 ETH)
   - Click "Send Secure Payment"
   - Approve in MetaMask

3. Watch the progress:
   - Step 1: ✅ Sent to escrow
   - Step 2: ⏳ Backend verifying (wait ~1 minute)
   - Step 3: ✅ Backend forwarding (check Render logs)
   - Step 4: ⏳ Verifying forward (wait ~1 minute)
   - Step 5: 🎉 Complete!

4. Verify on blockchain:
   - Check your destination wallet
   - Should receive ~99% of amount (minus 1% fee)

---

## 📊 Monitoring

### Render Logs

**Web Service Logs:**
- API requests
- Transaction creation
- Errors

**Background Worker Logs:**
- Transaction processing
- Blockchain verifications
- Auto-forwarding
- Auto-deletion

Key messages to look for:
```
✅ Transaction saved: xyz...
🔍 Processing: xyz... (status: pending)
✅ Escrow VERIFIED (3 confirmations)
🚀 Initiating forward to destination...
✅ Forward transaction sent: abc...
🎉 BOTH TRANSACTIONS VERIFIED - COMPLETE!
🗑️ AUTO-DELETED completed transaction
```

### Check Transactions

Visit: `https://your-backend.onrender.com/api/transactions`

See all active transactions (completed ones auto-delete after 60s)

---

## 🐛 Troubleshooting

### Backend won't start

**Error: "Failed to connect to blockchain"**
- Check `RPC_URL` is correct
- Verify API key is valid
- Test RPC URL in browser

**Error: "Escrow wallet not configured"**
- Check `ADMIN_PRIVATE_KEY` is set
- Remove `0x` prefix if present
- Verify private key is 64 characters

### Transactions stuck

**Stuck in "pending"**
- Check blockchain explorer (sepolia.etherscan.io)
- Verify transaction has confirmations
- Check if transaction failed
- Look at Background Worker logs

**Stuck in "verified" (won't forward)**
- Check escrow wallet has ETH for gas
- Check Background Worker is running
- Look for errors in worker logs

**Stuck in "forwarding_pending"**
- Check forward transaction on blockchain
- Verify it has confirmations
- Check worker is still monitoring

### Frontend issues

**"Backend not configured" error**
- Verify `BACKEND_URL` in index.html
- Should end with `/api`
- Test URL in browser (health endpoint)

**CORS errors in console**
- Check `FRONTEND_URL` in Render
- Should match your Vercel URL exactly

**MetaMask not connecting**
- Try different browser
- Clear cache
- Reinstall MetaMask extension

---

## 🔒 Security Checklist

- [ ] Using dedicated escrow wallet (not main wallet)
- [ ] Private key stored in Render env vars (not in code)
- [ ] `.env` file in `.gitignore`
- [ ] Escrow wallet has minimal balance
- [ ] Frontend uses HTTPS (Vercel default)
- [ ] Backend uses HTTPS (Render default)
- [ ] Monitoring backend logs regularly
- [ ] Testing on testnet first

---

## 🚀 Going to Mainnet

### 1. Switch Network

Update `RPC_URL` to mainnet:
```
Alchemy: https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY
Infura: https://mainnet.infura.io/v3/YOUR_KEY
```

### 2. Fund Escrow Wallet

Send ETH for gas fees (~$20-50 worth)

### 3. Update Frontend

No changes needed (MetaMask will use mainnet)

### 4. Test Small Amount First

Send 0.001 ETH first to verify everything works

### 5. Monitor Closely

Check logs frequently for first few days

---

## 💰 Cost Breakdown

### Render (Free Tier)
- Web Service: Free (750 hours/month)
- Background Worker: Free (750 hours/month)
- Total: **$0/month**

*Note: Free tier sleeps after 15 min inactivity*

### Vercel (Free Tier)
- Static hosting: Free
- Bandwidth: 100GB/month
- Total: **$0/month**

### Blockchain Costs
- Gas fees: ~$1-5 per forward transaction
- Your 1% fee covers this + profit

---

## 🎓 Next Steps

1. Test thoroughly on testnet
2. Monitor logs for issues
3. Add analytics/monitoring
4. Consider upgrading to paid plans for production
5. Add rate limiting
6. Add admin dashboard
7. Set up alerts for errors

---

## 📞 Support

If stuck:
1. Check Render logs
2. Check browser console
3. Test each component separately
4. Open GitHub issue with error logs

Good luck! 🚀
