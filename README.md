# Secure Payment Gateway - Frontend

User interface for the secure payment system with MetaMask integration.

## 🚀 Deploy to Render

### Quick Deploy

1. Go to [dashboard.render.com](https://dashboard.render.com)
2. Click **New +** → **Static Site**
3. Connect your GitHub repository: **Meta_mask_test**
4. Configure:
   ```
   Name: secure-payment-frontend
   Branch: frontend
   Root Directory: ./
   Build Command: (leave empty)
   Publish Directory: ./
   ```
5. Click **"Create Static Site"**
6. Copy your frontend URL: `https://secure-payment-frontend.onrender.com`

### Configuration

Before deploying, update `index.html` (line ~397):

```javascript
const CONFIG = {
    ESCROW_WALLET: '0xYourEscrowWalletAddress', // Your escrow wallet
    FEE_PERCENTAGE: 1,
    BACKEND_URL: 'https://your-backend.onrender.com/api' // Your backend URL
};
```

### Update Backend CORS

After deploying frontend:
1. Go to your **Backend Web Service** on Render
2. Update environment variable:
   ```
   FRONTEND_URL=https://secure-payment-frontend.onrender.com
   ```
3. Save and redeploy

## 📚 Files

- `index.html` - Main payment interface
- `admin.html` - Admin dashboard for monitoring
- `render.yaml` - Render deployment config

## 🔧 Local Development

Simply open `index.html` in your browser:
```bash
open index.html
# or
python -m http.server 8000
# then visit http://localhost:8000
```

## ✨ Features

- ✅ MetaMask integration
- ✅ Real-time transaction status
- ✅ Automatic backend communication
- ✅ Progress tracking
- ✅ Blockchain verification display

## 🔒 Security

- All sensitive operations on backend
- Frontend only handles UI and MetaMask
- No private keys in frontend code
- HTTPS enforced by Render

## 📝 License

MIT
