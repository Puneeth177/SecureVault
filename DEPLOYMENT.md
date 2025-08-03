# SecureVault Deployment Guide

## Deploying to Render

### Prerequisites
1. MongoDB Atlas account (free tier available)
2. GitHub repository with your code
3. Render account

### Step 1: Set up MongoDB Atlas

1. Go to [MongoDB Atlas](https://www.mongodb.com/atlas)
2. Create a free cluster
3. Create a database user:
   - Go to Database Access
   - Add New Database User
   - Choose password authentication
   - Save username and password
4. Configure Network Access:
   - Go to Network Access
   - Add IP Address: `0.0.0.0/0` (allow access from anywhere)
5. Get connection string:
   - Go to Clusters → Connect → Connect your application
   - Copy the connection string (looks like: `mongodb+srv://username:password@cluster.mongodb.net/`)

### Step 2: Configure Render Environment Variables

In your Render service dashboard, add these environment variables:

**Required Variables:**
```
MONGODB_URI=mongodb+srv://your-username:your-password@your-cluster.mongodb.net/securevault
JWT_SECRET=your-super-secure-jwt-secret-key-minimum-32-characters
ENCRYPTION_KEY=your-32-character-encryption-key-here
NODE_ENV=production
PORT=10000
```

**Optional Variables:**
```
ADMIN_PASSWORD=your-secure-admin-password
RATE_LIMIT_WINDOW_MS=900000
RATE_LIMIT_MAX_REQUESTS=100
SESSION_TIMEOUT_HOURS=24
CORS_ORIGIN=https://your-app-name.onrender.com
```

### Step 3: Deploy

1. Connect your GitHub repository to Render
2. Set build command: `npm install`
3. Set start command: `npm start`
4. Deploy!

### Troubleshooting

**MongoDB Connection Issues:**
- Verify your MongoDB Atlas connection string
- Ensure your database user has read/write permissions
- Check that Network Access allows connections from anywhere (0.0.0.0/0)
- Make sure you've replaced `<password>` in the connection string with your actual password

**CORS Issues:**
- Set `CORS_ORIGIN` to your Render app URL
- The app will automatically detect `RENDER_EXTERNAL_URL` if available

**Environment Variables:**
- Never commit `.env` file to GitHub
- Set all environment variables in Render dashboard
- Use strong, unique values for JWT_SECRET and ENCRYPTION_KEY

### Security Notes

1. **JWT_SECRET**: Should be at least 32 characters long and completely random
2. **ENCRYPTION_KEY**: Must be exactly 32 characters for AES-256 encryption
3. **ADMIN_PASSWORD**: Use a strong password with mixed case, numbers, and symbols
4. **MongoDB**: Enable authentication and use strong passwords
5. **CORS**: Only allow your actual domain in production

### Example MongoDB Atlas Connection String
```
mongodb+srv://myuser:mypassword@cluster0.abc123.mongodb.net/securevault?retryWrites=true&w=majority
```

Replace:
- `myuser` with your database username
- `mypassword` with your database password
- `cluster0.abc123.mongodb.net` with your actual cluster URL
- `securevault` with your preferred database name