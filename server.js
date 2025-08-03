const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const compression = require('compression');
const path = require('path');
require('dotenv').config();

// Import routes
const authRoutes = require('./routes/auth');
const passwordRoutes = require('./routes/passwords');
const adminRoutes = require('./routes/admin');

// Import middleware
const { authenticateToken } = require('./middleware/auth');
const { errorHandler } = require('./middleware/errorHandler');

const app = express();
const PORT = process.env.PORT || 3000;

// Security middleware
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            scriptSrc: ["'self'"],
            imgSrc: ["'self'", "data:", "https:"],
        },
    },
}));

// Rate limiting
const limiter = rateLimit({
    windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000, // 15 minutes
    max: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS) || 100, // limit each IP to 100 requests per windowMs
    message: {
        error: 'Too many requests from this IP, please try again later.',
        retryAfter: Math.ceil((parseInt(process.env.RATE_LIMIT_WINDOW_MS) || 15 * 60 * 1000) / 1000)
    },
    standardHeaders: true,
    legacyHeaders: false,
});

app.use(limiter);

// Compression middleware
app.use(compression());

// CORS configuration
app.use(cors({
    origin: process.env.CORS_ORIGIN || 'http://localhost:3000',
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization']
}));

// Body parsing middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Serve static files
app.use(express.static(path.join(__dirname, 'public')));

// Database connection
mongoose.connect(process.env.MONGODB_URI, {
    serverSelectionTimeoutMS: 10000
})
.then(() => {
    console.log('✅ Connected to MongoDB successfully');
})
.catch((error) => {
    console.error('❌ MongoDB connection error:', error);
    process.exit(1);
});

// Health check endpoint
app.get('/api/health', (req, res) => {
    res.json({
        status: 'OK',
        timestamp: new Date().toISOString(),
        uptime: process.uptime(),
        environment: process.env.NODE_ENV || 'development'
    });
});

// API Routes
app.use('/api/auth', authRoutes);
app.use('/api/passwords', authenticateToken, passwordRoutes);
app.use('/api/admin', authenticateToken, adminRoutes);

// Serve frontend for all other routes
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Error handling middleware
app.use(errorHandler);

// Graceful shutdown
process.on('SIGTERM', async () => {
    console.log('🔄 SIGTERM received, shutting down gracefully');
    await mongoose.connection.close();
    console.log('📦 MongoDB connection closed');
    process.exit(0);
});

process.on('SIGINT', async () => {
    console.log('🔄 SIGINT received, shutting down gracefully');
    await mongoose.connection.close();
    console.log('📦 MongoDB connection closed');
    process.exit(0);
});

// Start server
app.listen(PORT, () => {
    console.log(`🚀 SecureVault server running on port ${PORT}`);
    console.log(`🌐 Environment: ${process.env.NODE_ENV || 'development'}`);
    console.log(`📊 Running At: http://localhost:${PORT}/`);
});

module.exports = app;