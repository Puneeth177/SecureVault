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
const corsOptions = {
    origin: function (origin, callback) {
        // Allow requests with no origin (like mobile apps or curl requests)
        if (!origin) return callback(null, true);
        
        const allowedOrigins = [
            process.env.CORS_ORIGIN,
            'http://localhost:3000',
            'http://127.0.0.1:3000'
        ].filter(Boolean);
        
        // In production, also allow the Render app URL
        if (process.env.NODE_ENV === 'production' && process.env.RENDER_EXTERNAL_URL) {
            allowedOrigins.push(process.env.RENDER_EXTERNAL_URL);
        }

        if (allowedOrigins.includes(origin)) {
            callback(null, true);
        } else {
            callback(new Error(`Origin '${origin}' is not allowed by CORS`));
        }
    },
    allowedHeaders: ['Content-Type', 'Authorization'],
    credentials: true,
    methods: 'GET,HEAD,PUT,PATCH,POST,DELETE'
};

app.use(cors(corsOptions));

// Body parsing middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Serve static files
app.use(express.static(path.join(__dirname, 'public')));

// --- Database Connection ---
const MONGODB_URI = process.env.MONGODB_URI;

if (!MONGODB_URI) {
    console.error('❌ FATAL ERROR: MONGODB_URI environment variable is not set.');
    console.error('💡 For local development: mongodb://localhost:27017/SecureVault');
    console.error('💡 For production: mongodb+srv://username:password@cluster.mongodb.net/securevault');
    process.exit(1);
}

// Validate MongoDB URI format
const isValidMongoURI = (uri) => {
    return uri.startsWith('mongodb://') || uri.startsWith('mongodb+srv://');
};

if (!isValidMongoURI(MONGODB_URI)) {
    console.error('❌ FATAL ERROR: Invalid MongoDB URI format.');
    console.error('💡 URI should start with mongodb:// or mongodb+srv://');
    process.exit(1);
}

// Validate that srv URIs do not contain a port, which is a common mistake.
if (MONGODB_URI.startsWith('mongodb+srv://')) {
    // Find the part of the URI after the credentials (if any)
    const atIndex = MONGODB_URI.indexOf('@');
    const hostPartStartIndex = atIndex > -1 ? atIndex + 1 : MONGODB_URI.indexOf('//') + 2;
    
    // Find the end of the host part (before the path or options)
    const hostPartEndIndex = MONGODB_URI.indexOf('/', hostPartStartIndex);
    
    // Extract the host string
    const hostString = hostPartEndIndex > -1 
        ? MONGODB_URI.substring(hostPartStartIndex, hostPartEndIndex)
        : MONGODB_URI.substring(hostPartStartIndex);

    if (hostString.includes(':')) {
        console.error('❌ FATAL ERROR: Invalid mongodb+srv URI. A port number cannot be specified in an srv connection string.');
        console.error(`💡 Detected host part: ${hostString}`);
        process.exit(1);
    }
}

// For debugging connection issues, log the URI without credentials.
const maskedURI = MONGODB_URI.includes('@') 
    ? MONGODB_URI.replace(/:([^:@]+)@/, ':<password>@')
    : MONGODB_URI;
console.log(`🔗 Attempting to connect to MongoDB: ${maskedURI}`);

// Database connection with improved error handling
const connectOptions = {
    serverSelectionTimeoutMS: 30000, // Increased timeout for cloud connections
    socketTimeoutMS: 45000,
    maxPoolSize: 10,
    retryWrites: true,
    w: 'majority'
};

mongoose.connect(MONGODB_URI, connectOptions)
.then(() => {
    console.log('✅ Connected to MongoDB successfully');
    console.log(`📊 Database: ${mongoose.connection.name}`);
    console.log(`🌐 Host: ${mongoose.connection.host}`);
})
.catch((error) => {
    console.error('❌ MongoDB connection error:', error.message);
    
    // Provide helpful error messages
    if (error.message.includes('ENOTFOUND')) {
        console.error('💡 DNS resolution failed. Check your MongoDB URI and internet connection.');
    } else if (error.message.includes('authentication failed')) {
        console.error('💡 Authentication failed. Check your username and password.');
    } else if (error.message.includes('timeout')) {
        console.error('💡 Connection timeout. Check your network and MongoDB service status.');
    }
    
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
    const environment = process.env.NODE_ENV || 'development';
    const runningUrl = process.env.RENDER_EXTERNAL_URL || `http://localhost:${PORT}`;

    console.log(`🚀 SecureVault server running on port ${PORT}`);
    console.log(`🌐 Environment: ${environment}`);
    console.log(`📊 Running At: ${runningUrl}`);
});

module.exports = app;