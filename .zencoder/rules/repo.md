---
description: Repository Information Overview
alwaysApply: true
---

# SecureVault Information

## Summary
SecureVault is a secure password manager with MongoDB backend and strong encryption. It provides features like AES-256-GCM encryption for passwords, bcrypt password hashing, JWT authentication, rate limiting, account locking, and an admin panel for user management.

## Structure
- **config/**: Configuration files for security settings
- **middleware/**: Express middleware for authentication, error handling, and security
- **models/**: MongoDB schema definitions for users, passwords, and audit trails
- **public/**: Frontend static files (HTML, CSS, JavaScript)
- **routes/**: API endpoints for authentication, password management, and admin functions
- **scripts/**: Utility scripts for database initialization and testing
- **utils/**: Utility functions for encryption and password security

## Language & Runtime
**Language**: JavaScript (Node.js)
**Version**: Node.js v16.0.0 or higher
**Framework**: Express.js
**Database**: MongoDB
**Package Manager**: npm

## Dependencies
**Main Dependencies**:
- express: ^4.18.2 - Web framework
- mongoose: ^8.0.3 - MongoDB ODM
- bcryptjs: ^2.4.3 - Password hashing
- jsonwebtoken: ^9.0.2 - JWT authentication
- crypto: ^1.0.1 - Encryption utilities
- helmet: ^7.1.0 - Security headers
- express-rate-limit: ^7.1.5 - Rate limiting
- dotenv: ^16.3.1 - Environment variable management

**Development Dependencies**:
- nodemon: ^3.0.2 - Auto-restart during development

## Build & Installation
```bash
# Install dependencies
npm install

# Configure environment
# Copy .env.example to .env and update with your settings

# Start MongoDB
# Make sure MongoDB is running on your system

# Start the application in production mode
npm start

# Start in development mode (with auto-restart)
npm run dev
```

## Main Files
**Entry Point**: server.js
**API Routes**:
- routes/auth.js - Authentication endpoints
- routes/passwords.js - Password management
- routes/admin.js - Admin functionality

**Models**:
- models/User.js - User schema
- models/Password.js - Password schema
- models/DeletedUser.js - Audit trail for deleted users
- models/RestoredUser.js - Audit trail for restored users

## API Endpoints
**Authentication**:
- POST /api/auth/register - Register new user
- POST /api/auth/login - User login
- POST /api/auth/refresh - Refresh tokens
- GET /api/auth/me - Get current user info

**Passwords**:
- GET /api/passwords - Get user passwords
- POST /api/passwords - Create password
- PUT /api/passwords/:id - Update password
- DELETE /api/passwords/:id - Delete password

**Admin**:
- GET /api/admin/stats - Admin dashboard stats
- GET /api/admin/users - Get all users
- DELETE /api/admin/users/:id - Delete user
- POST /api/admin/users/:id/unlock - Unlock user account

## Security Features
- AES-256-GCM encryption for stored passwords
- bcrypt password hashing with salt rounds
- JWT authentication with refresh tokens
- Rate limiting to prevent brute force attacks
- Account locking after failed login attempts
- Security headers via Helmet.js
- Input validation on all endpoints
- MongoDB connection security

## Deployment
**Deployment Platform**: Render (recommended)
**Database**: MongoDB Atlas (cloud)
**Environment Variables**:
- MONGODB_URI - MongoDB connection string
- JWT_SECRET - Secret for JWT token generation
- ENCRYPTION_KEY - 32-character key for AES-256 encryption
- NODE_ENV - Set to 'production' for deployment
- PORT - Application port (default: 3000)
- ADMIN_PASSWORD - Password for admin access