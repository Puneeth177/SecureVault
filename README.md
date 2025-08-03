# SecureVault - MongoDB Password Manager

A secure, modern password manager with MongoDB backend and strong encryption.

## 🔒 Security Features

- **AES-256-GCM Encryption**: All passwords encrypted with industry-standard encryption
- **bcrypt Password Hashing**: User passwords hashed with salt rounds
- **JWT Authentication**: Secure token-based authentication with refresh tokens
- **Rate Limiting**: Protection against brute force attacks
- **Account Locking**: Automatic account locking after failed attempts
- **Admin Panel**: Comprehensive user management with audit trails
- **Secure Headers**: Helmet.js for security headers
- **Input Validation**: Comprehensive validation on all inputs

## 🚀 Quick Start

### Prerequisites

- Node.js (v16 or higher)
- MongoDB (local or cloud)

### Installation

1. **Clone/Download the project**
   ```bash
   cd SecureVault
   ```

2. **Install dependencies**
   ```bash
   npm install
   ```
   Or run the install script:
   ```bash
   install.bat
   ```

3. **Configure Environment**
   
   Update the `.env` file with your settings:
   ```env
   # Database Configuration
   MONGODB_URI=mongodb://localhost:27017/securevault
   
   # Security Configuration (CHANGE THESE!)
   JWT_SECRET=your-super-secret-jwt-key-change-this-in-production-min-32-chars
   ENCRYPTION_KEY=your-32-character-encryption-key-change-this-in-production!!
   ADMIN_PASSWORD=SecureVault2024!
   
   # Server Configuration
   PORT=3000
   NODE_ENV=development
   ```

4. **Start MongoDB**
   
   Make sure MongoDB is running on your system:
   ```bash
   # Windows (if MongoDB is installed as service)
   net start MongoDB
   
   # Or start manually
   mongod
   ```

5. **Start the Application**
   ```bash
   # Production mode
   npm start
   
   # Development mode (with auto-restart)
   npm run dev
   ```

6. **Access the Application**
   
   Open your browser and go to: `http://localhost:3000`

## 📊 Database Schema

### Users Collection
- **username**: Unique username (3-30 chars)
- **email**: Unique email address
- **password**: bcrypt hashed password
- **isAdmin**: Admin privileges flag
- **isActive**: Account status
- **lastLogin**: Last login timestamp
- **loginAttempts**: Failed login counter
- **lockUntil**: Account lock expiration
- **twoFactorEnabled**: 2FA status (future feature)

### Passwords Collection
- **userId**: Reference to user
- **website**: Website/service name
- **username**: Username for the service
- **encryptedPassword**: AES-256-GCM encrypted password
- **iv**: Initialization vector for encryption
- **category**: Password category
- **notes**: Optional notes
- **tags**: Array of tags
- **strength**: Password strength rating
- **lastAccessed**: Last access timestamp
- **accessCount**: Access counter
- **expiresAt**: Optional expiration date
- **isCompromised**: Compromise flag

### DeletedUsers Collection
- **originalUserId**: Original user ID
- **username**: Deleted username
- **email**: Deleted email
- **deletedBy**: Admin who deleted
- **deletionReason**: Reason for deletion
- **passwordCount**: Number of passwords deleted
- **metadata**: Additional user data

### RestoredUsers Collection
- **newUserId**: New user ID after restoration
- **username**: Restored username
- **email**: Restored email
- **originalDeletedAt**: Original deletion timestamp
- **restorationMethod**: How user was restored
- **timeBetweenDeletionAndRestoration**: Time difference

## 🔐 Encryption Details

### Password Encryption
- **Algorithm**: AES-256-GCM
- **Key Derivation**: PBKDF2 with 100,000 iterations
- **Initialization Vector**: 128-bit random IV per password
- **Authentication**: Built-in authentication tag
- **Additional Data**: "SecureVault" string for extra security

### User Password Hashing
- **Algorithm**: bcrypt
- **Salt Rounds**: 12 (configurable)
- **Automatic Salt**: Unique salt per password

## 🛡️ Security Best Practices

### Environment Variables
Always change these in production:
```env
JWT_SECRET=your-unique-jwt-secret-minimum-32-characters-long
ENCRYPTION_KEY=your-unique-32-character-encryption-key
ADMIN_PASSWORD=your-secure-admin-password
```

### MongoDB Security
- Use MongoDB authentication
- Enable SSL/TLS for connections
- Use MongoDB Atlas for cloud deployment
- Regular backups and monitoring

### Server Security
- Use HTTPS in production
- Configure proper CORS origins
- Set up proper firewall rules
- Regular security updates

## 👨‍💼 Admin Panel

Access the admin panel by:
1. Log in as an admin user
2. Press `Ctrl+Shift+A`
3. Enter admin password (default: `SecureVault2024!`)

### Admin Features
- **User Management**: View, delete, lock/unlock users
- **Bulk Operations**: Select and delete multiple users
- **Audit Trails**: Track deleted and restored users
- **Statistics**: User and password statistics
- **History Management**: Clear audit logs

## 🔧 API Endpoints

### Authentication
- `POST /api/auth/register` - Register new user
- `POST /api/auth/login` - User login
- `POST /api/auth/refresh` - Refresh tokens
- `POST /api/auth/forgot-password` - Reset password
- `GET /api/auth/me` - Get current user info

### Passwords
- `GET /api/passwords` - Get user passwords
- `POST /api/passwords` - Create password
- `PUT /api/passwords/:id` - Update password
- `DELETE /api/passwords/:id` - Delete password
- `DELETE /api/passwords` - Bulk delete passwords
- `POST /api/passwords/generate` - Generate secure password
- `GET /api/passwords/stats/overview` - Password statistics

### Admin (Requires Admin Role)
- `GET /api/admin/stats` - Admin dashboard stats
- `GET /api/admin/users` - Get all users
- `DELETE /api/admin/users/:id` - Delete user
- `DELETE /api/admin/users` - Bulk delete users
- `GET /api/admin/deleted-users` - Deleted users history
- `GET /api/admin/restored-users` - Restored users history
- `POST /api/admin/users/:id/unlock` - Unlock user account
- `POST /api/admin/users/:id/toggle-admin` - Toggle admin status

## 🚨 Error Handling

The application includes comprehensive error handling:
- **Validation Errors**: Input validation with detailed messages
- **Authentication Errors**: Token validation and refresh
- **Database Errors**: MongoDB connection and query errors
- **Rate Limiting**: Automatic rate limiting on sensitive endpoints
- **Account Locking**: Automatic locking after failed attempts

## 📈 Monitoring & Logging

- **Health Check**: `GET /api/health`
- **Console Logging**: Structured logging for debugging
- **Audit Trails**: User actions logged in database
- **Error Tracking**: Comprehensive error logging

## 🔄 Backup & Recovery

### Database Backup
```bash
# Create backup
mongodump --db securevault --out ./backup

# Restore backup
mongorestore --db securevault ./backup/securevault
```

### Environment Backup
- Backup `.env` file securely
- Store encryption keys safely
- Document admin credentials

## 🚀 Production Deployment

### Environment Setup
1. Set `NODE_ENV=production`
2. Use strong, unique secrets
3. Configure MongoDB with authentication
4. Set up SSL/TLS certificates
5. Configure reverse proxy (nginx/Apache)

### Security Checklist
- [ ] Change all default passwords
- [ ] Use environment variables for secrets
- [ ] Enable MongoDB authentication
- [ ] Configure HTTPS
- [ ] Set up proper CORS origins
- [ ] Enable rate limiting
- [ ] Configure security headers
- [ ] Set up monitoring and logging
- [ ] Regular security updates
- [ ] Backup strategy in place

## 🤝 Contributing

1. Fork the repository
2. Create feature branch
3. Make changes with tests
4. Submit pull request

## 📄 License

MIT License - see LICENSE file for details.

## 🆘 Support

For issues and questions:
1. Check the troubleshooting section
2. Review error logs
3. Check MongoDB connection
4. Verify environment variables

---

**⚠️ Security Notice**: This is a demonstration project. For production use, conduct a thorough security audit and follow enterprise security practices.