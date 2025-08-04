// SecureVault Frontend - MongoDB Integration
// Modern password manager with secure backend integration

class SecureVaultApp {
    constructor() {
        this.currentUser = null;
        this.token = null;
        this.refreshToken = null;
        this.passwords = [];
        this.selectedPasswords = new Set();
        this.apiBaseUrl = '/api';
        this.adminToken = null; // To store the temporary admin token
        
        this.initializeApp();
    }

    // Initialize the application
    async initializeApp() {
        this.bindEvents();
        await this.checkAuthentication();
    }

    // Bind all event listeners
    bindEvents() {
        // Authentication events
        const loginForm = document.getElementById('loginForm');
        if (loginForm) loginForm.addEventListener('submit', (e) => this.handleLogin(e));
        const registerForm = document.getElementById('registerForm');
        if (registerForm) registerForm.addEventListener('submit', (e) => this.handleRegister(e));
        const forgotPasswordForm = document.getElementById('forgotPasswordForm');
        if (forgotPasswordForm) forgotPasswordForm.addEventListener('submit', (e) => this.handleForgotPassword(e));
        const showRegister = document.getElementById('showRegister');
        if (showRegister) showRegister.addEventListener('click', () => this.showRegisterForm());
        const showLogin = document.getElementById('showLogin');
        if (showLogin) showLogin.addEventListener('click', () => this.showLoginForm());
        const showForgotPassword = document.getElementById('showForgotPassword');
        if (showForgotPassword) showForgotPassword.addEventListener('click', () => this.showForgotPasswordForm());
        const backToLogin = document.getElementById('backToLogin');
        if (backToLogin) backToLogin.addEventListener('click', () => this.showLoginForm());
        const logoutBtn = document.getElementById('logoutBtn');
        if (logoutBtn) logoutBtn.addEventListener('click', () => this.handleLogout());
        
        // Password validation events
        const registerPassword = document.getElementById('registerPassword');
        if (registerPassword) {
            registerPassword.addEventListener('focus', () => this.showPasswordRequirements());
            registerPassword.addEventListener('blur', () => this.hidePasswordRequirements());
            registerPassword.addEventListener('input', (e) => this.validatePasswordStrength(e.target.value));
        }

        // Password management events
        const passwordForm = document.getElementById('passwordForm');
        if (passwordForm) passwordForm.addEventListener('submit', (e) => this.handleAddPassword(e));
        const selectAllBtn = document.getElementById('selectAllBtn');
        if (selectAllBtn) selectAllBtn.addEventListener('click', () => this.handleSelectAll());
        const deleteSelectedBtn = document.getElementById('deleteSelectedBtn');
        if (deleteSelectedBtn) deleteSelectedBtn.addEventListener('click', () => this.handleDeleteSelected());

        // Delete account events
        const showDeleteAccount = document.getElementById('showDeleteAccount');
        if (showDeleteAccount) showDeleteAccount.addEventListener('click', () => this.showDeleteAccountPage());
        const deleteAccountForm = document.getElementById('deleteAccountForm');
        if (deleteAccountForm) deleteAccountForm.addEventListener('submit', (e) => this.handleDeleteAccount(e));
        const backToDashboard = document.getElementById('backToDashboard');
        if (backToDashboard) backToDashboard.addEventListener('click', () => this.showPasswordManager());

        // Password toggle functionality
        const loginPasswordToggle = document.getElementById('loginPasswordToggle');
        if (loginPasswordToggle) {
            loginPasswordToggle.addEventListener('click', () => {
                const passwordField = document.getElementById('loginPassword');
                if (passwordField.type === 'password') {
                    passwordField.type = 'text';
                    loginPasswordToggle.textContent = '🙈';
                } else {
                    passwordField.type = 'password';
                    loginPasswordToggle.textContent = '👁️';
                }
            });
        }

        // Register password toggle functionality
        const registerPasswordToggle = document.getElementById('registerPasswordToggle');
        if (registerPasswordToggle) {
            registerPasswordToggle.addEventListener('click', () => {
                const passwordField = document.getElementById('registerPassword');
                if (passwordField.type === 'password') {
                    passwordField.type = 'text';
                    registerPasswordToggle.textContent = '🙈';
                } else {
                    passwordField.type = 'password';
                    registerPasswordToggle.textContent = '👁️';
                }
            });
        }

        // New password toggle functionality for forgot password page
        const newPasswordToggle = document.getElementById('newPasswordToggle');
        if (newPasswordToggle) {
            newPasswordToggle.addEventListener('click', () => {
                const passwordField = document.getElementById('newPassword');
                if (passwordField.type === 'password') {
                    passwordField.type = 'text';
                    newPasswordToggle.textContent = '🙈';
                } else {
                    passwordField.type = 'password';
                    newPasswordToggle.textContent = '👁️';
                }
            });
        }

        // Search functionality
        const searchPasswords = document.getElementById('searchPasswords');
        if (searchPasswords) {
            searchPasswords.addEventListener('input', (e) => this.handleSearch(e.target.value));
        }

        // Admin panel - accessible via Ctrl+Shift+A
        document.addEventListener('keydown', (e) => {
            if (e.ctrlKey && e.shiftKey && e.key === 'A') {
                this.showAdminPanel();
            }
        });

        // Auto-refresh token
        setInterval(() => this.refreshTokenIfNeeded(), 5 * 60 * 1000); // Every 5 minutes
        
        // Set up registration field validation
        this.setupRegistrationValidation();
    }

    // API Helper Methods
    async apiCall(endpoint, options = {}) {
        const url = `${this.apiBaseUrl}${endpoint}`;
        const config = {
            headers: {
                'Content-Type': 'application/json',
                ...(this.token && { 'Authorization': `Bearer ${this.token}` })
            },
            ...options
        };

        if (config.body && typeof config.body === 'object') {
            config.body = JSON.stringify(config.body);
        }

        try {
            const response = await fetch(url, config);
            const data = await response.json();

            if (!response.ok) {
                // Handle token expiration
                if (response.status === 401 && this.refreshToken) {
                    const refreshed = await this.refreshTokens();
                    if (refreshed) {
                        // Retry the original request
                        config.headers['Authorization'] = `Bearer ${this.token}`;
                        const retryResponse = await fetch(url, config);
                        return await retryResponse.json();
                    }
                }
                
                // Create detailed error with validation info
                const error = new Error(data.message || 'API request failed');
                error.status = response.status;
                error.errors = data.errors || [];
                error.data = data;
                throw error;
            }

            return data;
        } catch (error) {
            console.error('API Error:', error);
            throw error;
        }
    }

    // Token Management
    async refreshTokens() {
        try {
            const response = await this.apiCall('/auth/refresh', {
                method: 'POST',
                body: { refreshToken: this.refreshToken }
            });

            if (response.success) {
                this.token = response.data.token;
                this.refreshToken = response.data.refreshToken;
                this.saveTokens();
                return true;
            }
        } catch (error) {
            console.error('Token refresh failed:', error);
            this.handleLogout();
        }
        return false;
    }

    async refreshTokenIfNeeded() {
        if (!this.token || !this.refreshToken) return;

        try {
            // Decode token to check expiration (simple check)
            const tokenPayload = JSON.parse(atob(this.token.split('.')[1]));
            const now = Math.floor(Date.now() / 1000);
            
            // Refresh if token expires in next 10 minutes
            if (tokenPayload.exp - now < 600) {
                await this.refreshTokens();
            }
        } catch (error) {
            console.error('Token check failed:', error);
        }
    }

    saveTokens() {
        if (this.token) localStorage.setItem('securevault_token', this.token);
        if (this.refreshToken) localStorage.setItem('securevault_refresh_token', this.refreshToken);
    }

    loadTokens() {
        this.token = localStorage.getItem('securevault_token');
        this.refreshToken = localStorage.getItem('securevault_refresh_token');
    }

    clearTokens() {
        this.token = null;
        this.refreshToken = null;
        localStorage.removeItem('securevault_token');
        localStorage.removeItem('securevault_refresh_token');
        localStorage.removeItem('securevault_current_user');
    }

    // Setup registration field validation
    setupRegistrationValidation() {
        const usernameField = document.getElementById('registerUsername');
        const emailField = document.getElementById('registerEmail');
        
        if (usernameField && !usernameField.hasAttribute('data-validated')) {
            usernameField.setAttribute('data-validated', 'true');
            
            // Clear error when user starts typing
            usernameField.addEventListener('input', () => {
                this.hideFieldError(usernameField);
            });
            
            usernameField.addEventListener('blur', async () => {
                const username = usernameField.value.trim();
                if (username.length >= 3) {
                    try {
                        // Check if username already exists
                        const response = await this.apiCall('/auth/check-username', {
                            method: 'POST',
                            body: { username }
                        });
                        
                        if (!response.success) {
                            usernameField.classList.add('input-error-vibrate');
                            this.showFieldError(usernameField, 'Username already registered');
                            setTimeout(() => {
                                usernameField.classList.remove('input-error-vibrate');
                            }, 400);
                        } else {
                            // Clear any previous error for this field
                            this.hideFieldError(usernameField);
                        }
                    } catch (error) {
                        console.error('Username check failed:', error);
                    }
                }
            });
        }
        
        if (emailField && !emailField.hasAttribute('data-validated')) {
            emailField.setAttribute('data-validated', 'true');
            
            // Clear error when user starts typing
            emailField.addEventListener('input', () => {
                this.hideFieldError(emailField);
            });
            
            emailField.addEventListener('blur', async () => {
                const email = emailField.value.trim();
                if (email) {
                    try {
                        // Check if email already exists
                        const response = await this.apiCall('/auth/check-email', {
                            method: 'POST',
                            body: { email }
                        });
                        
                        if (!response.success) {
                            emailField.classList.add('input-error-vibrate');
                            this.showFieldError(emailField, 'Email already registered');
                            setTimeout(() => {
                                emailField.classList.remove('input-error-vibrate');
                            }, 400);
                        } else {
                            // Clear any previous error for this field
                            this.hideFieldError(emailField);
                        }
                    } catch (error) {
                        console.error('Email check failed:', error);
                    }
                }
            });
        }
    }

    // Password Validation Methods
    showPasswordRequirements() {
        const requirements = document.getElementById('passwordRequirements');
        if (requirements) {
            requirements.style.display = 'block';
        }
    }
    
    hidePasswordRequirements() {
        const requirements = document.getElementById('passwordRequirements');
        if (requirements) {
            // Only hide if password is empty
            const passwordField = document.getElementById('registerPassword');
            if (passwordField && passwordField.value.trim() === '') {
                requirements.style.display = 'none';
            }
        }
    }
    
    validatePasswordStrength(password) {
        const requirements = {
            length: password.length >= 8,
            upper: /[A-Z]/.test(password),
            lower: /[a-z]/.test(password),
            number: /\d/.test(password),
            special: /[@$!%*?&]/.test(password)
        };
        
        // Update requirement indicators
        const lengthEl = document.getElementById('req-length');
        const upperEl = document.getElementById('req-upper');
        const lowerEl = document.getElementById('req-lower');
        const numberEl = document.getElementById('req-number');
        const specialEl = document.getElementById('req-special');
        
        if (lengthEl) lengthEl.classList.toggle('valid', requirements.length);
        if (upperEl) upperEl.classList.toggle('valid', requirements.upper);
        if (lowerEl) lowerEl.classList.toggle('valid', requirements.lower);
        if (numberEl) numberEl.classList.toggle('valid', requirements.number);
        if (specialEl) specialEl.classList.toggle('valid', requirements.special);
        
        return Object.values(requirements).every(req => req);
    }

    // Authentication Methods
    async checkAuthentication() {
        this.loadTokens();
        
        if (this.token) {
            try {
                const response = await this.apiCall('/auth/me');
                if (response.success) {
                    this.currentUser = response.data.user;
                    localStorage.setItem('securevault_current_user', JSON.stringify(this.currentUser));
                    await this.showPasswordManager();
                    return;
                }
            } catch (error) {
                console.error('Authentication check failed:', error);
                this.clearTokens();
            }
        }
        
        this.showAuthForm();
    }

    async handleRegister(event) {
        event.preventDefault();
        
        const usernameField = document.getElementById('registerUsername');
        const emailField = document.getElementById('registerEmail');
        const passwordField = document.getElementById('registerPassword');
        const confirmPasswordField = document.getElementById('confirmPassword');
        
        const username = usernameField.value.trim();
        const email = emailField.value.trim();
        const password = passwordField.value;
        const confirmPassword = confirmPasswordField.value;
        
        this.hideError('registerError');
        
        if (!username || !email || !password || !confirmPassword) {
            this.showError('registerError', 'Please fill in all fields.');
            return;
        }
        
        if (password !== confirmPassword) {
            this.showError('registerError', 'Passwords do not match.');
            return;
        }
        
        try {
            const response = await this.apiCall('/auth/register', {
                method: 'POST',
                body: { username, email, password }
            });
            
            if (response.success) {
                this.token = response.data.token;
                this.refreshToken = response.data.refreshToken;
                this.currentUser = response.data.user;
                
                this.saveTokens();
                localStorage.setItem('securevault_current_user', JSON.stringify(this.currentUser));
                
                this.showSuccess('Registration successful! Welcome to SecureVault!');
                
                setTimeout(() => {
                    this.showPasswordManager();
                }, 2000);
            } else if (response.message && response.message.includes('already exists')) {
                // Apply vibration and error to username/email fields
                usernameField.classList.add('input-error-vibrate');
                emailField.classList.add('input-error-vibrate');
                
                // Show error message
                this.showError('registerError', 'Username or email already exists');
                
                // Clear animation after it completes
                setTimeout(() => {
                    usernameField.classList.remove('input-error-vibrate');
                    emailField.classList.remove('input-error-vibrate');
                }, 400);
            }
        } catch (error) {
            // Handle detailed validation errors
            if (error.message === 'Validation failed' && error.errors && error.errors.length > 0) {
                // Show specific validation errors
                const errorMessages = error.errors.map(err => err.message).join('. ');
                this.showError('registerError', errorMessages);
            } else if (error.message === 'Validation failed') {
                // Generic validation message
                this.showError('registerError', 'Please check your input. Password must be at least 8 characters with uppercase, lowercase, number, and special character.');
            } else if (error.message.includes('already exists') || error.message.includes('duplicate') || error.status === 409) {
                usernameField.classList.add('input-error-vibrate');
                emailField.classList.add('input-error-vibrate');
                this.showError('registerError', 'Username or email already exists. Please choose different credentials.');
                setTimeout(() => {
                    usernameField.classList.remove('input-error-vibrate');
                    emailField.classList.remove('input-error-vibrate');
                }, 400);
            } else {
                this.showError('registerError', error.message);
            }
        }
    }

    async handleLogin(event) {
        event.preventDefault();
        
        const identifier = document.getElementById('loginIdentifier').value.trim();
        const password = document.getElementById('loginPassword').value;
        
        this.hideError('loginError');
        
        if (!identifier || !password) {
            this.showError('loginError', 'Please fill in all fields.');
            return;
        }
        
        try {
            const response = await this.apiCall('/auth/login', {
                method: 'POST',
                body: { identifier, password }
            });
            
            if (response.success) {
                this.token = response.data.token;
                this.refreshToken = response.data.refreshToken;
                this.currentUser = response.data.user;
                
                this.saveTokens();
                localStorage.setItem('securevault_current_user', JSON.stringify(this.currentUser));
                
                // Await loading passwords to ensure UI updates correctly
                await this.loadPasswords();
                await this.showPasswordManager();
            }
        } catch (error) {
            if (error.status === 401) {
                this.showError('loginError', 'Invalid username/email or password. Please check your credentials.');
            } else if (error.status === 423) {
                this.showError('loginError', 'Account is temporarily locked due to multiple failed attempts. Please try again later.');
            } else if (error.status === 403) {
                this.showError('loginError', 'Your account has been deleted. Please contact support.');
            } else {
                this.showError('loginError', error.message);
            }
        }
    }

    async handleForgotPassword(event) {
        event.preventDefault();
        
        const username = document.getElementById('forgotUsername').value.trim();
        const email = document.getElementById('forgotEmail').value.trim();
        const newPassword = document.getElementById('newPassword').value;
        const confirmNewPassword = document.getElementById('confirmNewPassword').value;
        
        this.hideError('forgotPasswordError');
        
        if (!username || !email || !newPassword || !confirmNewPassword) {
            this.showError('forgotPasswordError', 'Please fill in all fields.');
            return;
        }
        
        if (newPassword !== confirmNewPassword) {
            this.showError('forgotPasswordError', 'Passwords do not match.');
            return;
        }
        
        try {
            const response = await this.apiCall('/auth/forgot-password', {
                method: 'POST',
                body: { username, email, newPassword }
            });
            
            if (response.success) {
                this.showSuccess('Password updated successfully! You can now log in with your new password.');
                
                setTimeout(() => {
                    this.showLoginForm();
                    document.getElementById('loginIdentifier').value = username;
                }, 2000);
            }
        } catch (error) {
            this.showError('forgotPasswordError', error.message);
        }
    }

    handleLogout() {
        this.clearTokens();
        this.currentUser = null;
        this.passwords = [];
        this.selectedPasswords.clear();
        this.showAuthForm();
    }

    // UI Management Methods
    showAuthForm() {
        document.getElementById('auth-container').style.display = 'block';
        document.getElementById('app-container').classList.add('hidden');
        document.getElementById('delete-account-page').style.display = 'none';
        
        // Show login form by default
        this.showLoginForm();
    }

    async showPasswordManager() {
        document.getElementById('auth-container').style.display = 'none';
        document.getElementById('app-container').classList.remove('hidden');
        document.getElementById('delete-account-page').style.display = 'none';
        
        // Update user info in header
        if (this.currentUser) {
            document.getElementById('currentUser').textContent = this.currentUser.username;
            document.getElementById('currentUserEmail').textContent = this.currentUser.email;
        }
        
        // Load passwords
        await this.loadPasswords();
    }


    showLoginForm() {
        const login = document.getElementById('login-form');
        const register = document.getElementById('register-form');
        const forgot = document.getElementById('forgot-password-form');
        if (login) login.style.display = 'block';
        if (register) register.style.display = 'none';
        if (forgot) forgot.style.display = 'none';
        this.hideAllErrors();
    }

    showRegisterForm() {
        const login = document.getElementById('login-form');
        const register = document.getElementById('register-form');
        const forgot = document.getElementById('forgot-password-form');
        if (login) login.style.display = 'none';
        if (register) register.style.display = 'block';
        if (forgot) forgot.style.display = 'none';
        this.hideAllErrors();
    }

    showForgotPasswordForm() {
        const login = document.getElementById('login-form');
        const register = document.getElementById('register-form');
        const forgot = document.getElementById('forgot-password-form');
        if (login) login.style.display = 'none';
        if (register) register.style.display = 'none';
        if (forgot) forgot.style.display = 'block';
        this.hideAllErrors();
    }

    showDeleteAccountPage() {
        document.getElementById('auth-container').style.display = 'none';
        document.getElementById('app-container').classList.add('hidden');
        document.getElementById('delete-account-page').style.display = 'block';
    }

    async handleDeleteAccount(event) {
        event.preventDefault();
        
        const username = document.getElementById('deleteUsername').value.trim();
        const email = document.getElementById('deleteEmail').value.trim();
        const password = document.getElementById('deletePassword').value;
        
        this.hideError('deleteAccountError');
        
        if (!username || !email || !password) {
            this.showError('deleteAccountError', 'Please fill in all fields.');
            return;
        }
        
        const confirmation = confirm('⚠️ Are you sure you want to delete your account?\n\nThis action cannot be undone and will delete all your passwords.');
        if (!confirmation) return;
        
        try {
            const response = await this.apiCall('/auth/delete-account', {
                method: 'DELETE',
                body: { username, email, password }
            });
            
            if (response.success) {
                // Create an overlay for a more visible success message
                const overlay = document.createElement('div');
                overlay.className = 'account-deleted-overlay';
                
                const messageBox = document.createElement('div');
                messageBox.className = 'account-deleted-message';
                
                const icon = document.createElement('div');
                icon.className = 'success-icon';
                icon.textContent = '✅';
                
                const title = document.createElement('h2');
                title.textContent = 'Account Deleted Successfully';
                
                const message = document.createElement('p');
                message.textContent = 'Your account and all associated data have been permanently deleted.';
                
                const redirectMessage = document.createElement('p');
                redirectMessage.textContent = 'You will be redirected to the login page in a few seconds...';
                redirectMessage.style.fontSize = '0.9rem';
                redirectMessage.style.opacity = '0.8';
                redirectMessage.style.marginTop = '1rem';
                
                messageBox.appendChild(icon);
                messageBox.appendChild(title);
                messageBox.appendChild(message);
                messageBox.appendChild(redirectMessage);
                overlay.appendChild(messageBox);
                document.body.appendChild(overlay);
                
                // Clear tokens and redirect after a longer delay
                this.clearTokens();
                setTimeout(() => {
                    // Remove the overlay with a fade-out effect
                    overlay.style.opacity = '0';
                    overlay.style.transition = 'opacity 0.5s ease';
                    
                    setTimeout(() => {
                        if (overlay.parentNode) {
                            overlay.parentNode.removeChild(overlay);
                        }
                        this.showAuthForm();
                    }, 500);
                }, 4000); // Increased to 4 seconds for better visibility
            }
        } catch (error) {
            this.showError('deleteAccountError', error.message);
        }
    }

    showError(elementId, message) {
        const errorElement = document.getElementById(elementId);
        if (errorElement) {
            errorElement.textContent = message;
            errorElement.style.display = 'block';
        }
    }

    hideAllErrors() {
        const errorElements = document.querySelectorAll('.error-message');
        errorElements.forEach(element => {
            element.style.display = 'none';
            element.textContent = '';
        });
    }

    hideError(elementId) {
        const errorElement = document.getElementById(elementId);
        if (errorElement) {
            errorElement.style.display = 'none';
            errorElement.textContent = '';
        }
    }

    showFieldError(fieldElement, message) {
        // Remove any existing error message for this field
        this.hideFieldError(fieldElement);
        
        // Create error message element
        const errorElement = document.createElement('div');
        errorElement.className = 'input-error-message';
        errorElement.textContent = message;
        errorElement.setAttribute('data-field-error', 'true');
        
        // Insert after the field
        fieldElement.parentNode.insertBefore(errorElement, fieldElement.nextSibling);
    }

    hideFieldError(fieldElement) {
        // Find and remove any error message for this field
        const errorElement = fieldElement.parentNode.querySelector('[data-field-error="true"]');
        if (errorElement) {
            errorElement.remove();
        }
    }

    clearAllErrors() {
        const errorElements = document.querySelectorAll('.error-message');
        errorElements.forEach(element => {
            element.style.display = 'none';
            element.textContent = '';
        });
        
        // Also clear field-specific errors
        const fieldErrors = document.querySelectorAll('[data-field-error="true"]');
        fieldErrors.forEach(element => {
            element.remove();
        });
    }

    showSuccess(message) {
        // Get or create the success message area
        let successArea = document.querySelector('.success-message-area');
        if (!successArea) {
            successArea = document.createElement('div');
            successArea.className = 'success-message-area';
            document.body.appendChild(successArea);
        }
        
        // Create success message element
        const successElement = document.createElement('div');
        successElement.className = 'success-message show';
        successElement.textContent = message;
        successArea.appendChild(successElement);
        
        // Remove the message after 3 seconds
        setTimeout(() => {
            if (successElement.parentNode) {
                successElement.parentNode.removeChild(successElement);
            }
        }, 3000);
    }

    // Password Management Methods
    async loadPasswords() {
        try {
            const response = await this.apiCall('/passwords');
            if (response.success) {
                this.passwords = response.data.passwords || [];
                this.renderPasswordList();
                this.updateSelectionUI();
                return this.passwords;
            }
        } catch (error) {
            console.error('Failed to load passwords:', error);
            this.showError('passwordError', 'Failed to load passwords.');
        }
        return [];
    }

    renderPasswordList() {
        const passwordList = document.getElementById('passwordList');
        
        if (this.passwords.length === 0) {
            passwordList.innerHTML = `
                <div class="empty-state">
                    <p>No passwords saved yet. Add your first password above!</p>
                </div>
            `;
            return;
        }
        
        passwordList.innerHTML = this.passwords.map(password => `
            <div class="password-item" data-id="${password._id}">
                <div class="password-header">
                    <div class="password-info">
                        <input type="checkbox" class="password-checkbox" value="${password._id}">
                        <div class="password-details">
                            <h4>${this.escapeHtml(password.website)}</h4>
                            <p class="username">${this.escapeHtml(password.username)}</p>
                        </div>
                    </div>
                    <div class="password-actions">
                        <button class="btn-icon copy-btn" data-id="${password._id}" title="Copy Password">
                            📋
                        </button>
                        <button class="btn-icon btn-danger delete-btn" data-id="${password._id}" title="Delete">
                            🗑️
                        </button>
                    </div>
                </div>
                <div class="password-meta">
                    <small>Created: ${new Date(password.createdAt).toLocaleDateString()}</small>
                </div>
            </div>
        `).join('');
        
        // Attach event listeners to checkboxes
        const checkboxes = document.querySelectorAll('.password-checkbox');
        checkboxes.forEach(checkbox => {
            checkbox.addEventListener('change', (e) => {
                const passwordId = e.target.value;
                const isSelected = e.target.checked;
                this.handlePasswordSelection(passwordId, isSelected);
            });
        });
        
        // Attach event listeners to copy buttons
        const copyButtons = document.querySelectorAll('.copy-btn');
        copyButtons.forEach(button => {
            button.addEventListener('click', (e) => {
                const passwordId = e.target.getAttribute('data-id');
                this.copyPassword(passwordId);
            });
        });
        
        // Attach event listeners to delete buttons
        const deleteButtons = document.querySelectorAll('.delete-btn');
        deleteButtons.forEach(button => {
            button.addEventListener('click', (e) => {
                // Don't delete if button is disabled
                if (button.getAttribute('data-disabled') === 'true') {
                    e.preventDefault();
                    return false;
                }
                const passwordId = e.target.getAttribute('data-id');
                this.deletePassword(passwordId);
            });
        });
        
        this.updateSelectionUI();
    }

    async handleAddPassword(event) {
        event.preventDefault();
        
        const website = document.getElementById('websiteName').value.trim();
        const username = document.getElementById('username').value.trim();
        const password = document.getElementById('password').value;
        const category = 'other'; // Default category since no category field in HTML
        const notes = ''; // Default notes since no notes field in HTML
        
        this.hideError('passwordError');
        
        if (!website || !username || !password) {
            this.showError('passwordError', 'Please fill in all required fields.');
            return;
        }
        
        try {
            const response = await this.apiCall('/passwords', {
                method: 'POST',
                body: { website, username, password, category, notes }
            });
            
            if (response.success) {
                this.showSuccess('Password saved successfully!');
                document.getElementById('passwordForm').reset();
                await this.loadPasswords();
            }
        } catch (error) {
            this.showError('passwordError', error.message);
        }
    }

    async handleDeleteSelected() {
        if (this.selectedPasswords.size === 0) {
            alert('Please select passwords to delete.');
            return;
        }
        
        const confirmation = confirm(`Are you sure you want to delete ${this.selectedPasswords.size} password(s)?`);
        if (!confirmation) return;
        
        try {
            const passwordIds = Array.from(this.selectedPasswords);
            const response = await this.apiCall('/passwords', {
                method: 'DELETE',
                body: { passwordIds }
            });
            
            if (response.success) {
                this.showSuccess(`${response.data.deletedCount} password(s) deleted successfully.`);
                this.selectedPasswords.clear();
                await this.loadPasswords();
                this.updateSelectionUI();
            }
        } catch (error) {
            this.showError('passwordError', error.message);
        }
    }

    async deletePassword(passwordId) {
        const confirmation = confirm('Are you sure you want to delete this password?');
        if (!confirmation) return;
        
        try {
            const response = await this.apiCall(`/passwords/${passwordId}`, {
                method: 'DELETE'
            });
            
            if (response.success) {
                this.showSuccess('Password deleted successfully.');
                await this.loadPasswords();
            }
        } catch (error) {
            this.showError('passwordError', error.message);
        }
    }

    // Admin Panel Methods
    async showAdminPanel() {
        if (!this.currentUser) {
            alert('Access denied. Please log in first.');
            return;
        }

        // Re-authenticate admin with password for security
        const password = prompt('Please enter an admin password to access the admin panel:');
        if (password === null) { // User clicked cancel
            return;
        }
        if (!password) {
            alert('Password is required to continue.');
            return;
        }

        try {
            // This is a public endpoint, so it uses the regular apiCall method
            const verificationResponse = await this.apiCall('/auth/verify-admin', {
                method: 'POST',
                body: { password }
            });

            if (!verificationResponse.success) {
                alert('❌ Incorrect password. Access denied.');
                return;
            }

            // Store the admin token for all subsequent admin actions
            this.adminToken = verificationResponse.data.adminToken;

            // If password is correct, proceed to load admin data using the new admin-specific API call helper
            const statsResponse = await this.apiAdminCall('/admin/stats');
            const usersResponse = await this.apiAdminCall('/admin/users');
            const deletedUsersResponse = await this.apiAdminCall('/admin/deleted-users');
            const restoredUsersResponse = await this.apiAdminCall('/admin/restored-users');

            if (statsResponse.success && usersResponse.success) {
                this.renderAdminPanel(statsResponse.data, usersResponse.data.users, deletedUsersResponse.data?.deletedUsers || [], restoredUsersResponse.data?.restoredUsers || []);
            }
        } catch (error) {
            console.error('Failed to load admin data:', error);
            const errorMessage = error.message || 'Failed to load admin panel data. Your admin session may have expired.';
            alert(errorMessage);
            // Ensure admin token is cleared on failure
            this.adminToken = null;
        }
    }

    /**
     * A helper method for making API calls that require admin privileges.
     * It temporarily uses the stored admin token for the request.
     */
    async apiAdminCall(endpoint, options = {}) {
        if (!this.adminToken) {
            alert('Admin session has expired or is invalid. Please reopen the admin panel to re-authenticate.');
            this.hideAdminPanel();
            throw new Error('Admin token not available.');
        }

        // Temporarily swap the main token with the admin token for this specific call
        const originalToken = this.token;
        this.token = this.adminToken;

        try {
            // The existing apiCall method will now use the admin token
            return await this.apiCall(endpoint, options);
        } finally {
            // Always restore the original user's token after the call
            this.token = originalToken;
        }
    }
    renderAdminPanel(stats, users, deletedUsers, restoredUsers) {
        const adminPanel = document.createElement('div');
        adminPanel.className = 'admin-panel-overlay';
        adminPanel.innerHTML = `
            <div class="admin-panel">
                <h2>🔧 Admin Panel</h2>
                
                <!-- Admin Stats -->
                <div class="admin-stats">
                    <p><strong>Total Active Users:</strong> ${stats.users.total}</p>
                    <p><strong>Admin Users:</strong> ${stats.users.admins}</p>
                    <p><strong>Locked Users:</strong> ${stats.users.locked}</p>
                    <p><strong>Total Passwords:</strong> ${stats.passwords.total}</p>
                    <p><strong>Deleted Users:</strong> ${stats.deletions.total}</p>
                    <p><strong>Restored Users:</strong> ${stats.restorations.total}</p>
                </div>
                
                <!-- All Users List -->
                <div class="admin-users-section">
                    <div class="users-section-header">
                        <h3>👥 All Registered Users</h3>
                        <div class="bulk-user-controls">
                            <button class="btn btn-secondary btn-small" id="adminSelectAllBtn">
                                <span id="adminSelectAllText">Select All</span>
                            </button>
                            <button class="btn btn-danger btn-small" id="adminDeleteSelectedBtn" disabled>
                                🗑️ Delete Selected (<span id="adminSelectedCount">0</span>)
                            </button>
                        </div>
                    </div>
                    <div class="users-table-container">
                        <table class="users-table">
                            <thead>
                                <tr>
                                    <th class="select-column">
                                        <input type="checkbox" id="adminSelectAllCheckbox" />
                                    </th>
                                    <th>Username</th>
                                    <th>Email</th>
                                    <th>Created</th>
                                    <th>Passwords</th>
                                    <th>Status</th>
                                    <th>Actions</th>
                                </tr>
                            </thead>
                            <tbody>
                                ${users.map(user => `
                                    <tr data-user-id="${user.id}">
                                        <td class="select-cell">
                                            ${user.id === this.currentUser.id ? 
                                                '<span class="select-disabled">—</span>' : 
                                                `<input type="checkbox" class="admin-user-checkbox" value="${user._id || user.id}" />`
                                            }
                                        </td>
                                        <td class="username-cell">
                                            <strong>${this.escapeHtml(user.username)}</strong>
                                            ${user.id === this.currentUser.id ? '<span class="current-user-badge">YOU</span>' : ''}
                                            ${user.isAdmin ? '<span class="admin-badge">ADMIN</span>' : ''}
                                        </td>
                                        <td class="email-cell">${this.escapeHtml(user.email)}</td>
                                        <td class="date-cell">${new Date(user.createdAt).toLocaleDateString()}</td>
                                        <td class="password-count-cell">${user.passwordCount || 0}</td>
                                        <td class="status-cell">
                                            ${user.isLocked ? '<span class="status-locked">Locked</span>' : '<span class="status-active">Active</span>'}
                                        </td>
                                        <td class="actions-cell">
                                            ${user.id === this.currentUser.id ?
                                                '<span class="action-disabled">Cannot modify self</span>' :
                                                `<div class="user-actions-container">
                                                    <button class="btn-small ${user.isAdmin ? 'btn-warning' : 'btn-info'}" data-user-id="${user._id || user.id}" data-action="toggle-admin">
                                                        ${user.isAdmin ? 'Revoke Admin' : 'Make Admin'}
                                                    </button>
                                                    <button class="btn-small btn-danger" data-user-id="${user._id || user.id}" data-action="delete-user">
                                                        🗑️ Delete
                                                    </button>
                                                </div>`
                                            }
                                        </td>
                                    </tr>
                                `).join('')}
                            </tbody>
                        </table>
                    </div>
                </div>
                
                <!-- Deleted Users History -->
                ${deletedUsers.length > 0 ? `
                    <div class="admin-deleted-section">
                        <h3>🗂️ Deleted Users History</h3>
                        <p>Recently deleted users (${deletedUsers.length} total):</p>
                        <div class="deleted-users-table-container">
                            <table class="deleted-users-table">
                                <thead>
                                    <tr>
                                        <th>Username</th>
                                        <th>Email</th>
                                        <th>Deleted By</th>
                                        <th>Deleted At</th>
                                        <th>Passwords</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    ${deletedUsers.slice(0, 10).map(deletedUser => `
                                        <tr>
                                            <td><strong>${this.escapeHtml(deletedUser.username)}</strong></td>
                                            <td>${this.escapeHtml(deletedUser.email)}</td>
                                            <td>${this.escapeHtml(deletedUser.deletedByUsername)}</td>
                                            <td>${new Date(deletedUser.createdAt).toLocaleString()}</td>
                                            <td>${deletedUser.passwordCount || 0}</td>
                                        </tr>
                                    `).join('')}
                                </tbody>
                            </table>
                        </div>
                        <div class="deleted-users-actions">
                            <button class="btn btn-warning btn-small" id="clearDeletedUsersBtn">
                                🗑️ Clear History
                            </button>
                            <small>Showing last 10 deleted users</small>
                        </div>
                    </div>
                ` : ''}
                
                <!-- Restored Users History -->
                ${restoredUsers.length > 0 ? `
                    <div class="admin-restored-section">
                        <h3>🔄 Restored Users History</h3>
                        <p>Users who re-registered after being deleted (${restoredUsers.length} total):</p>
                        <div class="restored-users-table-container">
                            <table class="restored-users-table">
                                <thead>
                                    <tr>
                                        <th>Username</th>
                                        <th>Email</th>
                                        <th>Restored At</th>
                                        <th>Method</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    ${restoredUsers.slice(0, 10).map(restoredUser => `
                                        <tr>
                                            <td><strong>${this.escapeHtml(restoredUser.username)}</strong></td>
                                            <td>${this.escapeHtml(restoredUser.email)}</td>
                                            <td>${new Date(restoredUser.createdAt).toLocaleString()}</td>
                                            <td><span class="status-restored">${restoredUser.restorationMethod}</span></td>
                                        </tr>
                                    `).join('')}
                                </tbody>
                            </table>
                        </div>
                        <div class="restored-users-actions">
                            <button class="btn btn-info btn-small" id="clearRestoredUsersBtn">
                                🗑️ Clear History
                            </button>
                            <small>Showing last 10 restored users</small>
                        </div>
                    </div>
                ` : ''}
                
                <!-- Admin Actions -->
                <div class="admin-actions">
                    <button class="btn btn-secondary" id="closeAdminPanelBtn">Close Admin Panel</button>
                </div>
            </div>
        `;
        
        document.body.appendChild(adminPanel);
        
        // Bind event listeners for the admin panel
        this.bindAdminPanelEvents();
    }

    async adminDeleteUser(userId) {
        // Validate that the userId is a valid MongoDB ObjectID (24-character hex string)
        const isValidId = (id) => typeof id === 'string' && id.length === 24 && /^[0-9a-fA-F]{24}$/.test(id);
        
        if (!isValidId(userId)) {
            alert(`❌ Invalid user ID: ${userId}. Please refresh the admin panel and try again.`);
            return;
        }
        
        // Prevent users from deleting themselves
        if (userId === this.currentUser.id || userId === this.currentUser._id) {
            alert('❌ You cannot delete your own account.');
            return;
        }
        
        const confirmation = confirm('⚠️ Are you sure you want to delete this user?\n\nThis action cannot be undone and will delete all their passwords.');
        if (!confirmation) return;
        
        try {
            const response = await this.apiAdminCall(`/admin/users/${userId}`, {
                method: 'DELETE'
            });
            
            if (response.success) {
                alert('✅ User deleted successfully.');
                this.hideAdminPanel();
                setTimeout(() => this.showAdminPanel(), 100);
            } else {
                alert(`❌ Failed to delete user: ${response.message}`);
            }
        } catch (error) {
            alert(`❌ Failed to delete user: ${error.message}`);
        }
    }

    async adminDeleteSelectedUsers() {
        const selectedCheckboxes = document.querySelectorAll('.admin-user-checkbox:checked');
        const selectedUserIds = Array.from(selectedCheckboxes).map(cb => cb.value);
        
        // Debug logging to see what IDs we're getting
        console.log('Selected user IDs:', selectedUserIds);
        
        if (selectedUserIds.length === 0) {
            alert('❌ No users selected for deletion.');
            return;
        }
        
        // Validate that all IDs are valid MongoDB ObjectIDs (24-character hex strings)
        const isValidId = (id) => typeof id === 'string' && id.length === 24 && /^[0-9a-fA-F]{24}$/.test(id);
        const invalidIds = selectedUserIds.filter(id => !isValidId(id));
        
        if (invalidIds.length > 0) {
            alert(`❌ Invalid user IDs detected: ${invalidIds.join(', ')}. Please refresh the admin panel and try again.`);
            return;
        }
        
        // Prevent users from deleting themselves
        const selfDeletionAttempt = selectedUserIds.includes(this.currentUser.id) || selectedUserIds.includes(this.currentUser._id);
        if (selfDeletionAttempt) {
            alert('❌ You cannot delete your own account. Your account has been removed from the selection.');
            // Remove self from the list
            const filteredUserIds = selectedUserIds.filter(id => id !== this.currentUser.id && id !== this.currentUser._id);
            if (filteredUserIds.length === 0) {
                alert('❌ No valid users to delete.');
                return;
            }
            // Update the selectedUserIds array
            selectedUserIds = filteredUserIds;
        }
        
        const confirmation = confirm(`⚠️ Are you sure you want to delete ${selectedUserIds.length} user(s)?\n\nThis action cannot be undone and will delete all their passwords.`);
        if (!confirmation) return;
        
        try {
            const response = await this.apiAdminCall('/admin/users', {
                method: 'DELETE',
                body: { userIds: selectedUserIds }
            });
            
            if (response.success) {
                alert(`✅ Successfully deleted ${response.data.deletedCount} user(s).`);
                this.hideAdminPanel();
                setTimeout(() => this.showAdminPanel(), 100);
            } else {
                alert(`❌ Failed to delete users: ${response.message}`);
            }
        } catch (error) {
            console.error('Delete users error:', error);
            if (error.message === 'Validation failed' && error.errors && error.errors.length > 0) {
                const errorMessages = error.errors.map(err => err.message).join(', ');
                alert(`❌ Failed to delete users: Validation failed - ${errorMessages}`);
            } else {
                alert(`❌ Failed to delete users: ${error.message}`);
            }
        }
    }

    async clearDeletedUsersHistory() {
        const confirmation = confirm('⚠️ Are you sure you want to clear the deleted users history?');
        if (!confirmation) return;
        
        try {
            const response = await this.apiAdminCall('/admin/deleted-users', {
                method: 'DELETE'
            });
            
            if (response.success) {
                alert('✅ Deleted users history cleared.');
                this.hideAdminPanel();
                setTimeout(() => this.showAdminPanel(), 100);
            }
        } catch (error) {
            alert(`❌ Failed to clear history: ${error.message}`);
        }
    }

    async clearRestoredUsersHistory() {
        const confirmation = confirm('⚠️ Are you sure you want to clear the restored users history?');
        if (!confirmation) return;
        
        try {
            const response = await this.apiAdminCall('/admin/restored-users', {
                method: 'DELETE'
            });
            
            if (response.success) {
                alert('✅ Restored users history cleared.');
                this.hideAdminPanel();
                setTimeout(() => this.showAdminPanel(), 100);
            }
        } catch (error) {
            alert(`❌ Failed to clear history: ${error.message}`);
        }
    }

    async adminToggleAdminStatus(userId) {
        // Validate that the userId is a valid MongoDB ObjectID (24-character hex string)
        const isValidId = (id) => typeof id === 'string' && id.length === 24 && /^[0-9a-fA-F]{24}$/.test(id);
        
        if (!isValidId(userId)) {
            alert(`❌ Invalid user ID: ${userId}. Please refresh the admin panel and try again.`);
            return;
        }
        
        const userRow = document.querySelector(`tr[data-user-id="${userId}"]`);
        const username = userRow.querySelector('.username-cell strong').textContent;
        const isCurrentlyAdmin = userRow.querySelector('.admin-badge') !== null;

        const action = isCurrentlyAdmin ? 'revoke admin privileges from' : 'grant admin privileges to';
        const confirmation = confirm(`Are you sure you want to ${action} "${username}"?`);
        if (!confirmation) return;

        try {
            const response = await this.apiAdminCall(`/admin/users/${userId}/toggle-admin`, {
                method: 'POST'
            });

            if (response.success) {
                alert(`✅ ${response.message}`);
                this.hideAdminPanel();
                setTimeout(() => this.showAdminPanel(), 100); // Refresh panel
            }
        } catch (error) {
            alert(`❌ Failed to update user status: ${error.message}`);
        }
    }

    // Admin selection methods
    adminUpdateSelection() {
        const checkboxes = document.querySelectorAll('.admin-user-checkbox');
        const selectedCheckboxes = document.querySelectorAll('.admin-user-checkbox:checked');
        const selectAllCheckbox = document.getElementById('adminSelectAllCheckbox');
        const deleteSelectedBtn = document.getElementById('adminDeleteSelectedBtn');
        const selectedCountSpan = document.getElementById('adminSelectedCount');
        const selectAllText = document.getElementById('adminSelectAllText');
        
        // Debug logging to see what's happening with selection updates
        console.log('Selection updated:', {
            totalCheckboxes: checkboxes.length,
            selectedCheckboxes: selectedCheckboxes.length,
            selectedValues: Array.from(selectedCheckboxes).map(cb => cb.value)
        });
        
        const selectedCount = selectedCheckboxes.length;
        selectedCountSpan.textContent = selectedCount;
        deleteSelectedBtn.disabled = selectedCount === 0;
        
        if (selectedCount === 0) {
            selectAllCheckbox.indeterminate = false;
            selectAllCheckbox.checked = false;
            selectAllText.textContent = 'Select All';
        } else if (selectedCount === checkboxes.length) {
            selectAllCheckbox.indeterminate = false;
            selectAllCheckbox.checked = true;
            selectAllText.textContent = 'Deselect All';
        } else {
            selectAllCheckbox.indeterminate = true;
            selectAllText.textContent = 'Select All';
        }
    }

    adminToggleSelectAll() {
        const selectAllCheckbox = document.getElementById('adminSelectAllCheckbox');
        const checkboxes = document.querySelectorAll('.admin-user-checkbox');
        
        // Debug logging to see what's happening with select all
        console.log('Select all toggled:', { 
            checked: selectAllCheckbox.checked, 
            checkboxCount: checkboxes.length 
        });
        
        checkboxes.forEach(checkbox => {
            checkbox.checked = selectAllCheckbox.checked;
            console.log('Checkbox updated:', { 
                value: checkbox.value, 
                checked: checkbox.checked 
            });
        });
        
        this.adminUpdateSelection();
    }

    adminSelectAllUsers() {
        const selectAllCheckbox = document.getElementById('adminSelectAllCheckbox');
        selectAllCheckbox.checked = !selectAllCheckbox.checked;
        this.adminToggleSelectAll();
    }

    hideAdminPanel() {
        const adminPanel = document.querySelector('.admin-panel-overlay');
        if (adminPanel) {
            adminPanel.remove();
        }
    }

    bindAdminPanelEvents() {
        // Bind event listeners for admin panel buttons
        const adminSelectAllBtn = document.getElementById('adminSelectAllBtn');
        const adminSelectAllCheckbox = document.getElementById('adminSelectAllCheckbox');
        const adminDeleteSelectedBtn = document.getElementById('adminDeleteSelectedBtn');
        const clearDeletedUsersBtn = document.getElementById('clearDeletedUsersBtn');
        const clearRestoredUsersBtn = document.getElementById('clearRestoredUsersBtn');
        const closeAdminPanelBtn = document.getElementById('closeAdminPanelBtn');
        
        if (adminSelectAllBtn) {
            adminSelectAllBtn.addEventListener('click', () => this.adminSelectAllUsers());
        }
        
        if (adminSelectAllCheckbox) {
            adminSelectAllCheckbox.addEventListener('change', () => this.adminToggleSelectAll());
        }
        
        if (adminDeleteSelectedBtn) {
            adminDeleteSelectedBtn.addEventListener('click', () => this.adminDeleteSelectedUsers());
        }
        
        if (clearDeletedUsersBtn) {
            clearDeletedUsersBtn.addEventListener('click', () => this.clearDeletedUsersHistory());
        }
        
        if (clearRestoredUsersBtn) {
            clearRestoredUsersBtn.addEventListener('click', () => this.clearRestoredUsersHistory());
        }
        
        if (closeAdminPanelBtn) {
            closeAdminPanelBtn.addEventListener('click', () => this.hideAdminPanel());
        }
        
        // Bind event listeners for user action buttons
        const userActionButtons = document.querySelectorAll('.user-actions-container button');
        userActionButtons.forEach(button => {
            button.addEventListener('click', (e) => {
                const userId = e.target.getAttribute('data-user-id');
                const action = e.target.getAttribute('data-action');
                
                // Debug logging to see what IDs we're getting
                console.log('Button clicked:', { userId, action });
                
                if (action === 'toggle-admin') {
                    this.adminToggleAdminStatus(userId);
                } else if (action === 'delete-user') {
                    this.adminDeleteUser(userId);
                }
            });
        });
        
        // Bind event listeners for user checkboxes
        const adminUserCheckboxes = document.querySelectorAll('.admin-user-checkbox');
        adminUserCheckboxes.forEach(checkbox => {
            checkbox.addEventListener('change', (e) => {
                // Debug logging to see what values we're getting
                console.log('Checkbox changed:', { value: e.target.value, checked: e.target.checked });
                this.adminUpdateSelection();
            });
        });
    }

    showSuccess(message) {
        // Get or create the success message area
        let successArea = document.querySelector('.success-message-area');
        if (!successArea) {
            successArea = document.createElement('div');
            successArea.className = 'success-message-area';
            document.body.appendChild(successArea);
        }
        
        // Create success message element
        const successElement = document.createElement('div');
        successElement.className = 'success-message show';
        successElement.textContent = message;
        successArea.appendChild(successElement);
        
        // Remove the message after 3 seconds
        setTimeout(() => {
            if (successElement.parentNode) {
                successElement.parentNode.removeChild(successElement);
            }
        }, 3000);
    }

    renderPasswordList() {
        const passwordList = document.getElementById('passwordList');
        
        if (this.passwords.length === 0) {
            passwordList.innerHTML = `
                <div class="empty-state">
                    <h3>No passwords saved yet</h3>
                    <p>Add your first password using the form above.</p>
                </div>
            `;
            return;
        }
        
        passwordList.innerHTML = this.passwords.map(password => `
            <div class="password-item" data-id="${password._id}">
                <div class="password-header">
                    <div class="password-info">
                        <input type="checkbox" class="password-checkbox" value="${password._id}">
                        <div class="password-details">
                            <h4>${this.escapeHtml(password.website)}</h4>
                            <p class="username">${this.escapeHtml(password.username)}</p>
                            ${password.category !== 'other' ? `<span class="category-tag">${password.category}</span>` : ''}
                        </div>
                    </div>
                    <div class="password-actions">
                        <button class="btn-icon copy-btn" data-id="${password._id}" title="Copy Password">
                            📋
                        </button>
                        <button class="btn-icon btn-danger delete-btn" data-id="${password._id}" title="Delete">
                            🗑️
                        </button>
                    </div>
                </div>
                ${password.notes ? `<p class="password-notes">${this.escapeHtml(password.notes)}</p>` : ''}
                <div class="password-meta">
                    <small>Created: ${new Date(password.createdAt).toLocaleDateString()}</small>
                    ${password.lastAccessed ? `<small>Last accessed: ${new Date(password.lastAccessed).toLocaleDateString()}</small>` : ''}
                </div>
            </div>
        `).join('');
        
        // Attach event listeners to checkboxes
        const checkboxes = document.querySelectorAll('.password-checkbox');
        checkboxes.forEach(checkbox => {
            checkbox.addEventListener('change', (e) => {
                const passwordId = e.target.value;
                const isSelected = e.target.checked;
                this.handlePasswordSelection(passwordId, isSelected);
            });
        });
        
        // Attach event listeners to copy buttons
        const copyButtons = document.querySelectorAll('.copy-btn');
        copyButtons.forEach(button => {
            button.addEventListener('click', (e) => {
                const passwordId = e.target.getAttribute('data-id');
                this.copyPassword(passwordId);
            });
        });
        
        // Attach event listeners to delete buttons
        const deleteButtons = document.querySelectorAll('.delete-btn');
        deleteButtons.forEach(button => {
            button.addEventListener('click', (e) => {
                const passwordId = e.target.getAttribute('data-id');
                this.deletePassword(passwordId);
            });
        });
        
        this.updateSelectionUI();
    }

    handlePasswordSelection(passwordId, isSelected) {
        if (isSelected) {
            this.selectedPasswords.add(passwordId);
        } else {
            this.selectedPasswords.delete(passwordId);
        }
        this.updateSelectionUI();
        this.updateDeleteButtonsState();
    }

    updateDeleteButtonsState() {
        const deleteButtons = document.querySelectorAll('.delete-btn');
        const disable = this.selectedPasswords.size > 0;
        deleteButtons.forEach(button => {
            button.disabled = disable;
            if (disable) {
                button.classList.add('btn-disabled');
                button.style.pointerEvents = 'auto'; // Allow hover to show cursor
                button.style.cursor = 'not-allowed';
                button.title = '🚫 Cannot delete individual items when bulk selection is active';
                button.setAttribute('data-disabled', 'true');
            } else {
                button.classList.remove('btn-disabled');
                button.style.pointerEvents = 'auto';
                button.style.cursor = 'pointer';
                button.title = 'Delete';
                button.removeAttribute('data-disabled');
            }
        });
    }

    handleSelectAll() {
        const checkboxes = document.querySelectorAll('.password-checkbox');
        const allSelected = this.selectedPasswords.size === this.passwords.length;
        
        if (allSelected) {
            // Deselect all
            this.selectedPasswords.clear();
            checkboxes.forEach(cb => cb.checked = false);
        } else {
            // Select all
            this.passwords.forEach(password => this.selectedPasswords.add(password._id));
            checkboxes.forEach(cb => cb.checked = true);
        }
        
        this.updateSelectionUI();
    }

    updateSelectionUI() {
        const selectAllBtn = document.getElementById('selectAllBtn');
        const deleteSelectedBtn = document.getElementById('deleteSelectedBtn');
        
        if (selectAllBtn) {
            if (this.passwords.length === 0) {
                selectAllBtn.disabled = true;
                selectAllBtn.textContent = 'Select All';
            } else {
                selectAllBtn.disabled = false;
                selectAllBtn.textContent = this.selectedPasswords.size === this.passwords.length ? 'Deselect All' : 'Select All';
            }
        }
        
        if (deleteSelectedBtn) {
            deleteSelectedBtn.disabled = this.selectedPasswords.size === 0;
            deleteSelectedBtn.textContent = `Delete Selected (${this.selectedPasswords.size})`;
        }
    }

    handleSearch(searchTerm) {
        const filteredPasswords = this.passwords.filter(password => 
            password.website.toLowerCase().includes(searchTerm.toLowerCase()) ||
            password.username.toLowerCase().includes(searchTerm.toLowerCase())
        );
        this.renderFilteredPasswordList(filteredPasswords);
    }

    renderFilteredPasswordList(passwords) {
        const passwordList = document.getElementById('passwordList');
        
        if (passwords.length === 0) {
            passwordList.innerHTML = `
                <div class="empty-state">
                    <h3>No passwords found</h3>
                    <p>Try adjusting your search terms.</p>
                </div>
            `;
            return;
        }
        
        passwordList.innerHTML = passwords.map(password => `
            <div class="password-item" data-id="${password._id}">
                <div class="password-header">
                    <div class="password-info">
                        <input type="checkbox" class="password-checkbox" value="${password._id}">
                        <div class="password-details">
                            <h4>${this.escapeHtml(password.website)}</h4>
                            <p class="username">${this.escapeHtml(password.username)}</p>
                        </div>
                    </div>
                    <div class="password-actions">
                        <button class="btn-icon copy-btn" data-id="${password._id}" title="Copy Password">
                            📋
                        </button>
                        <button class="btn-icon btn-danger delete-btn" data-id="${password._id}" title="Delete">
                            🗑️
                        </button>
                    </div>
                </div>
                <div class="password-meta">
                    <small>Created: ${new Date(password.createdAt).toLocaleDateString()}</small>
                </div>
            </div>
        `).join('');
        
        // Attach event listeners to checkboxes
        const checkboxes = document.querySelectorAll('.password-checkbox');
        checkboxes.forEach(checkbox => {
            checkbox.addEventListener('change', (e) => {
                const passwordId = e.target.value;
                const isSelected = e.target.checked;
                this.handlePasswordSelection(passwordId, isSelected);
            });
        });
        
        // Attach event listeners to copy buttons
        const copyButtons = document.querySelectorAll('.copy-btn');
        copyButtons.forEach(button => {
            button.addEventListener('click', (e) => {
                const passwordId = e.target.getAttribute('data-id');
                this.copyPassword(passwordId);
            });
        });
        
        // Attach event listeners to delete buttons
        const deleteButtons = document.querySelectorAll('.delete-btn');
        deleteButtons.forEach(button => {
            button.addEventListener('click', (e) => {
                const passwordId = e.target.getAttribute('data-id');
                this.deletePassword(passwordId);
            });
        });
    }

    async copyPassword(passwordId) {
        try {
            // First try to find the password in the local array
            let password = this.passwords.find(p => p._id === passwordId);
            
            // If not found locally, fetch it from the server
            if (!password) {
                const response = await this.apiCall(`/passwords/${passwordId}`);
                if (response.success) {
                    password = response.data.password;
                }
            }
            
            if (password) {
                // Extract the actual password value
                let passwordValue;
                if (typeof password === 'string') {
                    // Already a string, use directly
                    passwordValue = password;
                } else if (password.password && typeof password.password === 'string') {
                    // New structure with decrypted password included
                    passwordValue = password.password;
                } else {
                    // Fallback for other structures
                    passwordValue = password.password || JSON.stringify(password);
                }
                
                // Copy to clipboard
                await navigator.clipboard.writeText(passwordValue);
                this.showSuccess('Password copied to clipboard!');
            }
        } catch (error) {
            console.error('Failed to copy password:', error);
            this.showError('passwordError', 'Failed to copy password.');
        }
    }

    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }

    // UI Navigation Methods
    showAuthForm() {
        document.getElementById('auth-container').style.display = 'flex';
        document.getElementById('app-container').classList.add('hidden');
        document.getElementById('delete-account-page').style.display = 'none';
        this.showLoginForm();
    }

    showLoginForm() {
        document.getElementById('login-form').style.display = 'block';
        document.getElementById('register-form').style.display = 'none';
        document.getElementById('forgot-password-form').style.display = 'none';
        this.clearAllErrors();
    }

    showRegisterForm() {
        document.getElementById('login-form').style.display = 'none';
        document.getElementById('register-form').style.display = 'block';
        document.getElementById('forgot-password-form').style.display = 'none';
        this.clearAllErrors();
    }

    showForgotPasswordForm() {
        document.getElementById('login-form').style.display = 'none';
        document.getElementById('register-form').style.display = 'none';
        document.getElementById('forgot-password-form').style.display = 'block';
        this.clearAllErrors();
    }

    async showPasswordManager() {
        document.getElementById('auth-container').style.display = 'none';
        document.getElementById('app-container').classList.remove('hidden');
        document.getElementById('delete-account-page').style.display = 'none';
        
        // Update user info in header
        if (this.currentUser) {
            const currentUserElement = document.getElementById('currentUser');
            const currentUserEmailElement = document.getElementById('currentUserEmail');
            if (currentUserElement) currentUserElement.textContent = this.currentUser.username;
            if (currentUserEmailElement) currentUserEmailElement.textContent = this.currentUser.email;
        }
        
        // Load passwords
        await this.loadPasswords();
    }

    showDeleteAccountPage() {
        document.getElementById('auth-container').style.display = 'none';
        document.getElementById('app-container').classList.add('hidden');
        document.getElementById('delete-account-page').style.display = 'flex';
        this.clearAllErrors();
    }
}

// Initialize the application when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    window.app = new SecureVaultApp();
});