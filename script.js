// SecurePass Password Manager
// A beginner-friendly password manager with user authentication

class SecurePass {
    constructor() {
        this.currentUser = null;
        this.users = this.loadUsers();
        this.passwords = [];
        this.selectedPasswords = new Set();
        
        this.initializeApp();
    }

    // Initialize the application
    initializeApp() {
        this.bindEvents();
        this.checkAuthentication();
    }

    // Bind all event listeners
    bindEvents() {
        // Authentication events
        document.getElementById('loginForm').addEventListener('submit', (e) => this.handleLogin(e));
        document.getElementById('registerForm').addEventListener('submit', (e) => this.handleRegister(e));
        document.getElementById('forgotPasswordForm').addEventListener('submit', (e) => this.handleForgotPassword(e));
        document.getElementById('showRegister').addEventListener('click', () => this.showRegisterForm());
        document.getElementById('showLogin').addEventListener('click', () => this.showLoginForm());
        document.getElementById('showForgotPassword').addEventListener('click', () => this.showForgotPasswordForm());
        document.getElementById('backToLogin').addEventListener('click', () => this.showLoginForm());
        document.getElementById('logoutBtn').addEventListener('click', () => this.handleLogout());

        // Password management events
        document.getElementById('passwordForm').addEventListener('submit', (e) => this.handleAddPassword(e));
        document.getElementById('selectAllBtn').addEventListener('click', () => this.handleSelectAll());
        document.getElementById('deleteSelectedBtn').addEventListener('click', () => this.handleDeleteSelected());
    }

    // Check if user is already authenticated
    checkAuthentication() {
        const savedUser = localStorage.getItem('securepass_current_user');
        if (savedUser) {
            this.currentUser = savedUser;
            this.showPasswordManager();
        } else {
            this.showAuthForm();
        }
    }

    // Load users from localStorage
    loadUsers() {
        const users = localStorage.getItem('securepass_users');
        return users ? JSON.parse(users) : {};
    }

    // Save users to localStorage
    saveUsers() {
        localStorage.setItem('securepass_users', JSON.stringify(this.users));
    }

    // Load passwords for current user
    loadPasswords() {
        if (!this.currentUser) return [];
        
        const userPasswords = localStorage.getItem(`securepass_passwords_${this.currentUser}`);
        return userPasswords ? JSON.parse(userPasswords) : [];
    }

    // Save passwords for current user
    savePasswords() {
        if (!this.currentUser) return;
        
        localStorage.setItem(`securepass_passwords_${this.currentUser}`, JSON.stringify(this.passwords));
    }

    // Validate password strength
    validatePassword(password) {
        const minLength = 8;
        const hasUpperCase = /[A-Z]/.test(password);
        const hasLowerCase = /[a-z]/.test(password);
        const hasNumbers = /\d/.test(password);
        const hasSpecialChar = /[!@#$%^&*(),.?":{}|<>]/.test(password);

        const isValid = password.length >= minLength && hasUpperCase && hasLowerCase && hasNumbers && hasSpecialChar;
        
        if (!isValid) {
            return {
                valid: false,
                message: 'Password must be at least 8 characters long and contain uppercase, lowercase, numbers, and special characters.'
            };
        }
        
        return { valid: true };
    }

    // Handle user registration
    handleRegister(event) {
        event.preventDefault();
        
        const username = document.getElementById('registerUsername').value.trim();
        const password = document.getElementById('registerPassword').value;
        const confirmPassword = document.getElementById('confirmPassword').value;
        
        // Clear previous errors
        this.hideError('registerError');
        
        // Validate input
        if (!username || !password || !confirmPassword) {
            this.showError('registerError', 'Please fill in all fields.');
            return;
        }
        
        if (username.length < 3) {
            this.showError('registerError', 'Username must be at least 3 characters long.');
            return;
        }
        
        if (this.users[username]) {
            this.showError('registerError', 'Username already exists. Please choose a different username.');
            return;
        }
        
        if (password !== confirmPassword) {
            this.showError('registerError', 'Passwords do not match.');
            return;
        }
        
        const passwordValidation = this.validatePassword(password);
        if (!passwordValidation.valid) {
            this.showError('registerError', passwordValidation.message);
            return;
        }
        
        // Create new user
        this.users[username] = {
            password: password, // In a real app, this would be hashed
            createdAt: new Date().toISOString()
        };
        
        this.saveUsers();
        this.showSuccess('Registration successful! Please login with your credentials.');
        
        // Clear form and switch to login
        document.getElementById('registerForm').reset();
        setTimeout(() => this.showLoginForm(), 2000);
    }

    // Handle user login
    handleLogin(event) {
        event.preventDefault();
        
        const username = document.getElementById('loginUsername').value.trim();
        const password = document.getElementById('loginPassword').value;
        
        // Clear previous errors
        this.hideError('loginError');
        
        // Validate input
        if (!username || !password) {
            this.showError('loginError', 'Please fill in all fields.');
            return;
        }
        
        // Check credentials
        if (!this.users[username] || this.users[username].password !== password) {
            this.showError('loginError', 'Invalid username or password.');
            return;
        }
        
        // Set current user and save to localStorage
        this.currentUser = username;
        localStorage.setItem('securepass_current_user', username);
        
        // Load user's passwords and show password manager
        this.passwords = this.loadPasswords();
        this.showPasswordManager();
    }

    // Handle user logout
    handleLogout() {
        this.currentUser = null;
        this.passwords = [];
        this.selectedPasswords.clear();
        
        localStorage.removeItem('securepass_current_user');
        
        // Clear forms
        document.getElementById('loginForm').reset();
        document.getElementById('passwordForm').reset();
        
        this.showAuthForm();
    }

    // Handle adding new password
    handleAddPassword(event) {
        event.preventDefault();
        
        const websiteName = document.getElementById('websiteName').value.trim();
        const username = document.getElementById('username').value.trim();
        const password = document.getElementById('password').value.trim();
        
        // Clear previous errors
        this.hideError('passwordError');
        
        // Validate input
        if (!websiteName || !username || !password) {
            this.showError('passwordError', 'Please fill in all fields.');
            return;
        }
        
        // Check for duplicate entries (same website and username)
        const existingPassword = this.passwords.find(p => 
            p.website.toLowerCase() === websiteName.toLowerCase() && 
            p.username.toLowerCase() === username.toLowerCase()
        );
        
        if (existingPassword) {
            this.showError('passwordError', `A password for ${websiteName} with username ${username} already exists. Please update the existing entry or use a different username.`);
            return;
        }
        
        // Create new password entry
        const newPassword = {
            id: Date.now().toString(),
            website: websiteName,
            username: username,
            password: password,
            createdAt: new Date().toISOString()
        };
        
        // Add to passwords array
        this.passwords.unshift(newPassword);
        this.savePasswords();
        
        // Clear form and refresh display
        document.getElementById('passwordForm').reset();
        this.renderPasswordList();
        
        this.showSuccess('Password saved successfully!');
    }

    // Handle select all passwords
    handleSelectAll() {
        const selectAllBtn = document.getElementById('selectAllBtn');
        const checkboxes = document.querySelectorAll('.select-checkbox');
        
        if (this.selectedPasswords.size === this.passwords.length) {
            // Deselect all
            this.selectedPasswords.clear();
            checkboxes.forEach(checkbox => checkbox.checked = false);
            selectAllBtn.textContent = 'Select All';
        } else {
            // Select all
            this.selectedPasswords.clear();
            this.passwords.forEach(password => this.selectedPasswords.add(password.id));
            checkboxes.forEach(checkbox => checkbox.checked = true);
            selectAllBtn.textContent = 'Deselect All';
        }
        
        this.updateDeleteButton();
        this.updateSelectedItems();
    }

    // Handle delete selected passwords
    handleDeleteSelected() {
        if (this.selectedPasswords.size === 0) return;
        
        const count = this.selectedPasswords.size;
        const confirmation = confirm(`Are you sure you want to delete ${count} password${count > 1 ? 's' : ''}?`);
        
        if (confirmation) {
            // Remove selected passwords
            this.passwords = this.passwords.filter(password => !this.selectedPasswords.has(password.id));
            this.selectedPasswords.clear();
            
            this.savePasswords();
            this.renderPasswordList();
            
            this.showSuccess(`${count} password${count > 1 ? 's' : ''} deleted successfully!`);
        }
    }

    // Handle individual password deletion
    handleDeletePassword(passwordId) {
        const password = this.passwords.find(p => p.id === passwordId);
        if (!password) return;
        
        const confirmation = confirm(`Are you sure you want to delete the password for ${password.website}?`);
        
        if (confirmation) {
            this.passwords = this.passwords.filter(p => p.id !== passwordId);
            this.selectedPasswords.delete(passwordId);
            
            this.savePasswords();
            this.renderPasswordList();
            
            this.showSuccess('Password deleted successfully!');
        }
    }

    // Handle password selection
    handlePasswordSelection(passwordId, isSelected) {
        if (isSelected) {
            this.selectedPasswords.add(passwordId);
        } else {
            this.selectedPasswords.delete(passwordId);
        }
        
        this.updateDeleteButton();
        this.updateSelectAllButton();
        this.updateSelectedItems();
    }

    // Toggle password visibility
    togglePasswordVisibility(passwordId) {
        const passwordInput = document.querySelector(`[data-password-id="${passwordId}"]`);
        const toggleBtn = document.querySelector(`[data-toggle-id="${passwordId}"]`);
        
        if (passwordInput.type === 'password') {
            passwordInput.type = 'text';
            toggleBtn.textContent = '👁️‍🗨️';
            toggleBtn.title = 'Hide password';
        } else {
            passwordInput.type = 'password';
            toggleBtn.textContent = '👁️';
            toggleBtn.title = 'Show password';
        }
    }

    // Copy password to clipboard
    async copyToClipboard(password) {
        try {
            await navigator.clipboard.writeText(password);
            this.showSuccess('Password copied to clipboard!');
        } catch (err) {
            // Fallback for older browsers
            const textArea = document.createElement('textarea');
            textArea.value = password;
            document.body.appendChild(textArea);
            textArea.select();
            document.execCommand('copy');
            document.body.removeChild(textArea);
            this.showSuccess('Password copied to clipboard!');
        }
    }

    // Update delete button state
    updateDeleteButton() {
        const deleteBtn = document.getElementById('deleteSelectedBtn');
        deleteBtn.disabled = this.selectedPasswords.size === 0;
        deleteBtn.textContent = `Delete Selected (${this.selectedPasswords.size})`;
    }

    // Update select all button state
    updateSelectAllButton() {
        const selectAllBtn = document.getElementById('selectAllBtn');
        if (this.selectedPasswords.size === this.passwords.length && this.passwords.length > 0) {
            selectAllBtn.textContent = 'Deselect All';
        } else {
            selectAllBtn.textContent = 'Select All';
        }
    }

    // Update bulk operation buttons based on password count
    updateBulkOperationButtons() {
        const selectAllBtn = document.getElementById('selectAllBtn');
        const deleteSelectedBtn = document.getElementById('deleteSelectedBtn');
        
        if (this.passwords.length === 0) {
            selectAllBtn.disabled = true;
            deleteSelectedBtn.disabled = true;
            deleteSelectedBtn.textContent = 'Delete Selected (0)';
        } else {
            selectAllBtn.disabled = false;
            // deleteSelectedBtn state is handled by updateDeleteButton
        }
    }

    // Update selected item styling
    updateSelectedItems() {
        document.querySelectorAll('.password-item').forEach(item => {
            const checkbox = item.querySelector('.select-checkbox');
            if (checkbox && checkbox.checked) {
                item.classList.add('selected');
            } else {
                item.classList.remove('selected');
            }
        });
    }

    // Render the password list
    renderPasswordList() {
        const passwordList = document.getElementById('passwordList');
        
        if (this.passwords.length === 0) {
            passwordList.innerHTML = `
                <div class="empty-state">
                    <p>No passwords saved yet. Add your first password above!</p>
                </div>
            `;
            // Disable bulk operation buttons when no passwords exist
            this.updateBulkOperationButtons();
            return;
        }
        
        passwordList.innerHTML = this.passwords.map(password => `
            <div class="password-item" data-id="${password.id}">
                <div class="password-header">
                    <div class="password-info">
                        <h3>${this.escapeHtml(password.website)}</h3>
                        <p>${this.escapeHtml(password.username)}</p>
                    </div>
                    <div class="password-actions">
                        <input type="checkbox" class="select-checkbox" 
                               onchange="app.handlePasswordSelection('${password.id}', this.checked)">
                        <button class="icon-btn" onclick="app.handleDeletePassword('${password.id}')" title="Delete password">
                            🗑️
                        </button>
                    </div>
                </div>
                <div class="password-controls">
                    <div class="password-field">
                        <input type="password" class="password-input" 
                               value="${this.escapeHtml(password.password)}" 
                               data-password-id="${password.id}" readonly>
                        <button class="icon-btn" data-toggle-id="${password.id}" 
                                onclick="app.togglePasswordVisibility('${password.id}')" title="Show password">
                            👁️
                        </button>
                        <button class="icon-btn" 
                                onclick="app.copyToClipboard('${this.escapeHtml(password.password)}')" title="Copy password">
                            📋
                        </button>
                    </div>
                </div>
            </div>
        `).join('');
        
        // Update button states
        this.updateDeleteButton();
        this.updateSelectAllButton();
        this.updateBulkOperationButtons();
    }

    // Show authentication form
    showAuthForm() {
        document.getElementById('auth-container').style.display = 'flex';
        document.getElementById('app-container').classList.add('hidden');
    }

    // Show password manager
    showPasswordManager() {
        document.getElementById('auth-container').style.display = 'none';
        document.getElementById('app-container').classList.remove('hidden');
        document.getElementById('currentUser').textContent = this.currentUser;
        this.renderPasswordList();
        // Ensure bulk operation buttons are properly initialized
        this.updateBulkOperationButtons();
    }

    // Show login form
    showLoginForm() {
        document.getElementById('login-form').classList.add('active');
        document.getElementById('register-form').classList.remove('active');
        document.getElementById('forgot-password-form').classList.remove('active');
        this.hideError('registerError');
        this.hideError('forgotPasswordError');
    }

    // Handle forgot password
    handleForgotPassword(event) {
        event.preventDefault();
        
        const username = document.getElementById('forgotUsername').value.trim();
        const newPassword = document.getElementById('newPassword').value;
        const confirmNewPassword = document.getElementById('confirmNewPassword').value;
        
        // Clear previous errors
        this.hideError('forgotPasswordError');
        
        // Validate input
        if (!username || !newPassword || !confirmNewPassword) {
            this.showError('forgotPasswordError', 'Please fill in all fields.');
            return;
        }
        
        // Check if user exists
        if (!this.users[username]) {
            this.showError('forgotPasswordError', 'Username not found. Please check your username or register a new account.');
            return;
        }
        
        if (newPassword !== confirmNewPassword) {
            this.showError('forgotPasswordError', 'Passwords do not match.');
            return;
        }
        
        const passwordValidation = this.validatePassword(newPassword);
        if (!passwordValidation.valid) {
            this.showError('forgotPasswordError', passwordValidation.message);
            return;
        }
        
        // Update user's password
        this.users[username].password = newPassword;
        this.saveUsers();
        
        this.showSuccess('Password reset successfully! You can now login with your new password.');
        
        // Clear form and switch to login
        document.getElementById('forgotPasswordForm').reset();
        setTimeout(() => this.showLoginForm(), 2000);
    }

    // Show register form
    showRegisterForm() {
        document.getElementById('register-form').classList.add('active');
        document.getElementById('login-form').classList.remove('active');
        document.getElementById('forgot-password-form').classList.remove('active');
        this.hideError('loginError');
        this.hideError('forgotPasswordError');
    }
    
    // Show forgot password form
    showForgotPasswordForm() {
        document.getElementById('forgot-password-form').classList.add('active');
        document.getElementById('login-form').classList.remove('active');
        document.getElementById('register-form').classList.remove('active');
        this.hideError('loginError');
        this.hideError('registerError');
    }

    // Show error message
    showError(elementId, message) {
        const errorElement = document.getElementById(elementId);
        errorElement.textContent = message;
        errorElement.classList.add('show');
    }

    // Hide error message
    hideError(elementId) {
        const errorElement = document.getElementById(elementId);
        errorElement.classList.remove('show');
    }

    // Show success message
    showSuccess(message) {
        // Create and show new success message
        const successElement = document.createElement('div');
        successElement.className = 'success-message show';
        successElement.textContent = message;
        
        // Add to appropriate area
        if (document.getElementById('auth-container').style.display !== 'none') {
            // For authentication pages, add to active form
            const activeForm = document.querySelector('.auth-form.active .glass-card');
            if (activeForm) {
                // Remove any existing success messages in the form
                const existingSuccess = activeForm.querySelector('.success-message');
                if (existingSuccess) {
                    existingSuccess.remove();
                }
                activeForm.appendChild(successElement);
            }
        } else {
            // For main app, use fixed position success area
            const successArea = document.getElementById('successMessageArea');
            if (successArea) {
                successArea.appendChild(successElement);
            }
        }
        
        // Auto-hide after 3 seconds
        setTimeout(() => {
            successElement.classList.remove('show');
            setTimeout(() => successElement.remove(), 400);
        }, 3000);
    }

    // Escape HTML to prevent XSS
    escapeHtml(text) {
        const div = document.createElement('div');
        div.textContent = text;
        return div.innerHTML;
    }
}

// Initialize the application when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
    window.app = new SecurePass();
});

// Export for potential testing
if (typeof module !== 'undefined' && module.exports) {
    module.exports = SecurePass;
}
