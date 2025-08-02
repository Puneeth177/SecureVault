# Overview

SecurePass is a client-side password manager built entirely with vanilla web technologies (HTML, CSS, JavaScript). It provides a complete authentication system with user registration and login, allowing multiple users to maintain separate password vaults. The application features a modern glassmorphism UI design and stores all data locally in the browser's localStorage, requiring no backend server or external dependencies.

# User Preferences

Preferred communication style: Simple, everyday language.

# System Architecture

## Frontend Architecture
- **Pure Vanilla Approach**: Built with vanilla HTML5, CSS3, and ES6+ JavaScript without any frameworks or libraries
- **Single Page Application**: Uses JavaScript to dynamically show/hide different views (authentication, password manager)
- **Component-Based Structure**: Organized around a main `SecurePass` class that handles all application logic
- **Event-Driven Architecture**: Uses event listeners for user interactions and form submissions

## Authentication System
- **Client-Side Authentication**: Username/password validation performed entirely in the browser
- **Multi-User Support**: Allows multiple users to create accounts and maintain separate password vaults
- **Session Persistence**: Maintains login state using localStorage to remember current user
- **Password Security**: Enforces strong password requirements with validation rules
- **Password Reset**: Forgot password functionality allowing users to reset their password with username verification

## Data Storage
- **localStorage API**: All user data and passwords stored in browser's localStorage
- **User Isolation**: Each user's passwords stored separately using username-based keys
- **Data Structure**: Users stored as objects with username/password pairs, passwords stored as arrays of objects
- **No External Database**: Completely offline solution requiring no server-side storage

## Security Features
- **XSS Protection**: HTML escaping implemented to prevent cross-site scripting attacks
- **Input Validation**: Client-side validation for all user inputs and password strength
- **Data Isolation**: User data compartmentalized to prevent cross-user access
- **Password Masking**: Passwords hidden by default with toggle visibility feature

## UI/UX Design
- **Glassmorphism Design**: Modern frosted glass aesthetic with transparency and blur effects
- **Responsive Layout**: CSS Grid and Flexbox for mobile-first responsive design
- **Dark Theme**: Gradient backgrounds with light text for modern appearance
- **Smooth Animations**: CSS transitions and transforms for interactive elements

## Core Features
- **Password Management**: Add, view, copy, and delete password entries
- **Duplicate Prevention**: Prevents saving duplicate passwords for same website and username combination
- **Bulk Operations**: Select multiple passwords for batch deletion
- **Clipboard Integration**: One-click copying using Navigator Clipboard API with fallback
- **Form Validation**: Real-time validation for registration and password entry forms
- **Responsive Grid Layout**: Displays passwords in two-column grid on desktop, single column on mobile

# External Dependencies

## Browser APIs
- **localStorage API**: For persistent data storage across browser sessions
- **Navigator Clipboard API**: For secure clipboard operations with document.execCommand fallback
- **DOM APIs**: Standard web APIs for element manipulation and event handling

## No External Services
- **No Backend Required**: Completely client-side application
- **No CDNs**: All CSS and JavaScript served locally
- **No Third-Party Libraries**: Pure vanilla implementation without frameworks
- **No Network Requests**: Operates entirely offline after initial page load