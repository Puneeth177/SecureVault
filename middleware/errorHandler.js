const mongoose = require('mongoose');

/**
 * Global error handling middleware
 */
const errorHandler = (err, req, res, next) => {
    let error = { ...err };
    error.message = err.message;
    
    // Log error for debugging
    console.error('Error:', err);
    
    // Mongoose bad ObjectId
    if (err.name === 'CastError') {
        const message = 'Invalid resource ID';
        error = {
            message,
            statusCode: 400
        };
    }
    
    // Mongoose duplicate key
    if (err.code === 11000) {
        let message = 'Duplicate field value entered';
        
        // Extract field name from error
        const field = Object.keys(err.keyValue)[0];
        if (field === 'email') {
            message = 'Email address is already registered';
        } else if (field === 'username') {
            message = 'Username is already taken';
        }
        
        error = {
            message,
            statusCode: 400
        };
    }
    
    // Mongoose validation error
    if (err.name === 'ValidationError') {
        const message = Object.values(err.errors).map(val => val.message).join(', ');
        error = {
            message,
            statusCode: 400
        };
    }
    
    // JWT errors
    if (err.name === 'JsonWebTokenError') {
        error = {
            message: 'Invalid token',
            statusCode: 401
        };
    }
    
    if (err.name === 'TokenExpiredError') {
        error = {
            message: 'Token expired',
            statusCode: 401
        };
    }
    
    // Rate limiting errors
    if (err.status === 429) {
        error = {
            message: 'Too many requests, please try again later',
            statusCode: 429
        };
    }
    
    // Default to 500 server error
    const statusCode = error.statusCode || 500;
    const message = error.message || 'Internal Server Error';
    
    res.status(statusCode).json({
        success: false,
        message,
        ...(process.env.NODE_ENV === 'development' && {
            stack: err.stack,
            error: err
        })
    });
};

/**
 * Handle async errors
 */
const asyncHandler = (fn) => (req, res, next) => {
    Promise.resolve(fn(req, res, next)).catch(next);
};

/**
 * Handle 404 errors
 */
const notFound = (req, res, next) => {
    const error = new Error(`Not found - ${req.originalUrl}`);
    res.status(404);
    next(error);
};

/**
 * Validation error formatter
 */
const formatValidationErrors = (errors) => {
    return errors.array().map(error => ({
        field: error.param,
        message: error.msg,
        value: error.value
    }));
};

module.exports = {
    errorHandler,
    asyncHandler,
    notFound,
    formatValidationErrors
};