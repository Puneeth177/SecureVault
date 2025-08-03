const fs = require('fs').promises;
const path = require('path');

/**
 * Security Event Logger and Monitor
 */
class SecurityMonitor {
    constructor() {
        this.logFile = path.join(__dirname, '../logs/security.log');
        this.alertThresholds = {
            failedLogins: parseInt(process.env.ALERT_THRESHOLD_FAILED_LOGINS) || 10,
            suspiciousRequests: 5,
            bruteForceAttempts: 3
        };
        this.eventCounts = new Map();
        this.ensureLogDirectory();
    }

    async ensureLogDirectory() {
        try {
            const logDir = path.dirname(this.logFile);
            await fs.mkdir(logDir, { recursive: true });
        } catch (error) {
            console.error('Failed to create log directory:', error);
        }
    }

    /**
     * Log security events
     */
    async logEvent(eventType, details) {
        const timestamp = new Date().toISOString();
        const logEntry = {
            timestamp,
            eventType,
            details,
            severity: this.getSeverity(eventType)
        };

        try {
            const logLine = JSON.stringify(logEntry) + '\n';
            await fs.appendFile(this.logFile, logLine);
            
            // Check if we need to send alerts
            this.checkAlertThresholds(eventType, details);
            
        } catch (error) {
            console.error('Failed to write security log:', error);
        }
    }

    /**
     * Get severity level for event types
     */
    getSeverity(eventType) {
        const severityMap = {
            'failed_login': 'medium',
            'account_locked': 'high',
            'brute_force_attempt': 'high',
            'suspicious_request': 'medium',
            'sql_injection_attempt': 'critical',
            'xss_attempt': 'high',
            'admin_action': 'low',
            'password_reset': 'medium',
            'account_deletion': 'high',
            'unauthorized_access': 'critical'
        };
        return severityMap[eventType] || 'low';
    }

    /**
     * Check if alert thresholds are exceeded
     */
    checkAlertThresholds(eventType, details) {
        const key = `${eventType}_${details.ip || 'unknown'}`;
        const count = (this.eventCounts.get(key) || 0) + 1;
        this.eventCounts.set(key, count);

        // Reset counts every hour
        setTimeout(() => {
            this.eventCounts.delete(key);
        }, 60 * 60 * 1000);

        // Check thresholds
        if (eventType === 'failed_login' && count >= this.alertThresholds.failedLogins) {
            this.sendAlert('HIGH_FAILED_LOGIN_RATE', {
                ip: details.ip,
                count,
                timeframe: '1 hour'
            });
        }

        if (eventType === 'brute_force_attempt' && count >= this.alertThresholds.bruteForceAttempts) {
            this.sendAlert('BRUTE_FORCE_DETECTED', {
                ip: details.ip,
                count,
                target: details.target
            });
        }
    }

    /**
     * Send security alerts (can be extended to email, Slack, etc.)
     */
    async sendAlert(alertType, details) {
        const alert = {
            timestamp: new Date().toISOString(),
            alertType,
            details,
            severity: 'CRITICAL'
        };

        console.error('🚨 SECURITY ALERT:', JSON.stringify(alert, null, 2));
        
        // Log the alert
        await this.logEvent('security_alert', alert);
        
        // Here you can add integrations with:
        // - Email notifications
        // - Slack webhooks
        // - SMS alerts
        // - External monitoring systems
    }

    /**
     * Get recent security events
     */
    async getRecentEvents(hours = 24, eventType = null) {
        try {
            const logContent = await fs.readFile(this.logFile, 'utf8');
            const lines = logContent.trim().split('\n').filter(line => line);
            const events = lines.map(line => JSON.parse(line));
            
            const cutoffTime = new Date(Date.now() - (hours * 60 * 60 * 1000));
            
            return events
                .filter(event => new Date(event.timestamp) > cutoffTime)
                .filter(event => !eventType || event.eventType === eventType)
                .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
                
        } catch (error) {
            console.error('Failed to read security log:', error);
            return [];
        }
    }

    /**
     * Get security statistics
     */
    async getSecurityStats(hours = 24) {
        const events = await this.getRecentEvents(hours);
        
        const stats = {
            totalEvents: events.length,
            eventsByType: {},
            eventsBySeverity: {},
            topIPs: {},
            timeframe: `${hours} hours`
        };

        events.forEach(event => {
            // Count by type
            stats.eventsByType[event.eventType] = (stats.eventsByType[event.eventType] || 0) + 1;
            
            // Count by severity
            stats.eventsBySeverity[event.severity] = (stats.eventsBySeverity[event.severity] || 0) + 1;
            
            // Count by IP
            const ip = event.details?.ip || 'unknown';
            stats.topIPs[ip] = (stats.topIPs[ip] || 0) + 1;
        });

        // Sort top IPs
        stats.topIPs = Object.entries(stats.topIPs)
            .sort(([,a], [,b]) => b - a)
            .slice(0, 10)
            .reduce((obj, [ip, count]) => ({ ...obj, [ip]: count }), {});

        return stats;
    }

    /**
     * Clean old log files
     */
    async cleanOldLogs(daysToKeep = 30) {
        try {
            const events = await this.getRecentEvents(daysToKeep * 24);
            const newLogContent = events.map(event => JSON.stringify(event)).join('\n') + '\n';
            await fs.writeFile(this.logFile, newLogContent);
            console.log(`🧹 Cleaned security logs, kept ${events.length} events from last ${daysToKeep} days`);
        } catch (error) {
            console.error('Failed to clean old logs:', error);
        }
    }
}

// Create singleton instance
const securityMonitor = new SecurityMonitor();

// Helper functions for easy use
const logSecurityEvent = (eventType, details) => {
    return securityMonitor.logEvent(eventType, details);
};

const getSecurityStats = (hours = 24) => {
    return securityMonitor.getSecurityStats(hours);
};

const getRecentEvents = (hours = 24, eventType = null) => {
    return securityMonitor.getRecentEvents(hours, eventType);
};

module.exports = {
    SecurityMonitor,
    securityMonitor,
    logSecurityEvent,
    getSecurityStats,
    getRecentEvents
};