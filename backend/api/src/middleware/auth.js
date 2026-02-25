// ============================================================
// NHI SHIELD — Authentication & Authorization Middleware
// ============================================================
const jwt = require('jsonwebtoken');
const { isTokenBlacklisted } = require('../services/redis');
const { query } = require('../services/db');
const logger = require('../services/logger');
const { AppError } = require('../utils/errors');

// ── JWT Verification ──────────────────────────────────────────
const authenticate = async (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        throw new AppError('Authentication required', 401, 'NO_TOKEN');
    }

    const token = authHeader.substring(7); // Remove "Bearer " prefix

    // Check if token was explicitly blacklisted (logout)
    const blacklisted = await isTokenBlacklisted(token);
    if (blacklisted) {
        throw new AppError('Token has been revoked', 401, 'TOKEN_REVOKED');
    }

    // Verify signature and expiry
    let payload;
    try {
        payload = jwt.verify(token, process.env.JWT_SECRET);
    } catch (err) {
        if (err.name === 'TokenExpiredError') {
            throw new AppError('Token has expired', 401, 'TOKEN_EXPIRED');
        }
        throw new AppError('Invalid token', 401, 'TOKEN_INVALID');
    }

    // Load current user from DB (catches deactivated accounts)
    const result = await query(
        'SELECT id, org_id, email, role, is_active FROM users WHERE id = $1',
        [payload.userId]
    );

    if (result.rows.length === 0 || !result.rows[0].is_active) {
        throw new AppError('User account not found or deactivated', 401, 'USER_NOT_FOUND');
    }

    req.user = result.rows[0];
    req.token = token;  // Stored for logout use
    next();
};

// ── Role-Based Access Control ─────────────────────────────────
// Usage: requireRole('admin') or requireRole(['admin', 'analyst'])
const requireRole = (roles) => {
    const allowedRoles = Array.isArray(roles) ? roles : [roles];
    return (req, res, next) => {
        if (!req.user) {
            throw new AppError('Authentication required', 401, 'NOT_AUTHENTICATED');
        }
        if (!allowedRoles.includes(req.user.role)) {
            logger.warn('Unauthorized role access attempt', {
                userId: req.user.id,
                userRole: req.user.role,
                requiredRoles: allowedRoles,
                path: req.path,
            });
            throw new AppError(
                `This action requires one of these roles: ${allowedRoles.join(', ')}`,
                403,
                'INSUFFICIENT_PERMISSIONS'
            );
        }
        next();
    };
};

module.exports = { authenticate, requireRole };
