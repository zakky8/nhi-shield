// ============================================================
// NHI SHIELD — Auth Routes
// POST /api/auth/login
// POST /api/auth/logout
// POST /api/auth/refresh
// ============================================================
const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const Joi = require('joi');
const { rateLimit } = require('express-rate-limit');

const { query } = require('../services/db');
const {
    blacklistToken, incrementLoginAttempts,
    getLoginAttempts, clearLoginAttempts
} = require('../services/redis');
const { authenticate } = require('../middleware/auth');
const logger = require('../services/logger');
const { AppError, ValidationError } = require('../utils/errors');

const router = express.Router();

// Tight rate limit for auth endpoints only
const authRateLimit = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 10,
    keyGenerator: (req) => req.ip,
    standardHeaders: true,
    message: { error: 'Too many auth requests — try again in 15 minutes', code: 'RATE_LIMIT_EXCEEDED' },
});

// ── Input Validation Schemas ──────────────────────────────────
const loginSchema = Joi.object({
    email: Joi.string().email().max(255).required(),
    password: Joi.string().min(8).max(128).required(),
});

const refreshSchema = Joi.object({
    refreshToken: Joi.string().required(),
});

// ── Generate Token Pair ───────────────────────────────────────
function generateTokens(user) {
    const payload = { userId: user.id, orgId: user.org_id, role: user.role };

    const accessToken = jwt.sign(payload, process.env.JWT_SECRET, {
        expiresIn: '15m',
        issuer: 'nhi-shield',
        subject: user.id,
    });

    const refreshToken = jwt.sign(
        { userId: user.id, type: 'refresh' },
        process.env.JWT_SECRET,
        { expiresIn: '7d', issuer: 'nhi-shield' }
    );

    return { accessToken, refreshToken };
}

// ── POST /api/auth/login ──────────────────────────────────────
router.post('/login', authRateLimit, async (req, res) => {
    const { error, value } = loginSchema.validate(req.body, { stripUnknown: true });
    if (error) throw new ValidationError(error.details[0].message);

    const { email, password } = value;
    const ipKey = `${req.ip}:${email}`;

    // Check brute force lockout BEFORE querying the database
    const attempts = await getLoginAttempts(ipKey);
    if (attempts >= 5) {
        logger.warn('Login blocked — brute force protection', { ip: req.ip, email });
        throw new AppError(
            'Account temporarily locked after too many failed attempts. Try again in 15 minutes.',
            429,
            'ACCOUNT_LOCKED'
        );
    }

    // Find user (same error message for both cases to prevent email enumeration)
    const result = await query(
        'SELECT id, org_id, email, password_hash, role, is_active FROM users WHERE email = $1',
        [email.toLowerCase()]
    );

    const user = result.rows[0];
    const passwordMatch = user
        ? await bcrypt.compare(password, user.password_hash)
        : false; // Still run compare to prevent timing attacks

    if (!user || !passwordMatch || !user.is_active) {
        await incrementLoginAttempts(ipKey);
        const remaining = await getLoginAttempts(ipKey);

        logger.warn('Failed login attempt', { email, ip: req.ip, attempt: remaining });

        // Write to audit log
        await query(
            `INSERT INTO audit_logs (action, ip_address, new_state)
             VALUES ('LOGIN_FAILED', $1, $2)`,
            [req.ip, JSON.stringify({ email, reason: 'invalid_credentials' })]
        );

        throw new AppError('Invalid email or password', 401, 'INVALID_CREDENTIALS');
    }

    // Success — clear brute force counter
    await clearLoginAttempts(ipKey);

    const { accessToken, refreshToken } = generateTokens(user);

    // Update last login
    await query('UPDATE users SET last_login = NOW() WHERE id = $1', [user.id]);

    // Audit log
    await query(
        `INSERT INTO audit_logs (org_id, action, performed_by, ip_address, new_state)
         VALUES ($1, 'LOGIN_SUCCESS', $2, $3, $4)`,
        [user.org_id, user.id, req.ip, JSON.stringify({ email })]
    );

    logger.info('User logged in', { userId: user.id, email, role: user.role });

    res.json({
        accessToken,
        refreshToken,
        user: {
            id: user.id,
            email: user.email,
            role: user.role,
            orgId: user.org_id,
        },
    });
});

// ── POST /api/auth/logout ─────────────────────────────────────
router.post('/logout', authenticate, async (req, res) => {
    // Blacklist the current token until it would have expired
    // (15 min TTL matches token expiry)
    await blacklistToken(req.token, 15 * 60);

    await query(
        `INSERT INTO audit_logs (org_id, action, performed_by, ip_address)
         VALUES ($1, 'LOGOUT', $2, $3)`,
        [req.user.org_id, req.user.id, req.ip]
    );

    logger.info('User logged out', { userId: req.user.id });
    res.json({ message: 'Logged out successfully' });
});

// ── POST /api/auth/refresh ────────────────────────────────────
router.post('/refresh', async (req, res) => {
    const { error, value } = refreshSchema.validate(req.body);
    if (error) throw new ValidationError(error.details[0].message);

    let payload;
    try {
        payload = jwt.verify(value.refreshToken, process.env.JWT_SECRET);
    } catch {
        throw new AppError('Invalid or expired refresh token', 401, 'TOKEN_INVALID');
    }

    if (payload.type !== 'refresh') {
        throw new AppError('Invalid token type', 401, 'TOKEN_INVALID');
    }

    const result = await query(
        'SELECT id, org_id, email, role, is_active FROM users WHERE id = $1',
        [payload.userId]
    );

    if (!result.rows[0]?.is_active) {
        throw new AppError('User not found or deactivated', 401, 'USER_NOT_FOUND');
    }

    const { accessToken, refreshToken } = generateTokens(result.rows[0]);
    res.json({ accessToken, refreshToken });
});

module.exports = router;
