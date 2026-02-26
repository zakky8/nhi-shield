// ============================================================
// NHI SHIELD — Identities Routes
// GET    /api/identities
// GET    /api/identities/:id
// POST   /api/identities/:id/offboard
// PUT    /api/identities/:id/owner
// ============================================================
const express = require('express');
const Joi = require('joi');
const { rateLimit } = require('express-rate-limit');

const { query } = require('../services/db');
const { publishEvent } = require('../services/redis');
const { authenticate, requireRole } = require('../middleware/auth');
const logger = require('../services/logger');
const { AppError, ValidationError, NotFoundError } = require('../utils/errors');

const router = express.Router();
router.use(authenticate);

// Rate limit for destructive actions
const offboardRateLimit = rateLimit({
    windowMs: 60 * 60 * 1000, // 1 hour
    max: 10,
    keyGenerator: (req) => req.user.id,
    message: { error: 'Too many offboard operations — limit 10/hour', code: 'RATE_LIMIT_EXCEEDED' },
});

// ── GET /api/identities ───────────────────────────────────────
// Returns paginated, filterable list of identities with risk scores
router.get('/', async (req, res) => {
    const { platform, risk_level, is_active, type, search, sort_by, page, limit } = req.query;

    const pageNum = Math.max(1, parseInt(page || '1', 10));
    const pageLimit = Math.min(100, Math.max(1, parseInt(limit || '20', 10)));
    const offset = (pageNum - 1) * pageLimit;

    const validSortFields = ['risk_score', 'created_at', 'last_used', 'name'];
    const sortField = validSortFields.includes(sort_by) ? sort_by : 'risk_score';

    // Build query dynamically based on filters
    let conditions = ['i.org_id = $1'];
    let params = [req.user.org_id];
    let paramIdx = 2;

    if (platform) { conditions.push(`i.platform = $${paramIdx++}`); params.push(platform); }
    if (type) { conditions.push(`i.type = $${paramIdx++}`); params.push(type); }
    if (is_active !== undefined) {
        conditions.push(`i.is_active = $${paramIdx++}`);
        params.push(is_active === 'true');
    }
    if (risk_level) { conditions.push(`rs.level = $${paramIdx++}`); params.push(risk_level.toUpperCase()); }
    if (search) {
        conditions.push(`i.name ILIKE $${paramIdx++}`);
        params.push(`%${search}%`);
    }

    const whereClause = conditions.join(' AND ');

    const sortMap = {
        risk_score: 'rs.total_score DESC NULLS LAST',
        created_at: 'i.created_at DESC',
        last_used: 'i.last_used DESC NULLS LAST',
        name: 'i.name ASC',
    };

    const dataQuery = `
        SELECT
            i.id, i.name, i.platform, i.type, i.permissions,
            i.owner, i.is_active, i.created_at, i.last_used,
            i.discovered_at, i.metadata,
            rs.total_score AS risk_score,
            rs.level AS risk_level,
            rs.calculated_at AS risk_updated_at
        FROM identities i
        LEFT JOIN LATERAL (
            SELECT total_score, level, calculated_at
            FROM risk_scores WHERE identity_id = i.id
            ORDER BY calculated_at DESC LIMIT 1
        ) rs ON true
        WHERE ${whereClause}
        ORDER BY ${sortMap[sortField]}
        LIMIT $${paramIdx} OFFSET $${paramIdx + 1}
    `;

    const countQuery = `
        SELECT COUNT(*) as total
        FROM identities i
        LEFT JOIN LATERAL (
            SELECT level FROM risk_scores WHERE identity_id = i.id
            ORDER BY calculated_at DESC LIMIT 1
        ) rs ON true
        WHERE ${whereClause}
    `;

    const [dataResult, countResult] = await Promise.all([
        query(dataQuery, [...params, pageLimit, offset]),
        query(countQuery, params),
    ]);

    const total = parseInt(countResult.rows[0].total, 10);

    res.json({
        identities: dataResult.rows,
        pagination: {
            total,
            page: pageNum,
            limit: pageLimit,
            pages: Math.ceil(total / pageLimit),
        },
    });
});

// ── GET /api/identities/:id ───────────────────────────────────
// Full identity details with risk factors + recent alerts
router.get('/:id', async (req, res) => {
    const { id } = req.params;

    const result = await query(
        `SELECT i.*, rs.total_score AS risk_score, rs.level AS risk_level,
                rs.factors AS risk_factors, rs.recommendations AS risk_recommendations,
                rs.calculated_at AS risk_updated_at
         FROM identities i
         LEFT JOIN LATERAL (
             SELECT * FROM risk_scores WHERE identity_id = i.id
             ORDER BY calculated_at DESC LIMIT 1
         ) rs ON true
         WHERE i.id = $1 AND i.org_id = $2`,
        [id, req.user.org_id]
    );

    if (!result.rows[0]) throw new NotFoundError('Identity');

    // Get last 5 alerts
    const alertsResult = await query(
        `SELECT id, severity, type, description, confidence, created_at, resolved
         FROM anomaly_alerts
         WHERE identity_id = $1
         ORDER BY created_at DESC LIMIT 5`,
        [id]
    );

    res.json({
        identity: result.rows[0],
        recentAlerts: alertsResult.rows,
    });
});

// ── POST /api/identities/:id/offboard ─────────────────────────
// Admin only — deactivates an identity and triggers platform handlers
router.post('/:id/offboard', requireRole('admin'), offboardRateLimit, async (req, res) => {
    const { id } = req.params;

    const { error, value } = Joi.object({
        reason: Joi.string().min(10).max(500).required(),
    }).validate(req.body);
    if (error) throw new ValidationError('A reason of at least 10 characters is required to offboard an identity');

    const { reason } = value;

    // Confirm identity exists and belongs to this org
    const existing = await query(
        'SELECT id, name, platform, is_active FROM identities WHERE id = $1 AND org_id = $2',
        [id, req.user.org_id]
    );
    if (!existing.rows[0]) throw new NotFoundError('Identity');
    if (!existing.rows[0].is_active) throw new AppError('Identity is already offboarded', 400, 'ALREADY_INACTIVE');

    const identity = existing.rows[0];

    // Update identity status and write audit log in a transaction
    await query('BEGIN');
    try {
        await query(
            `UPDATE identities
             SET is_active = false, offboarded_at = NOW(), offboarded_by = $1
             WHERE id = $2`,
            [req.user.id, id]
        );

        await query(
            `INSERT INTO audit_logs
             (org_id, identity_id, action, performed_by, reason, old_state, new_state, ip_address)
             VALUES ($1, $2, 'IDENTITY_OFFBOARDED', $3, $4, $5, $6, $7)`,
            [
                req.user.org_id, id, req.user.id, reason,
                JSON.stringify({ is_active: true }),
                JSON.stringify({ is_active: false, offboarded_by: req.user.id }),
                req.ip,
            ]
        );

        await query('COMMIT');
    } catch (err) {
        await query('ROLLBACK');
        throw err;
    }

    // Notify other services (e.g., integration handlers that may revoke on platform)
    await publishEvent(`offboard:${req.user.org_id}`, {
        identityId: id,
        platform: identity.platform,
        name: identity.name,
        offboardedBy: req.user.id,
        reason,
        timestamp: new Date().toISOString(),
    });

    logger.info('Identity offboarded', { identityId: id, by: req.user.id, name: identity.name });

    res.json({ message: `Identity "${identity.name}" has been offboarded successfully` });
});

// ── PUT /api/identities/:id/owner ─────────────────────────────
// Assign or change owner of an identity
router.put('/:id/owner', requireRole(['admin', 'analyst']), async (req, res) => {
    const { id } = req.params;
    const { error, value } = Joi.object({
        owner: Joi.string().email().max(255).allow(null).required(),
    }).validate(req.body);
    if (error) throw new ValidationError(error.details[0].message);

    const existing = await query(
        'SELECT id, name, owner FROM identities WHERE id = $1 AND org_id = $2',
        [id, req.user.org_id]
    );
    if (!existing.rows[0]) throw new NotFoundError('Identity');

    const oldOwner = existing.rows[0].owner;

    await query('UPDATE identities SET owner = $1 WHERE id = $2', [value.owner, id]);

    await query(
        `INSERT INTO audit_logs
         (org_id, identity_id, action, performed_by, old_state, new_state, ip_address)
         VALUES ($1, $2, 'OWNER_CHANGED', $3, $4, $5, $6)`,
        [req.user.org_id, id, req.user.id,
         JSON.stringify({ owner: oldOwner }),
         JSON.stringify({ owner: value.owner }),
         req.ip]
    );

    res.json({
        message: `Owner updated from "${oldOwner || 'unassigned'}" to "${value.owner || 'unassigned'}"`,
        owner: value.owner,
    });
});

module.exports = router;
