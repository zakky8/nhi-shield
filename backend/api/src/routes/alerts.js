// ============================================================
// NHI SHIELD — Alerts Routes
// ============================================================
const express = require('express');
const Joi = require('joi');
const { query } = require('../services/db');
const { authenticate, requireRole } = require('../middleware/auth');
const { NotFoundError, ValidationError, AppError } = require('../utils/errors');

const router = express.Router();
router.use(authenticate);

// GET /api/alerts
router.get('/', async (req, res) => {
    const { severity, resolved, identity_id, page, limit } = req.query;
    const pageNum = Math.max(1, parseInt(page || '1', 10));
    const pageLimit = Math.min(100, parseInt(limit || '20', 10));
    const offset = (pageNum - 1) * pageLimit;

    let conditions = ['a.org_id = $1'];
    let params = [req.user.org_id];
    let idx = 2;

    if (severity) { conditions.push(`a.severity = $${idx++}`); params.push(severity.toUpperCase()); }
    if (resolved !== undefined) { conditions.push(`a.resolved = $${idx++}`); params.push(resolved === 'true'); }
    if (identity_id) { conditions.push(`a.identity_id = $${idx++}`); params.push(identity_id); }

    const where = conditions.join(' AND ');

    const [data, count] = await Promise.all([
        query(
            `SELECT a.*, i.name AS identity_name, i.platform AS identity_platform
             FROM anomaly_alerts a
             LEFT JOIN identities i ON a.identity_id = i.id
             WHERE ${where}
             ORDER BY a.created_at DESC
             LIMIT $${idx} OFFSET $${idx + 1}`,
            [...params, pageLimit, offset]
        ),
        query(`SELECT COUNT(*) FROM anomaly_alerts a WHERE ${where}`, params),
    ]);

    res.json({
        alerts: data.rows,
        pagination: {
            total: parseInt(count.rows[0].count, 10),
            page: pageNum,
            limit: pageLimit,
        },
    });
});

// PATCH /api/alerts/:id/resolve
router.patch('/:id/resolve', requireRole(['admin', 'analyst']), async (req, res) => {
    const { id } = req.params;
    const { error, value } = Joi.object({
        resolution_note: Joi.string().max(500).optional(),
    }).validate(req.body);
    if (error) throw new ValidationError(error.details[0].message);

    const existing = await query(
        'SELECT id, resolved FROM anomaly_alerts WHERE id = $1 AND org_id = $2',
        [id, req.user.org_id]
    );
    if (!existing.rows[0]) throw new NotFoundError('Alert');
    if (existing.rows[0].resolved) throw new AppError('Alert is already resolved', 400, 'ALREADY_RESOLVED');

    await query(
        `UPDATE anomaly_alerts
         SET resolved = true, resolved_by = $1, resolved_at = NOW(), resolution_note = $2
         WHERE id = $3`,
        [req.user.id, value.resolution_note || null, id]
    );

    await query(
        `INSERT INTO audit_logs (org_id, action, performed_by, new_state, ip_address)
         VALUES ($1, 'ALERT_RESOLVED', $2, $3, $4)`,
        [req.user.org_id, req.user.id, JSON.stringify({ alert_id: id }), req.ip]
    );

    res.json({ message: 'Alert resolved' });
});

module.exports = router;
