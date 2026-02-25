// ============================================================
// NHI SHIELD — Reports Routes
// GET /api/reports/compliance
// GET /api/reports/audit
// ============================================================
const express = require('express');
const { rateLimit } = require('express-rate-limit');
const { query } = require('../services/db');
const { authenticate } = require('../middleware/auth');

const router = express.Router();
router.use(authenticate);

const reportRateLimit = rateLimit({
    windowMs: 60 * 60 * 1000,
    max: 5,
    keyGenerator: (req) => req.user.org_id,
    message: { error: 'Report generation limit: 5/hour', code: 'RATE_LIMIT_EXCEEDED' },
});

// GET /api/reports/compliance
router.get('/compliance', reportRateLimit, async (req, res) => {
    const orgId = req.user.org_id;

    const [summary, platforms, trend] = await Promise.all([
        // Overall numbers
        query(
            `SELECT
                COUNT(*) FILTER (WHERE is_active) AS active_identities,
                COUNT(*) FILTER (WHERE NOT is_active) AS inactive_identities,
                COUNT(*) FILTER (WHERE owner IS NULL AND is_active) AS unowned,
                COUNT(*) FILTER (WHERE last_used < NOW() - INTERVAL '90 days' AND is_active) AS dormant_90d,
                COUNT(*) FILTER (WHERE last_used < NOW() - INTERVAL '180 days' AND is_active) AS dormant_180d
             FROM identities WHERE org_id = $1`,
            [orgId]
        ),
        // Platform breakdown
        query(
            `SELECT
                i.platform,
                COUNT(*) FILTER (WHERE i.is_active) AS count,
                ROUND(AVG(rs.total_score)) AS avg_risk_score
             FROM identities i
             LEFT JOIN LATERAL (
                SELECT total_score FROM risk_scores WHERE identity_id = i.id
                ORDER BY calculated_at DESC LIMIT 1
             ) rs ON true
             WHERE i.org_id = $1
             GROUP BY i.platform ORDER BY count DESC`,
            [orgId]
        ),
        // Risk level distribution
        query(
            `SELECT rs.level, COUNT(*) AS count
             FROM identities i
             LEFT JOIN LATERAL (
                SELECT level FROM risk_scores WHERE identity_id = i.id
                ORDER BY calculated_at DESC LIMIT 1
             ) rs ON true
             WHERE i.org_id = $1 AND i.is_active = true
             GROUP BY rs.level`,
            [orgId]
        ),
    ]);

    const s = summary.rows[0];
    const totalActive = parseInt(s.active_identities, 10);

    // Compliance score: 100 minus penalties
    let complianceScore = 100;
    if (totalActive > 0) {
        const dormantRatio = parseInt(s.dormant_90d, 10) / totalActive;
        const unownedRatio = parseInt(s.unowned, 10) / totalActive;
        complianceScore = Math.max(0, Math.round(
            100 - (dormantRatio * 30) - (unownedRatio * 25)
        ));
    }

    await query(
        `INSERT INTO audit_logs (org_id, action, performed_by) VALUES ($1, 'REPORT_GENERATED', $2)`,
        [orgId, req.user.id]
    );

    res.json({
        generatedAt: new Date().toISOString(),
        complianceScore,
        summary: {
            activeIdentities: parseInt(s.active_identities, 10),
            inactiveIdentities: parseInt(s.inactive_identities, 10),
            unownedIdentities: parseInt(s.unowned, 10),
            dormant90Days: parseInt(s.dormant_90d, 10),
            dormant180Days: parseInt(s.dormant_180d, 10),
        },
        riskDistribution: trend.rows.reduce((acc, r) => {
            acc[r.level || 'UNKNOWN'] = parseInt(r.count, 10);
            return acc;
        }, { LOW: 0, MEDIUM: 0, HIGH: 0, CRITICAL: 0 }),
        platformBreakdown: platforms.rows,
    });
});

// GET /api/reports/audit
router.get('/audit', async (req, res) => {
    const { action, start_date, end_date, page, limit } = req.query;
    const pageNum = Math.max(1, parseInt(page || '1', 10));
    const pageLimit = Math.min(500, parseInt(limit || '50', 10));
    const offset = (pageNum - 1) * pageLimit;

    let conditions = ['org_id = $1'];
    let params = [req.user.org_id];
    let idx = 2;

    if (action) { conditions.push(`action = $${idx++}`); params.push(action.toUpperCase()); }
    if (start_date) { conditions.push(`created_at >= $${idx++}`); params.push(start_date); }
    if (end_date) { conditions.push(`created_at <= $${idx++}`); params.push(end_date); }

    const where = conditions.join(' AND ');
    const result = await query(
        `SELECT al.*, u.email AS performed_by_email
         FROM audit_logs al
         LEFT JOIN users u ON al.performed_by = u.id
         WHERE ${where}
         ORDER BY al.created_at DESC
         LIMIT $${idx} OFFSET $${idx + 1}`,
        [...params, pageLimit, offset]
    );

    res.json({ logs: result.rows, exportedAt: new Date().toISOString() });
});

module.exports = router;
