// ============================================================
// NHI SHIELD — Integrations Routes
// GET  /api/integrations
// POST /api/integrations
// DELETE /api/integrations/:platform
// POST /api/integrations/:platform/trigger-scan
// ============================================================
const express = require('express');
const Joi = require('joi');
const { query } = require('../services/db');
const { publishEvent } = require('../services/redis');
const { authenticate, requireRole } = require('../middleware/auth');
const { encrypt, decrypt } = require('../services/vault');
const { NotFoundError, ValidationError } = require('../utils/errors');
const logger = require('../services/logger');

const router = express.Router();
router.use(authenticate);

const SUPPORTED_PLATFORMS = ['github', 'aws', 'openai', 'slack', 'google', 'azure'];

// GET /api/integrations — list all for this org
router.get('/', async (req, res) => {
    const result = await query(
        `SELECT id, platform, is_active, last_sync, last_sync_count, created_at
         FROM integrations WHERE org_id = $1 ORDER BY platform`,
        [req.user.org_id]
    );
    // Never return credentials to the client
    res.json({ integrations: result.rows });
});

// POST /api/integrations — connect a new platform
router.post('/', requireRole('admin'), async (req, res) => {
    const { error, value } = Joi.object({
        platform: Joi.string().valid(...SUPPORTED_PLATFORMS).required(),
        credentials: Joi.object().required(), // Varies per platform
    }).validate(req.body, { stripUnknown: true });
    if (error) throw new ValidationError(error.details[0].message);

    const { platform, credentials } = value;

    // Encrypt credentials before storing
    const encryptedCredentials = encrypt(JSON.stringify(credentials));

    await query(
        `INSERT INTO integrations (org_id, platform, credentials, created_by)
         VALUES ($1, $2, $3, $4)
         ON CONFLICT (org_id, platform) DO UPDATE
         SET credentials = EXCLUDED.credentials, is_active = true`,
        [req.user.org_id, platform, encryptedCredentials, req.user.id]
    );

    await query(
        `INSERT INTO audit_logs (org_id, action, performed_by, new_state, ip_address)
         VALUES ($1, 'INTEGRATION_CONNECTED', $2, $3, $4)`,
        [req.user.org_id, req.user.id,
         JSON.stringify({ platform }), req.ip]
    );

    logger.info('Integration connected', { platform, orgId: req.user.org_id });

    // Trigger immediate discovery for the new integration
    await publishEvent('discovery:trigger', {
        orgId: req.user.org_id,
        platform,
        reason: 'new_integration',
    });

    res.status(201).json({ message: `${platform} integration connected. Discovery starting...` });
});

// DELETE /api/integrations/:platform
router.delete('/:platform', requireRole('admin'), async (req, res) => {
    const { platform } = req.params;
    const result = await query(
        'UPDATE integrations SET is_active = false WHERE org_id = $1 AND platform = $2 RETURNING id',
        [req.user.org_id, platform]
    );
    if (!result.rows[0]) throw new NotFoundError(`Integration for platform: ${platform}`);

    await query(
        `INSERT INTO audit_logs (org_id, action, performed_by, new_state, ip_address)
         VALUES ($1, 'INTEGRATION_DISCONNECTED', $2, $3, $4)`,
        [req.user.org_id, req.user.id, JSON.stringify({ platform }), req.ip]
    );

    res.json({ message: `${platform} integration disconnected` });
});

// POST /api/integrations/:platform/trigger-scan
router.post('/:platform/trigger-scan', requireRole(['admin', 'analyst']), async (req, res) => {
    const { platform } = req.params;
    await publishEvent('discovery:trigger', {
        orgId: req.user.org_id,
        platform,
        reason: 'manual_trigger',
    });
    res.json({ message: `Discovery scan triggered for ${platform}` });
});

module.exports = router;
