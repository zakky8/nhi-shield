// ============================================================
// NHI SHIELD — API Server Entry Point
// ============================================================
require('dotenv').config();
require('express-async-errors'); // Makes async errors propagate correctly

const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const { rateLimit } = require('express-rate-limit');

const logger = require('./services/logger');
const { connectDB, disconnectDB } = require('./services/db');
const { connectRedis, disconnectRedis } = require('./services/redis');
const { connectNeo4j, disconnectNeo4j } = require('./services/neo4j');

// Routes
const authRoutes = require('./routes/auth');
const identityRoutes = require('./routes/identities');
const alertRoutes = require('./routes/alerts');
const integrationRoutes = require('./routes/integrations');
const reportRoutes = require('./routes/reports');
const graphRoutes = require('./routes/graph');

const app = express();
const PORT = process.env.PORT || 3000;

// ── Security Headers ─────────────────────────────────────────
app.use(helmet({
    contentSecurityPolicy: {
        directives: {
            defaultSrc: ["'self'"],
            styleSrc: ["'self'", "'unsafe-inline'"],
            scriptSrc: ["'self'"],
            imgSrc: ["'self'", 'data:'],
        },
    },
    hsts: {
        maxAge: 31536000,
        includeSubDomains: true,
        preload: true,
    },
}));

// ── CORS ─────────────────────────────────────────────────────
app.use(cors({
    origin: process.env.ALLOWED_ORIGINS?.split(',') || ['http://localhost:3001'],
    credentials: true,
    methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'],
    allowedHeaders: ['Content-Type', 'Authorization'],
}));

// ── Body Parsing (limit request size to prevent DoS) ─────────
app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true, limit: '1mb' }));

// ── Global Rate Limiter (generous — per-route limits are tighter) ──
app.use(rateLimit({
    windowMs: 15 * 60 * 1000,  // 15 minutes
    max: 500,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: 'Too many requests', code: 'RATE_LIMIT_EXCEEDED' },
}));

// ── Request Logging ──────────────────────────────────────────
app.use((req, res, next) => {
    const start = Date.now();
    res.on('finish', () => {
        const duration = Date.now() - start;
        logger.http(`${req.method} ${req.path}`, {
            status: res.statusCode,
            duration: `${duration}ms`,
            ip: req.ip,
            userAgent: req.get('User-Agent'),
            userId: req.user?.id || null,
        });
    });
    next();
});

// ── Health Check (no auth required) ─────────────────────────
app.get('/health', async (req, res) => {
    res.json({
        status: 'ok',
        timestamp: new Date().toISOString(),
        version: '1.0.0',
        uptime: process.uptime(),
    });
});

// ── API Routes ───────────────────────────────────────────────
app.use('/api/auth', authRoutes);
app.use('/api/identities', identityRoutes);
app.use('/api/alerts', alertRoutes);
app.use('/api/integrations', integrationRoutes);
app.use('/api/reports', reportRoutes);
app.use('/api/graph', graphRoutes);

// ── 404 Handler ──────────────────────────────────────────────
app.use((req, res) => {
    res.status(404).json({
        error: `Route not found: ${req.method} ${req.path}`,
        code: 'NOT_FOUND',
    });
});

// ── Global Error Handler ─────────────────────────────────────
// Catches any unhandled errors from route handlers
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
    // Log the full error internally
    logger.error('Unhandled error', {
        error: err.message,
        stack: err.stack,
        path: req.path,
        method: req.method,
        userId: req.user?.id,
    });

    // Don't leak internal error details to the client
    const statusCode = err.statusCode || err.status || 500;
    const isOperational = err.isOperational === true; // Only expose expected errors

    res.status(statusCode).json({
        error: isOperational ? err.message : 'An internal server error occurred',
        code: err.code || 'INTERNAL_ERROR',
        ...(process.env.NODE_ENV === 'development' && {
            stack: err.stack,
            details: err.details,
        }),
    });
});

// ── Server Startup ───────────────────────────────────────────
async function start() {
    try {
        logger.info('Starting NHI Shield API...');

        // Connect to all databases before accepting traffic
        await connectDB();
        logger.info('✓ PostgreSQL connected');

        await connectRedis();
        logger.info('✓ Redis connected');

        await connectNeo4j();
        logger.info('✓ Neo4j connected');

        const server = app.listen(PORT, () => {
            logger.info(`✓ NHI Shield API running on port ${PORT}`);
            logger.info(`  Health: http://localhost:${PORT}/health`);
        });

        // ── Graceful Shutdown ─────────────────────────────────
        // Allows in-flight requests to finish before closing
        const shutdown = async (signal) => {
            logger.info(`Received ${signal} — graceful shutdown starting...`);

            server.close(async () => {
                logger.info('HTTP server closed');
                try {
                    await disconnectDB();
                    await disconnectRedis();
                    await disconnectNeo4j();
                    logger.info('All connections closed — bye!');
                    process.exit(0);
                } catch (err) {
                    logger.error('Error during shutdown:', err);
                    process.exit(1);
                }
            });

            // Force exit if graceful shutdown takes too long
            setTimeout(() => {
                logger.error('Forcing exit after timeout');
                process.exit(1);
            }, 10000);
        };

        process.on('SIGTERM', () => shutdown('SIGTERM'));
        process.on('SIGINT', () => shutdown('SIGINT'));

    } catch (err) {
        logger.error('Failed to start server:', err);
        process.exit(1);
    }
}

start();

module.exports = app; // Exported for testing
