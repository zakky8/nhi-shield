// ============================================================
// NHI SHIELD — PostgreSQL Service
// Connection pool shared across all routes
// ============================================================
const { Pool } = require('pg');
const logger = require('./logger');

let pool = null;

function getPool() {
    if (!pool) throw new Error('Database not connected — call connectDB() first');
    return pool;
}

async function connectDB() {
    pool = new Pool({
        connectionString: process.env.DATABASE_URL,
        max: 20,                  // Max connections in pool
        idleTimeoutMillis: 30000, // Close idle connections after 30s
        connectionTimeoutMillis: 5000, // Fail fast if can't connect
    });

    // Test the connection
    const client = await pool.connect();
    await client.query('SELECT 1');
    client.release();

    pool.on('error', (err) => {
        logger.error('Unexpected PostgreSQL pool error', { error: err.message });
    });

    return pool;
}

async function disconnectDB() {
    if (pool) {
        await pool.end();
        pool = null;
        logger.info('PostgreSQL disconnected');
    }
}

// Helper: run a query with automatic logging
async function query(text, params) {
    const start = Date.now();
    try {
        const result = await getPool().query(text, params);
        const duration = Date.now() - start;
        if (duration > 1000) {
            logger.warn('Slow query detected', { duration: `${duration}ms`, query: text.substring(0, 100) });
        }
        return result;
    } catch (err) {
        logger.error('Database query error', { error: err.message, query: text.substring(0, 100) });
        throw err;
    }
}

// Helper: run multiple queries in a transaction
async function transaction(fn) {
    const client = await getPool().connect();
    try {
        await client.query('BEGIN');
        const result = await fn(client);
        await client.query('COMMIT');
        return result;
    } catch (err) {
        await client.query('ROLLBACK');
        throw err;
    } finally {
        client.release();
    }
}

module.exports = { connectDB, disconnectDB, query, transaction, getPool };
