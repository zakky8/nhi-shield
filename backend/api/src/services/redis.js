// ============================================================
// NHI SHIELD — Redis Service
// Used for: JWT blacklist, rate limiting, pub/sub events, cache
// ============================================================
const Redis = require('ioredis');
const logger = require('./logger');

let client = null;

function getRedis() {
    if (!client) throw new Error('Redis not connected — call connectRedis() first');
    return client;
}

async function connectRedis() {
    client = new Redis(process.env.REDIS_URL, {
        retryStrategy: (times) => {
            if (times > 10) return null; // Stop retrying after 10 attempts
            return Math.min(times * 100, 3000); // Exponential backoff
        },
        maxRetriesPerRequest: 3,
        lazyConnect: false,
    });

    client.on('error', (err) => {
        logger.error('Redis error', { error: err.message });
    });

    client.on('reconnecting', () => {
        logger.warn('Redis reconnecting...');
    });

    // Verify connection
    await client.ping();
    return client;
}

async function disconnectRedis() {
    if (client) {
        await client.quit();
        client = null;
        logger.info('Redis disconnected');
    }
}

// ── JWT Blacklist ─────────────────────────────────────────────
// Blacklisted tokens are stored until they expire
async function blacklistToken(token, expiresInSeconds) {
    return getRedis().setex(`blacklist:${token}`, expiresInSeconds, '1');
}

async function isTokenBlacklisted(token) {
    const result = await getRedis().get(`blacklist:${token}`);
    return result !== null;
}

// ── Brute Force Protection ────────────────────────────────────
async function incrementLoginAttempts(key) {
    const redis = getRedis();
    const count = await redis.incr(`login_attempts:${key}`);
    if (count === 1) {
        // Set expiry on first attempt: 15 minutes window
        await redis.expire(`login_attempts:${key}`, 15 * 60);
    }
    return count;
}

async function getLoginAttempts(key) {
    const count = await getRedis().get(`login_attempts:${key}`);
    return parseInt(count || '0', 10);
}

async function clearLoginAttempts(key) {
    return getRedis().del(`login_attempts:${key}`);
}

// ── Pub/Sub for Real-time Events ──────────────────────────────
async function publishEvent(channel, data) {
    return getRedis().publish(channel, JSON.stringify(data));
}

// ── Generic Cache ─────────────────────────────────────────────
async function cacheGet(key) {
    const val = await getRedis().get(`cache:${key}`);
    return val ? JSON.parse(val) : null;
}

async function cacheSet(key, value, ttlSeconds = 300) {
    return getRedis().setex(`cache:${key}`, ttlSeconds, JSON.stringify(value));
}

async function cacheDel(key) {
    return getRedis().del(`cache:${key}`);
}

module.exports = {
    connectRedis, disconnectRedis, getRedis,
    blacklistToken, isTokenBlacklisted,
    incrementLoginAttempts, getLoginAttempts, clearLoginAttempts,
    publishEvent, cacheGet, cacheSet, cacheDel,
};
