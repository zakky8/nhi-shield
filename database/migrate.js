#!/usr/bin/env node
// ============================================================
// NHI SHIELD — Database Migration Runner
// Usage:
//   node database/migrate.js          → run all pending migrations
//   node database/migrate.js rollback → rollback last migration
//   node database/migrate.js status   → show migration status
// ============================================================

require('dotenv').config();
const { Client } = require('pg');
const fs = require('fs');
const path = require('path');

const DATABASE_URL = process.env.DATABASE_URL;
const MIGRATIONS_DIR = path.join(__dirname, 'migrations');

async function getClient() {
    const client = new Client({ connectionString: DATABASE_URL });
    await client.connect();
    return client;
}

// Create the migrations tracking table if it doesn't exist
async function ensureMigrationsTable(client) {
    await client.query(`
        CREATE TABLE IF NOT EXISTS _migrations (
            id          SERIAL PRIMARY KEY,
            filename    VARCHAR(255) UNIQUE NOT NULL,
            executed_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
            checksum    VARCHAR(64) NOT NULL  -- SHA256 of file contents
        )
    `);
    console.log('✓ Migrations table ready');
}

// Get list of already-executed migrations
async function getExecutedMigrations(client) {
    const result = await client.query(
        'SELECT filename, checksum FROM _migrations ORDER BY id'
    );
    return result.rows;
}

// Read all .sql files from migrations directory, sorted by filename
function getMigrationFiles() {
    if (!fs.existsSync(MIGRATIONS_DIR)) {
        console.error(`✗ Migrations directory not found: ${MIGRATIONS_DIR}`);
        process.exit(1);
    }
    return fs.readdirSync(MIGRATIONS_DIR)
        .filter(f => f.endsWith('.sql'))
        .sort()
        .map(filename => ({
            filename,
            filepath: path.join(MIGRATIONS_DIR, filename),
        }));
}

// Simple checksum to detect if a migration file was changed after running
function checksum(content) {
    const crypto = require('crypto');
    return crypto.createHash('sha256').update(content).digest('hex');
}

// Run all pending migrations
async function runMigrations() {
    const client = await getClient();
    try {
        await ensureMigrationsTable(client);
        const executed = await getExecutedMigrations(client);
        const executedFilenames = new Set(executed.map(e => e.filename));

        const allFiles = getMigrationFiles();
        const pending = allFiles.filter(f => !executedFilenames.has(f.filename));

        if (pending.length === 0) {
            console.log('✓ Database is up to date — no pending migrations');
            return;
        }

        console.log(`\nRunning ${pending.length} pending migration(s):\n`);

        for (const migration of pending) {
            const sql = fs.readFileSync(migration.filepath, 'utf8');
            const hash = checksum(sql);

            console.log(`  → ${migration.filename}`);

            // Run migration in a transaction so it's atomic
            await client.query('BEGIN');
            try {
                await client.query(sql);
                await client.query(
                    'INSERT INTO _migrations (filename, checksum) VALUES ($1, $2)',
                    [migration.filename, hash]
                );
                await client.query('COMMIT');
                console.log(`  ✓ ${migration.filename} — SUCCESS`);
            } catch (err) {
                await client.query('ROLLBACK');
                console.error(`  ✗ ${migration.filename} — FAILED`);
                console.error(`    Error: ${err.message}`);
                process.exit(1);
            }
        }

        console.log(`\n✓ All migrations complete\n`);
    } finally {
        await client.end();
    }
}

// Rollback: shows what the last migration was (manual rollback required)
async function rollbackStatus() {
    const client = await getClient();
    try {
        await ensureMigrationsTable(client);
        const result = await client.query(
            'SELECT * FROM _migrations ORDER BY id DESC LIMIT 1'
        );
        if (result.rows.length === 0) {
            console.log('No migrations have been run yet.');
        } else {
            const last = result.rows[0];
            const filepath = path.join(MIGRATIONS_DIR, last.filename);
            console.log(`\nLast migration: ${last.filename}`);
            console.log(`Executed at: ${last.executed_at}`);
            console.log(`\nTo rollback, create a new migration file in database/migrations/`);
            console.log(`with a higher number (e.g. 002_rollback_something.sql)`);
            console.log(`\nNOTE: Rollbacks are done via forward migrations to maintain audit trail.`);
        }
    } finally {
        await client.end();
    }
}

// Show status of all migrations
async function showStatus() {
    const client = await getClient();
    try {
        await ensureMigrationsTable(client);
        const executed = await getExecutedMigrations(client);
        const executedMap = new Map(executed.map(e => [e.filename, e]));
        const allFiles = getMigrationFiles();

        console.log('\nMigration Status:\n');
        console.log('  Status    | File');
        console.log('  ----------|----------------------------------------');

        for (const file of allFiles) {
            const status = executedMap.has(file.filename) ? '✓ APPLIED  ' : '○ PENDING  ';
            console.log(`  ${status}| ${file.filename}`);
        }

        // Check for any migrations in DB that don't have files (deleted/renamed)
        for (const [filename] of executedMap) {
            const fileExists = allFiles.some(f => f.filename === filename);
            if (!fileExists) {
                console.log(`  ✗ MISSING  | ${filename} (in DB but file not found!)`);
            }
        }
        console.log();
    } finally {
        await client.end();
    }
}

// CLI router
const command = process.argv[2] || 'run';
switch (command) {
    case 'run':
    case 'up':
        runMigrations().catch(err => {
            console.error('Migration failed:', err.message);
            process.exit(1);
        });
        break;
    case 'rollback':
        rollbackStatus().catch(err => {
            console.error('Error:', err.message);
            process.exit(1);
        });
        break;
    case 'status':
        showStatus().catch(err => {
            console.error('Error:', err.message);
            process.exit(1);
        });
        break;
    default:
        console.log('Usage: node migrate.js [run|rollback|status]');
        process.exit(1);
}
