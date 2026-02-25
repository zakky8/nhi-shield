// ============================================================
// NHI SHIELD — Neo4j Graph Database Service
// ============================================================
const neo4j = require('neo4j-driver');
const logger = require('./logger');

let driver = null;
let sessionFactory = null;

function getDriver() {
    if (!driver) throw new Error('Neo4j not connected — call connectNeo4j() first');
    return driver;
}

async function connectNeo4j() {
    driver = neo4j.driver(
        process.env.NEO4J_URI || 'bolt://localhost:7687',
        neo4j.auth.basic(
            process.env.NEO4J_USER || 'neo4j',
            process.env.NEO4J_PASSWORD
        ),
        {
            maxConnectionPoolSize: 50,
            connectionAcquisitionTimeout: 10000,
        }
    );

    // Verify connectivity
    await driver.getServerInfo();

    sessionFactory = () => driver.session({ database: 'neo4j' });
    return driver;
}

async function disconnectNeo4j() {
    if (driver) {
        await driver.close();
        driver = null;
        logger.info('Neo4j disconnected');
    }
}

// Helper: run a Cypher query and return records
async function runCypher(query, params = {}) {
    const session = getDriver().session();
    try {
        const result = await session.run(query, params);
        return result.records.map(r => r.toObject());
    } finally {
        await session.close();
    }
}

// Helper: write query (use for mutations)
async function writeCypher(query, params = {}) {
    const session = getDriver().session();
    try {
        const result = await session.writeTransaction(tx => tx.run(query, params));
        return result.records.map(r => r.toObject());
    } finally {
        await session.close();
    }
}

module.exports = { connectNeo4j, disconnectNeo4j, runCypher, writeCypher, getDriver };
