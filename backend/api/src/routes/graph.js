// ============================================================
// NHI SHIELD — Graph Routes (Neo4j)
// GET /api/graph/identities  — Full graph for visualization
// GET /api/graph/neighbors/:id — Neighbors of a node
// ============================================================
const express = require('express');
const { runCypher } = require('../services/neo4j');
const { authenticate } = require('../middleware/auth');
const { cacheGet, cacheSet } = require('../services/redis');

const router = express.Router();
router.use(authenticate);

// GET /api/graph/identities — returns nodes + edges for D3.js
router.get('/identities', async (req, res) => {
    const orgId = req.user.org_id;
    const cacheKey = `graph:${orgId}`;

    // Cache graph for 5 minutes (expensive query)
    const cached = await cacheGet(cacheKey);
    if (cached) return res.json(cached);

    const records = await runCypher(
        `MATCH (n:NHIdentity {org_id: $orgId})
         OPTIONAL MATCH (n)-[r]->(m:NHIdentity {org_id: $orgId})
         RETURN n, r, m LIMIT 500`,
        { orgId }
    );

    const nodesMap = new Map();
    const edges = [];

    for (const record of records) {
        const n = record.n;
        if (n && !nodesMap.has(n.properties.id)) {
            nodesMap.set(n.properties.id, {
                id: n.properties.id,
                name: n.properties.name,
                platform: n.properties.platform,
                riskScore: n.properties.risk_score,
                isActive: n.properties.is_active,
            });
        }
        const m = record.m;
        if (m && !nodesMap.has(m.properties.id)) {
            nodesMap.set(m.properties.id, {
                id: m.properties.id,
                name: m.properties.name,
                platform: m.properties.platform,
                riskScore: m.properties.risk_score,
                isActive: m.properties.is_active,
            });
        }
        const rel = record.r;
        if (rel && n && m) {
            edges.push({
                source: n.properties.id,
                target: m.properties.id,
                type: rel.type,
            });
        }
    }

    const result = { nodes: Array.from(nodesMap.values()), edges };
    await cacheSet(cacheKey, result, 300); // 5 min cache

    res.json(result);
});

// GET /api/graph/neighbors/:id — Find all connected identities
router.get('/neighbors/:id', async (req, res) => {
    const records = await runCypher(
        `MATCH (n:NHIdentity {id: $id})-[r]-(m:NHIdentity)
         RETURN n, r, m`,
        { id: req.params.id }
    );

    const nodes = [];
    const edges = [];
    for (const record of records) {
        if (record.m) nodes.push(record.m.properties);
        if (record.r && record.n && record.m) {
            edges.push({
                source: record.n.properties.id,
                target: record.m.properties.id,
                type: record.r.type,
            });
        }
    }

    res.json({ nodes, edges });
});

module.exports = router;
