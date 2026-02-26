/**
 * NHI Shield - Identity Graph Page
 * Full-page identity relationship visualization
 */

import React, { useState, useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import axios from 'axios';
import IdentityGraph from '../components/IdentityGraph';
import useWebSocket from '../hooks/useWebSocket';

const API_URL = process.env.REACT_APP_API_URL || 'http://localhost:3000/api';

const IdentityGraphPage = () => {
  const navigate = useNavigate();
  const [nodes, setNodes] = useState([]);
  const [edges, setEdges] = useState([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(null);
  const [filter, setFilter] = useState({ platform: '', riskLevel: '', activeOnly: true });
  const [selectedNode, setSelectedNode] = useState(null);
  const [dimensions, setDimensions] = useState({ width: 900, height: 600 });

  // Real-time updates
  const { connected } = useWebSocket(['identity:discovered', 'identity:offboarded', 'identity:updated']);

  // Responsive graph dimensions
  useEffect(() => {
    const updateDimensions = () => {
      const container = document.getElementById('graph-container');
      if (container) {
        setDimensions({ width: container.offsetWidth, height: Math.max(500, window.innerHeight - 280) });
      }
    };
    updateDimensions();
    window.addEventListener('resize', updateDimensions);
    return () => window.removeEventListener('resize', updateDimensions);
  }, []);

  const loadGraph = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);

      // Load all identities for the graph
      const params = new URLSearchParams({ limit: 200 });
      if (filter.platform) params.set('platform', filter.platform);
      if (filter.riskLevel) params.set('risk_level', filter.riskLevel);
      if (filter.activeOnly) params.set('is_active', 'true');

      const res = await axios.get(`${API_URL}/identities?${params}`);
      const identities = res.data.identities || [];

      // Build nodes from identities
      const graphNodes = identities.map(id => ({
        id: id.id,
        name: id.name,
        platform: id.platform,
        type: id.type,
        risk_level: id.risk_level || 'UNKNOWN',
        is_active: id.is_active,
        owner: id.owner,
        total_score: id.total_score,
      }));

      // Build edges from the first few identities' graph data
      // For large graphs we sample; full graph is loaded per-identity on click
      const graphEdges = [];
      const edgeSet = new Set();

      // Load graph edges for top 20 highest-risk identities
      const topRisk = identities.slice(0, 20);
      await Promise.allSettled(
        topRisk.map(async (id) => {
          try {
            const gRes = await axios.get(`${API_URL}/identities/${id.id}/graph`);
            const { edges: gEdges } = gRes.data;
            gEdges.forEach(e => {
              const key = `${e.source}-${e.target}-${e.type}`;
              if (!edgeSet.has(key)) {
                edgeSet.add(key);
                graphEdges.push(e);
              }
            });
          } catch {
            // Skip failed nodes
          }
        })
      );

      setNodes(graphNodes);
      setEdges(graphEdges);
    } catch (err) {
      setError(err.response?.data?.error || 'Failed to load identity graph');
    } finally {
      setLoading(false);
    }
  }, [filter]);

  useEffect(() => {
    loadGraph();
  }, [loadGraph]);

  const handleNodeClick = useCallback((node) => {
    setSelectedNode(node);
  }, []);

  const handleViewDetail = () => {
    if (selectedNode) navigate(`/identities/${selectedNode.id}`);
  };

  const platforms = [...new Set(nodes.map(n => n.platform))].filter(Boolean).sort();

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Identity Graph</h1>
          <p className="text-sm text-gray-500 mt-1">
            Visual map of all non-human identities and their relationships
          </p>
        </div>
        <div className="flex items-center gap-3">
          {/* WebSocket status */}
          <div className={`flex items-center gap-1.5 text-xs px-2 py-1 rounded-full ${connected ? 'bg-green-50 text-green-700' : 'bg-gray-100 text-gray-500'}`}>
            <div className={`w-2 h-2 rounded-full ${connected ? 'bg-green-500 animate-pulse' : 'bg-gray-400'}`} />
            {connected ? 'Live' : 'Offline'}
          </div>
          <button
            onClick={loadGraph}
            disabled={loading}
            className="inline-flex items-center px-3 py-1.5 border border-gray-300 rounded-md text-sm font-medium text-gray-700 bg-white hover:bg-gray-50 disabled:opacity-50"
          >
            {loading ? '⟳ Loading...' : '↺ Refresh'}
          </button>
        </div>
      </div>

      {/* Filters */}
      <div className="flex items-center gap-3 bg-white p-3 rounded-lg border border-gray-200">
        <select
          value={filter.platform}
          onChange={e => setFilter(f => ({ ...f, platform: e.target.value }))}
          className="text-sm border border-gray-300 rounded-md px-2 py-1 focus:outline-none focus:ring-2 focus:ring-blue-500"
        >
          <option value="">All Platforms</option>
          {platforms.map(p => <option key={p} value={p}>{p.toUpperCase()}</option>)}
        </select>
        <select
          value={filter.riskLevel}
          onChange={e => setFilter(f => ({ ...f, riskLevel: e.target.value }))}
          className="text-sm border border-gray-300 rounded-md px-2 py-1 focus:outline-none focus:ring-2 focus:ring-blue-500"
        >
          <option value="">All Risk Levels</option>
          <option value="CRITICAL">Critical</option>
          <option value="HIGH">High</option>
          <option value="MEDIUM">Medium</option>
          <option value="LOW">Low</option>
        </select>
        <label className="flex items-center gap-2 text-sm text-gray-700 cursor-pointer">
          <input
            type="checkbox"
            checked={filter.activeOnly}
            onChange={e => setFilter(f => ({ ...f, activeOnly: e.target.checked }))}
            className="rounded border-gray-300 text-blue-600 focus:ring-blue-500"
          />
          Active only
        </label>
        <span className="ml-auto text-xs text-gray-500">
          {nodes.length} nodes · {edges.length} edges
        </span>
      </div>

      {/* Main content */}
      <div className="flex gap-4">
        {/* Graph */}
        <div id="graph-container" className="flex-1 min-w-0">
          {error ? (
            <div className="bg-red-50 border border-red-200 rounded-lg p-4 text-red-700 text-sm">
              {error}
            </div>
          ) : loading ? (
            <div className="bg-white rounded-lg border border-gray-200 flex items-center justify-center" style={{ height: 500 }}>
              <div className="text-center text-gray-400">
                <div className="animate-spin text-4xl mb-3">⟳</div>
                <div className="text-sm">Loading identity graph...</div>
              </div>
            </div>
          ) : (
            <IdentityGraph
              nodes={nodes}
              edges={edges}
              onNodeClick={handleNodeClick}
              width={dimensions.width}
              height={dimensions.height}
            />
          )}
        </div>

        {/* Selected node panel */}
        {selectedNode && (
          <div className="w-64 flex-shrink-0 bg-white rounded-lg border border-gray-200 p-4 h-fit">
            <div className="flex items-center justify-between mb-3">
              <h3 className="font-semibold text-gray-900 text-sm">Selected Identity</h3>
              <button onClick={() => setSelectedNode(null)} className="text-gray-400 hover:text-gray-600">✕</button>
            </div>
            <div className="space-y-2 text-sm">
              <div>
                <span className="text-gray-500">Name</span>
                <div className="font-medium text-gray-900 break-all">{selectedNode.name}</div>
              </div>
              <div>
                <span className="text-gray-500">Platform</span>
                <div className="font-medium text-gray-900 capitalize">{selectedNode.platform}</div>
              </div>
              <div>
                <span className="text-gray-500">Type</span>
                <div className="font-medium text-gray-900">{selectedNode.type}</div>
              </div>
              <div>
                <span className="text-gray-500">Risk Level</span>
                <div className={`font-semibold ${
                  selectedNode.risk_level === 'CRITICAL' ? 'text-red-600' :
                  selectedNode.risk_level === 'HIGH' ? 'text-orange-600' :
                  selectedNode.risk_level === 'MEDIUM' ? 'text-yellow-600' : 'text-green-600'
                }`}>{selectedNode.risk_level || 'UNKNOWN'}</div>
              </div>
              <div>
                <span className="text-gray-500">Status</span>
                <div className={`font-medium ${selectedNode.is_active ? 'text-green-600' : 'text-gray-500'}`}>
                  {selectedNode.is_active ? '● Active' : '○ Inactive'}
                </div>
              </div>
              {selectedNode.owner && (
                <div>
                  <span className="text-gray-500">Owner</span>
                  <div className="font-medium text-gray-900">{selectedNode.owner}</div>
                </div>
              )}
              {selectedNode.total_score !== undefined && (
                <div>
                  <span className="text-gray-500">Risk Score</span>
                  <div className="flex items-center gap-2">
                    <div className="flex-1 bg-gray-200 rounded-full h-2">
                      <div
                        className="h-2 rounded-full"
                        style={{
                          width: `${selectedNode.total_score}%`,
                          backgroundColor: selectedNode.total_score >= 75 ? '#ef4444' :
                            selectedNode.total_score >= 50 ? '#f97316' :
                            selectedNode.total_score >= 25 ? '#eab308' : '#22c55e'
                        }}
                      />
                    </div>
                    <span className="font-semibold text-gray-900">{selectedNode.total_score}</span>
                  </div>
                </div>
              )}
            </div>
            <button
              onClick={handleViewDetail}
              className="mt-4 w-full bg-blue-600 text-white text-sm py-2 rounded-md hover:bg-blue-700 transition-colors font-medium"
            >
              View Full Details →
            </button>
          </div>
        )}
      </div>
    </div>
  );
};

export default IdentityGraphPage;
