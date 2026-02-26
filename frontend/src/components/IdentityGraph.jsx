/**
 * NHI Shield - Identity Graph Visualization
 * Interactive D3.js force-directed graph showing identity relationships
 * Features: zoom/pan, click-to-detail, risk color coding, relationship labels
 */

import React, { useEffect, useRef, useCallback, useState } from 'react';
import * as d3 from 'd3';

const RISK_COLORS = {
  CRITICAL: '#ef4444',
  HIGH: '#f97316',
  MEDIUM: '#eab308',
  LOW: '#22c55e',
  UNKNOWN: '#9ca3af',
};

const PLATFORM_ICONS = {
  github: '⚙',
  aws: '☁',
  openai: '🤖',
  slack: '💬',
  google: '🔍',
  azure: '🌐',
  default: '🔑',
};

const NODE_RADIUS = 18;

/**
 * @param {Object[]} nodes - Array of {id, name, platform, risk_level, type, is_active}
 * @param {Object[]} edges - Array of {source, target, type}
 * @param {function} onNodeClick - Callback when node is clicked
 * @param {number} width
 * @param {number} height
 */
const IdentityGraph = ({ nodes = [], edges = [], onNodeClick, width = 900, height = 600 }) => {
  const svgRef = useRef(null);
  const simulationRef = useRef(null);
  const [tooltip, setTooltip] = useState({ visible: false, x: 0, y: 0, node: null });

  const renderGraph = useCallback(() => {
    if (!svgRef.current || nodes.length === 0) return;

    // Clear previous render
    d3.select(svgRef.current).selectAll('*').remove();

    const svg = d3.select(svgRef.current)
      .attr('width', width)
      .attr('height', height);

    // Zoom behavior
    const zoom = d3.zoom()
      .scaleExtent([0.2, 4])
      .on('zoom', (event) => container.attr('transform', event.transform));
    svg.call(zoom);

    const container = svg.append('g').attr('class', 'graph-container');

    // Arrow markers for directed edges
    const defs = svg.append('defs');
    const edgeTypes = [...new Set(edges.map(e => e.type || 'RELATED'))];
    edgeTypes.forEach(type => {
      defs.append('marker')
        .attr('id', `arrow-${type}`)
        .attr('viewBox', '0 -5 10 10')
        .attr('refX', NODE_RADIUS + 10)
        .attr('refY', 0)
        .attr('markerWidth', 6)
        .attr('markerHeight', 6)
        .attr('orient', 'auto')
        .append('path')
        .attr('d', 'M0,-5L10,0L0,5')
        .attr('fill', type === 'CREATES' ? '#7c3aed' : type === 'ACCESSES' ? '#2563eb' : '#9ca3af');
    });

    // Deep clone nodes/edges so D3 can mutate them for simulation
    const simNodes = nodes.map(n => ({ ...n }));
    const simEdges = edges.map(e => ({ ...e }));

    // Force simulation
    const simulation = d3.forceSimulation(simNodes)
      .force('link', d3.forceLink(simEdges)
        .id(d => d.id)
        .distance(120)
        .strength(0.5))
      .force('charge', d3.forceManyBody().strength(-400))
      .force('center', d3.forceCenter(width / 2, height / 2))
      .force('collision', d3.forceCollide(NODE_RADIUS + 10));
    simulationRef.current = simulation;

    // Edges
    const link = container.append('g').attr('class', 'links')
      .selectAll('line')
      .data(simEdges)
      .enter()
      .append('line')
      .attr('stroke', d => {
        const t = d.type || 'RELATED';
        if (t === 'CREATES') return '#7c3aed';
        if (t === 'ACCESSES') return '#2563eb';
        return '#d1d5db';
      })
      .attr('stroke-width', 1.5)
      .attr('stroke-opacity', 0.7)
      .attr('marker-end', d => `url(#arrow-${d.type || 'RELATED'})`);

    // Edge labels
    const edgeLabel = container.append('g').attr('class', 'edge-labels')
      .selectAll('text')
      .data(simEdges)
      .enter()
      .append('text')
      .attr('font-size', '9px')
      .attr('fill', '#6b7280')
      .attr('text-anchor', 'middle')
      .text(d => d.type || '');

    // Node groups
    const node = container.append('g').attr('class', 'nodes')
      .selectAll('g')
      .data(simNodes)
      .enter()
      .append('g')
      .attr('class', 'node')
      .style('cursor', 'pointer')
      .call(d3.drag()
        .on('start', (event, d) => {
          if (!event.active) simulation.alphaTarget(0.3).restart();
          d.fx = d.x; d.fy = d.y;
        })
        .on('drag', (event, d) => { d.fx = event.x; d.fy = event.y; })
        .on('end', (event, d) => {
          if (!event.active) simulation.alphaTarget(0);
          d.fx = null; d.fy = null;
        }))
      .on('click', (event, d) => {
        event.stopPropagation();
        if (onNodeClick) onNodeClick(d);
      })
      .on('mouseover', (event, d) => {
        setTooltip({ visible: true, x: event.clientX + 12, y: event.clientY - 12, node: d });
        d3.select(event.currentTarget).select('circle').attr('r', NODE_RADIUS + 4);
      })
      .on('mouseout', (event) => {
        setTooltip(prev => ({ ...prev, visible: false }));
        d3.select(event.currentTarget).select('circle').attr('r', NODE_RADIUS);
      });

    // Node circles
    node.append('circle')
      .attr('r', NODE_RADIUS)
      .attr('fill', d => RISK_COLORS[d.risk_level || 'UNKNOWN'])
      .attr('fill-opacity', d => d.is_active ? 0.9 : 0.4)
      .attr('stroke', d => d.is_active ? '#fff' : '#9ca3af')
      .attr('stroke-width', 2.5)
      .attr('stroke-dasharray', d => d.is_active ? null : '4,2');

    // Platform icon inside node
    node.append('text')
      .attr('text-anchor', 'middle')
      .attr('dominant-baseline', 'central')
      .attr('font-size', '12px')
      .text(d => PLATFORM_ICONS[d.platform] || PLATFORM_ICONS.default);

    // Node label below
    node.append('text')
      .attr('text-anchor', 'middle')
      .attr('dy', NODE_RADIUS + 14)
      .attr('font-size', '10px')
      .attr('fill', '#374151')
      .attr('font-weight', '500')
      .text(d => d.name?.length > 18 ? d.name.slice(0, 16) + '…' : (d.name || 'Unknown'));

    // Inactive badge
    node.filter(d => !d.is_active)
      .append('text')
      .attr('text-anchor', 'middle')
      .attr('dy', -NODE_RADIUS - 4)
      .attr('font-size', '8px')
      .attr('fill', '#6b7280')
      .text('INACTIVE');

    // Tick handler
    simulation.on('tick', () => {
      link
        .attr('x1', d => d.source.x)
        .attr('y1', d => d.source.y)
        .attr('x2', d => d.target.x)
        .attr('y2', d => d.target.y);
      edgeLabel
        .attr('x', d => (d.source.x + d.target.x) / 2)
        .attr('y', d => (d.source.y + d.target.y) / 2);
      node.attr('transform', d => `translate(${d.x},${d.y})`);
    });

    // Click background to deselect
    svg.on('click', () => setTooltip(prev => ({ ...prev, visible: false })));

    // Auto-fit after simulation stabilizes
    simulation.on('end', () => {
      const bounds = container.node().getBBox();
      const padding = 40;
      const scale = Math.min(
        (width - padding * 2) / bounds.width,
        (height - padding * 2) / bounds.height,
        1.5
      );
      const tx = width / 2 - scale * (bounds.x + bounds.width / 2);
      const ty = height / 2 - scale * (bounds.y + bounds.height / 2);
      svg.transition().duration(750)
        .call(zoom.transform, d3.zoomIdentity.translate(tx, ty).scale(scale));
    });

    return () => simulation.stop();
  }, [nodes, edges, onNodeClick, width, height]);

  useEffect(() => {
    const cleanup = renderGraph();
    return () => {
      if (simulationRef.current) simulationRef.current.stop();
      if (cleanup) cleanup();
    };
  }, [renderGraph]);

  return (
    <div className="relative bg-white rounded-lg border border-gray-200 overflow-hidden">
      {/* Legend */}
      <div className="absolute top-3 left-3 z-10 bg-white bg-opacity-90 rounded-lg p-3 border border-gray-200 text-xs space-y-1.5 shadow-sm">
        <div className="font-semibold text-gray-700 mb-2">Risk Level</div>
        {Object.entries(RISK_COLORS).filter(([k]) => k !== 'UNKNOWN').map(([level, color]) => (
          <div key={level} className="flex items-center gap-2">
            <div className="w-3 h-3 rounded-full" style={{ backgroundColor: color }} />
            <span className="text-gray-600">{level}</span>
          </div>
        ))}
        <div className="border-t border-gray-200 mt-2 pt-2 font-semibold text-gray-700">Relationships</div>
        <div className="flex items-center gap-2">
          <div className="w-6 h-0.5 bg-purple-600" />
          <span className="text-gray-600">Creates</span>
        </div>
        <div className="flex items-center gap-2">
          <div className="w-6 h-0.5 bg-blue-600" />
          <span className="text-gray-600">Accesses</span>
        </div>
        <div className="flex items-center gap-2">
          <div className="w-6 h-0.5 bg-gray-300" />
          <span className="text-gray-600">Related</span>
        </div>
      </div>

      {/* Node count badge */}
      <div className="absolute top-3 right-3 z-10 bg-white bg-opacity-90 rounded-lg px-3 py-2 border border-gray-200 text-xs text-gray-600 shadow-sm">
        {nodes.length} identities · {edges.length} relationships
      </div>

      {nodes.length === 0 ? (
        <div className="flex items-center justify-center h-96 text-gray-400">
          <div className="text-center">
            <div className="text-4xl mb-3">🔍</div>
            <div className="text-sm">No identities to display</div>
            <div className="text-xs mt-1">Add integrations to discover identities</div>
          </div>
        </div>
      ) : (
        <svg ref={svgRef} className="w-full" style={{ minHeight: height }} />
      )}

      {/* Tooltip */}
      {tooltip.visible && tooltip.node && (
        <div
          className="fixed z-50 bg-gray-900 text-white text-xs rounded-lg p-3 shadow-xl pointer-events-none"
          style={{ left: tooltip.x, top: tooltip.y, maxWidth: 240 }}
        >
          <div className="font-semibold text-sm mb-1">{tooltip.node.name}</div>
          <div className="space-y-1 text-gray-300">
            <div>Platform: <span className="text-white">{tooltip.node.platform}</span></div>
            <div>Type: <span className="text-white">{tooltip.node.type}</span></div>
            <div>Risk: <span style={{ color: RISK_COLORS[tooltip.node.risk_level || 'UNKNOWN'] }}>{tooltip.node.risk_level || 'UNKNOWN'}</span></div>
            <div>Status: <span className={tooltip.node.is_active ? 'text-green-400' : 'text-red-400'}>{tooltip.node.is_active ? 'Active' : 'Inactive'}</span></div>
            {tooltip.node.owner && <div>Owner: <span className="text-white">{tooltip.node.owner}</span></div>}
          </div>
          <div className="text-gray-500 mt-2 text-xs">Click to view details</div>
        </div>
      )}
    </div>
  );
};

export default IdentityGraph;
