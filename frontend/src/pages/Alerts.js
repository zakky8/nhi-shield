import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { CheckCircleIcon } from '@heroicons/react/24/outline';

const API_URL = process.env.REACT_APP_API_URL || 'http://localhost:3000/api';

const SeverityBadge = ({ severity }) => {
  const styles = {
    LOW: 'bg-blue-100 text-blue-800',
    MEDIUM: 'bg-yellow-100 text-yellow-800',
    HIGH: 'bg-orange-100 text-orange-800',
    CRITICAL: 'bg-red-100 text-red-800'
  };
  return (
    <span className={`inline-flex items-center px-2.5 py-0.5 rounded-full text-xs font-medium ${styles[severity] || 'bg-gray-100 text-gray-800'}`}>
      {severity}
    </span>
  );
};

const Alerts = () => {
  const [alerts, setAlerts] = useState([]);
  const [counts, setCounts] = useState({});
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState('all');

  useEffect(() => {
    fetchAlerts();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [filter]);

  const fetchAlerts = async () => {
    try {
      setLoading(true);
      const params = new URLSearchParams();
      if (filter !== 'all') {
        params.append('severity', filter);
      }
      params.append('resolved', 'false');

      const response = await axios.get(`${API_URL}/alerts?${params}`);
      setAlerts(response.data.alerts);
      setCounts(response.data.counts);
    } catch (error) {
      console.error('Error fetching alerts:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleResolve = async (alertId) => {
    try {
      await axios.put(`${API_URL}/alerts/${alertId}/resolve`, {
        resolution_notes: 'Resolved by user'
      });
      fetchAlerts();
    } catch (error) {
      console.error('Error resolving alert:', error);
    }
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-gray-900">Alerts</h1>
        <p className="mt-1 text-sm text-gray-500">
          Monitor and respond to security anomalies
        </p>
      </div>

      {/* Alert Counts */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className="card p-4">
          <p className="text-sm text-gray-500">Critical</p>
          <p className="text-2xl font-bold text-red-600">{counts.CRITICAL || 0}</p>
        </div>
        <div className="card p-4">
          <p className="text-sm text-gray-500">High</p>
          <p className="text-2xl font-bold text-orange-600">{counts.HIGH || 0}</p>
        </div>
        <div className="card p-4">
          <p className="text-sm text-gray-500">Medium</p>
          <p className="text-2xl font-bold text-yellow-600">{counts.MEDIUM || 0}</p>
        </div>
        <div className="card p-4">
          <p className="text-sm text-gray-500">Low</p>
          <p className="text-2xl font-bold text-blue-600">{counts.LOW || 0}</p>
        </div>
      </div>

      {/* Filter */}
      <div className="flex gap-2">
        {['all', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'].map((sev) => (
          <button
            key={sev}
            onClick={() => setFilter(sev)}
            className={`px-4 py-2 rounded-md text-sm font-medium ${filter === sev
                ? 'bg-primary-600 text-white'
                : 'bg-white text-gray-700 hover:bg-gray-50'
              }`}
          >
            {sev === 'all' ? 'All' : sev}
          </button>
        ))}
      </div>

      {/* Alerts List */}
      <div className="card divide-y divide-gray-200">
        {loading ? (
          <div className="p-8 text-center">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary-600 mx-auto"></div>
          </div>
        ) : alerts.length === 0 ? (
          <div className="p-8 text-center text-gray-500">
            <CheckCircleIcon className="h-12 w-12 text-green-500 mx-auto mb-4" />
            <p>No open alerts</p>
          </div>
        ) : (
          alerts.map((alert) => (
            <div key={alert.id} className="p-6">
              <div className="flex items-start justify-between">
                <div className="flex-1">
                  <div className="flex items-center gap-2">
                    <SeverityBadge severity={alert.severity} />
                    <span className="text-sm text-gray-500">
                      {alert.alert_type}
                    </span>
                  </div>
                  <h3 className="mt-2 text-lg font-medium text-gray-900">
                    {alert.description}
                  </h3>
                  <p className="mt-1 text-sm text-gray-500">
                    Identity: {alert.identity_name || alert.identity_id}
                  </p>
                  <p className="mt-1 text-sm text-gray-500">
                    Platform: {alert.platform}
                  </p>
                  {alert.evidence && (
                    <div className="mt-2 text-sm text-gray-600 bg-gray-50 p-2 rounded">
                      <pre className="whitespace-pre-wrap">
                        {JSON.stringify(alert.evidence, null, 2)}
                      </pre>
                    </div>
                  )}
                  <p className="mt-2 text-xs text-gray-400">
                    {new Date(alert.created_at).toLocaleString()}
                  </p>
                </div>
                <button
                  onClick={() => handleResolve(alert.id)}
                  className="ml-4 inline-flex items-center px-3 py-1 border border-transparent text-sm font-medium rounded-md text-green-700 bg-green-100 hover:bg-green-200"
                >
                  Resolve
                </button>
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
};

export default Alerts;
