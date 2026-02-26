import React, { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import axios from 'axios';
import {
  ArrowLeftIcon,
  ExclamationTriangleIcon,
  PowerIcon
} from '@heroicons/react/24/outline';

const API_URL = process.env.REACT_APP_API_URL || 'http://localhost:3000/api';

const IdentityDetail = () => {
  const { id } = useParams();
  const navigate = useNavigate();
  const [identity, setIdentity] = useState(null);
  const [graph, setGraph] = useState(null);
  const [loading, setLoading] = useState(true);
  const [offboardReason, setOffboardReason] = useState('');
  const [showOffboardModal, setShowOffboardModal] = useState(false);

  useEffect(() => {
    fetchIdentityData();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [id]);

  const fetchIdentityData = async () => {
    try {
      setLoading(true);
      const [identityRes, graphRes] = await Promise.all([
        axios.get(`${API_URL}/identities/${id}`),
        axios.get(`${API_URL}/identities/${id}/graph`)
      ]);

      setIdentity(identityRes.data.identity);
      setGraph(graphRes.data);
    } catch (error) {
      console.error('Error fetching identity data:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleOffboard = async () => {
    try {
      await axios.post(`${API_URL}/identities/${id}/offboard`, {
        reason: offboardReason
      });
      setShowOffboardModal(false);
      fetchIdentityData();
    } catch (error) {
      console.error('Error offboarding identity:', error);
      alert('Failed to offboard identity');
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary-600"></div>
      </div>
    );
  }

  if (!identity) {
    return (
      <div className="text-center py-12">
        <p className="text-gray-500">Identity not found</p>
        <button
          onClick={() => navigate('/identities')}
          className="mt-4 text-primary-600 hover:text-primary-900"
        >
          Back to identities
        </button>
      </div>
    );
  }

  const riskColors = {
    LOW: 'text-green-600 bg-green-50',
    MEDIUM: 'text-yellow-600 bg-yellow-50',
    HIGH: 'text-orange-600 bg-orange-50',
    CRITICAL: 'text-red-600 bg-red-50'
  };

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center">
          <button
            onClick={() => navigate('/identities')}
            className="mr-4 text-gray-400 hover:text-gray-600"
          >
            <ArrowLeftIcon className="h-6 w-6" />
          </button>
          <div>
            <h1 className="text-2xl font-bold text-gray-900">{identity.name}</h1>
            <p className="text-sm text-gray-500">{identity.id}</p>
          </div>
        </div>

        {identity.is_active && (
          <button
            onClick={() => setShowOffboardModal(true)}
            className="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md text-white bg-red-600 hover:bg-red-700"
          >
            <PowerIcon className="h-4 w-4 mr-2" />
            Offboard
          </button>
        )}
      </div>

      {/* Overview Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <div className="card p-6">
          <h3 className="text-sm font-medium text-gray-500">Risk Level</h3>
          <div className="mt-2">
            <span className={`inline-flex items-center px-3 py-1 rounded-full text-sm font-medium ${riskColors[identity.risk_level] || 'text-gray-600 bg-gray-100'
              }`}>
              {identity.risk_level || 'LOW'}
            </span>
            {identity.total_score && (
              <span className="ml-2 text-2xl font-bold text-gray-900">
                {identity.total_score}/100
              </span>
            )}
          </div>
        </div>

        <div className="card p-6">
          <h3 className="text-sm font-medium text-gray-500">Status</h3>
          <div className="mt-2">
            <span className={`inline-flex items-center px-3 py-1 rounded-full text-sm font-medium ${identity.is_active
                ? 'text-green-600 bg-green-100'
                : 'text-red-600 bg-red-100'
              }`}>
              {identity.is_active ? 'Active' : 'Inactive'}
            </span>
          </div>
        </div>

        <div className="card p-6">
          <h3 className="text-sm font-medium text-gray-500">Platform</h3>
          <div className="mt-2">
            <span className="text-lg font-medium text-gray-900 capitalize">
              {identity.platform}
            </span>
            <span className="text-sm text-gray-500 ml-2">
              ({identity.type})
            </span>
          </div>
        </div>
      </div>

      {/* Details */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <div className="card">
          <div className="px-6 py-4 border-b border-gray-200">
            <h3 className="text-lg font-medium text-gray-900">Details</h3>
          </div>
          <div className="p-6 space-y-4">
            <div>
              <label className="text-sm font-medium text-gray-500">Owner</label>
              <p className="mt-1 text-sm text-gray-900">
                {identity.owner || 'Not assigned'}
              </p>
            </div>
            <div>
              <label className="text-sm font-medium text-gray-500">Created</label>
              <p className="mt-1 text-sm text-gray-900">
                {identity.created_at
                  ? new Date(identity.created_at).toLocaleString()
                  : 'Unknown'
                }
              </p>
            </div>
            <div>
              <label className="text-sm font-medium text-gray-500">Last Used</label>
              <p className="mt-1 text-sm text-gray-900">
                {identity.last_used
                  ? new Date(identity.last_used).toLocaleString()
                  : 'Never'
                }
              </p>
            </div>
            <div>
              <label className="text-sm font-medium text-gray-500">Discovered</label>
              <p className="mt-1 text-sm text-gray-900">
                {identity.discovered_at
                  ? new Date(identity.discovered_at).toLocaleString()
                  : 'Unknown'
                }
              </p>
            </div>
          </div>
        </div>

        <div className="card">
          <div className="px-6 py-4 border-b border-gray-200">
            <h3 className="text-lg font-medium text-gray-900">Permissions</h3>
          </div>
          <div className="p-6">
            {identity.permissions && identity.permissions.length > 0 ? (
              <div className="flex flex-wrap gap-2">
                {identity.permissions.map((perm, idx) => (
                  <span
                    key={idx}
                    className="inline-flex items-center px-2.5 py-0.5 rounded-md text-sm font-medium bg-gray-100 text-gray-800"
                  >
                    {perm}
                  </span>
                ))}
              </div>
            ) : (
              <p className="text-sm text-gray-500">No permissions recorded</p>
            )}
          </div>
        </div>
      </div>

      {/* Risk Factors */}
      {identity.risk_factors && identity.risk_factors.length > 0 && (
        <div className="card">
          <div className="px-6 py-4 border-b border-gray-200">
            <h3 className="text-lg font-medium text-gray-900">Risk Factors</h3>
          </div>
          <div className="divide-y divide-gray-200">
            {identity.risk_factors.map((factor, idx) => (
              <div key={idx} className="px-6 py-4">
                <div className="flex items-center">
                  <ExclamationTriangleIcon className="h-5 w-5 text-yellow-500 mr-2" />
                  <div>
                    <p className="text-sm font-medium text-gray-900">
                      {factor.factor}
                    </p>
                    <p className="text-sm text-gray-500">
                      {factor.detail} (+{factor.points} points)
                    </p>
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Relationships */}
      {graph && graph.nodes.length > 1 && (
        <div className="card">
          <div className="px-6 py-4 border-b border-gray-200">
            <h3 className="text-lg font-medium text-gray-900">Relationships</h3>
          </div>
          <div className="p-6">
            <p className="text-sm text-gray-500">
              Connected to {graph.nodes.length - 1} other identities/resources
            </p>
            <div className="mt-4 space-y-2">
              {graph.edges.map((edge, idx) => (
                <div key={idx} className="flex items-center text-sm">
                  <span className="font-medium">{edge.source}</span>
                  <span className="mx-2 text-gray-400">→</span>
                  <span className="text-gray-600">{edge.type}</span>
                  <span className="mx-2 text-gray-400">→</span>
                  <span className="font-medium">{edge.target}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Offboard Modal */}
      {showOffboardModal && (
        <div className="fixed inset-0 z-50 overflow-y-auto">
          <div className="flex items-end justify-center min-h-screen pt-4 px-4 pb-20 text-center sm:block sm:p-0">
            <div
              className="fixed inset-0 bg-gray-500 bg-opacity-75 transition-opacity"
              onClick={() => setShowOffboardModal(false)}
            />
            <span className="hidden sm:inline-block sm:align-middle sm:h-screen">&#8203;</span>
            <div className="inline-block align-bottom bg-white rounded-lg text-left overflow-hidden shadow-xl transform transition-all sm:my-8 sm:align-middle sm:max-w-lg sm:w-full">
              <div className="bg-white px-4 pt-5 pb-4 sm:p-6 sm:pb-4">
                <div className="sm:flex sm:items-start">
                  <div className="mx-auto flex-shrink-0 flex items-center justify-center h-12 w-12 rounded-full bg-red-100 sm:mx-0 sm:h-10 sm:w-10">
                    <ExclamationTriangleIcon className="h-6 w-6 text-red-600" />
                  </div>
                  <div className="mt-3 text-center sm:mt-0 sm:ml-4 sm:text-left">
                    <h3 className="text-lg leading-6 font-medium text-gray-900">
                      Offboard Identity
                    </h3>
                    <div className="mt-2">
                      <p className="text-sm text-gray-500">
                        Are you sure you want to offboard {identity.name}? This will revoke all access.
                      </p>
                      <textarea
                        className="mt-4 w-full border border-gray-300 rounded-md p-2 text-sm"
                        rows="3"
                        placeholder="Reason for offboarding..."
                        value={offboardReason}
                        onChange={(e) => setOffboardReason(e.target.value)}
                      />
                    </div>
                  </div>
                </div>
              </div>
              <div className="bg-gray-50 px-4 py-3 sm:px-6 sm:flex sm:flex-row-reverse">
                <button
                  type="button"
                  onClick={handleOffboard}
                  disabled={!offboardReason}
                  className="w-full inline-flex justify-center rounded-md border border-transparent shadow-sm px-4 py-2 bg-red-600 text-base font-medium text-white hover:bg-red-700 focus:outline-none sm:ml-3 sm:w-auto sm:text-sm disabled:opacity-50"
                >
                  Offboard
                </button>
                <button
                  type="button"
                  onClick={() => setShowOffboardModal(false)}
                  className="mt-3 w-full inline-flex justify-center rounded-md border border-gray-300 shadow-sm px-4 py-2 bg-white text-base font-medium text-gray-700 hover:bg-gray-50 focus:outline-none sm:mt-0 sm:ml-3 sm:w-auto sm:text-sm"
                >
                  Cancel
                </button>
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default IdentityDetail;
