import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { 
  CheckCircleIcon, 
  ExclamationTriangleIcon,
  DocumentTextIcon
} from '@heroicons/react/24/outline';

const API_URL = process.env.REACT_APP_API_URL || 'http://localhost:3000/api';

const Compliance = () => {
  const [report, setReport] = useState(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetchReport();
  }, []);

  const fetchReport = async () => {
    try {
      const response = await axios.get(`${API_URL}/reports/compliance`);
      setReport(response.data);
    } catch (error) {
      console.error('Error fetching compliance report:', error);
    } finally {
      setLoading(false);
    }
  };

  const getGradeColor = (grade) => {
    const colors = {
      'A': 'text-green-600',
      'B': 'text-blue-600',
      'C': 'text-yellow-600',
      'D': 'text-orange-600',
      'F': 'text-red-600'
    };
    return colors[grade] || 'text-gray-600';
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-primary-600"></div>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-gray-900">Compliance Report</h1>
        <p className="mt-1 text-sm text-gray-500">
          Security and compliance overview for your organization
        </p>
      </div>

      {/* Score Card */}
      <div className="card p-8 text-center">
        <h2 className="text-lg font-medium text-gray-900 mb-4">Compliance Score</h2>
        <div className="flex items-center justify-center">
          <span className={`text-6xl font-bold ${getGradeColor(report?.grade)}`}>
            {report?.grade || '-'}
          </span>
        </div>
        <p className="mt-2 text-2xl font-semibold text-gray-900">
          {report?.compliance_score || 0}/100
        </p>
        <p className="mt-1 text-sm text-gray-500">
          Generated: {report?.generated_at ? new Date(report.generated_at).toLocaleString() : '-'}
        </p>
      </div>

      {/* Summary Stats */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-6">
        <div className="card p-6">
          <p className="text-sm text-gray-500">Total Identities</p>
          <p className="text-2xl font-bold text-gray-900">
            {report?.summary?.total_identities || 0}
          </p>
        </div>
        <div className="card p-6">
          <p className="text-sm text-gray-500">Active Identities</p>
          <p className="text-2xl font-bold text-green-600">
            {report?.summary?.active_identities || 0}
          </p>
        </div>
        <div className="card p-6">
          <p className="text-sm text-gray-500">High Risk</p>
          <p className="text-2xl font-bold text-red-600">
            {report?.summary?.high_risk_identities || 0}
          </p>
        </div>
        <div className="card p-6">
          <p className="text-sm text-gray-500">Inactive (90+ days)</p>
          <p className="text-2xl font-bold text-orange-600">
            {report?.summary?.inactive_90_days || 0}
          </p>
        </div>
      </div>

      {/* Platform Breakdown */}
      <div className="card">
        <div className="px-6 py-4 border-b border-gray-200">
          <h3 className="text-lg font-medium text-gray-900">Platform Breakdown</h3>
        </div>
        <div className="divide-y divide-gray-200">
          {report?.by_platform?.map((platform) => (
            <div key={platform.platform} className="px-6 py-4 flex items-center justify-between">
              <span className="text-sm font-medium text-gray-900 capitalize">
                {platform.platform}
              </span>
              <span className="text-sm text-gray-500">
                {platform.count} identities
              </span>
            </div>
          ))}
        </div>
      </div>

      {/* Recommendations */}
      <div className="card">
        <div className="px-6 py-4 border-b border-gray-200">
          <h3 className="text-lg font-medium text-gray-900">Recommendations</h3>
        </div>
        <div className="p-6 space-y-4">
          {(report?.summary?.high_risk_identities || 0) > 0 && (
            <div className="flex items-start">
              <ExclamationTriangleIcon className="h-5 w-5 text-red-500 mr-3 mt-0.5" />
              <div>
                <p className="text-sm font-medium text-gray-900">
                  Address High-Risk Identities
                </p>
                <p className="text-sm text-gray-500">
                  {report.summary.high_risk_identities} identities have high or critical risk scores. 
                  Review and remediate these immediately.
                </p>
              </div>
            </div>
          )}
          
          {(report?.summary?.inactive_90_days || 0) > 0 && (
            <div className="flex items-start">
              <ExclamationTriangleIcon className="h-5 w-5 text-yellow-500 mr-3 mt-0.5" />
              <div>
                <p className="text-sm font-medium text-gray-900">
                  Offboard Dormant Identities
                </p>
                <p className="text-sm text-gray-500">
                  {report.summary.inactive_90_days} identities haven't been used in 90+ days. 
                  Consider offboarding these to reduce attack surface.
                </p>
              </div>
            </div>
          )}
          
          {(report?.summary?.no_owner || 0) > 0 && (
            <div className="flex items-start">
              <ExclamationTriangleIcon className="h-5 w-5 text-blue-500 mr-3 mt-0.5" />
              <div>
                <p className="text-sm font-medium text-gray-900">
                  Assign Owners
                </p>
                <p className="text-sm text-gray-500">
                  {report.summary.no_owner} identities have no assigned owner. 
                  Assign owners for accountability.
                </p>
              </div>
            </div>
          )}
          
          {(report?.summary?.high_risk_identities || 0) === 0 && 
           (report?.summary?.inactive_90_days || 0) === 0 && 
           (report?.summary?.no_owner || 0) === 0 && (
            <div className="flex items-center">
              <CheckCircleIcon className="h-5 w-5 text-green-500 mr-3" />
              <p className="text-sm text-gray-900">
                Great job! No immediate action items.
              </p>
            </div>
          )}
        </div>
      </div>

      {/* Export */}
      <div className="flex justify-end">
        <button 
          onClick={() => alert('Export feature coming soon!')}
          className="btn-secondary"
        >
          <DocumentTextIcon className="h-4 w-4 mr-2" />
          Export Report
        </button>
      </div>
    </div>
  );
};

export default Compliance;
