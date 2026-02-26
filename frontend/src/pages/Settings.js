import React, { useState } from 'react';
import {
  BellIcon,
  ShieldCheckIcon,
  KeyIcon,
  UserGroupIcon
} from '@heroicons/react/24/outline';

const Settings = () => {
  const [activeTab, setActiveTab] = useState('notifications');
  const [notifications, setNotifications] = useState({
    email: true,
    slack: false,
    webhook: false,
    criticalAlerts: true,
    highAlerts: true,
    mediumAlerts: false,
    dailySummary: true
  });
  const [apiKey, setApiKey] = useState(() => localStorage.getItem('nhi_mock_api_key') || null);
  const [isNewKey, setIsNewKey] = useState(false);
  const [inviteStatus, setInviteStatus] = useState(null);

  const handleGenerateApiKey = () => {
    const newKey = `nhi_live_${Math.random().toString(36).substring(2, 15)}`;
    setApiKey(newKey);
    setIsNewKey(true);
    localStorage.setItem('nhi_mock_api_key', newKey);
  };

  const handleRevokeApiKey = () => {
    setApiKey(null);
    setIsNewKey(false);
    localStorage.removeItem('nhi_mock_api_key');
  };

  const tabs = [
    { id: 'notifications', name: 'Notifications', icon: BellIcon },
    { id: 'security', name: 'Security', icon: ShieldCheckIcon },
    { id: 'api', name: 'API Keys', icon: KeyIcon },
    { id: 'team', name: 'Team', icon: UserGroupIcon },
  ];

  const handleNotificationChange = (key) => {
    setNotifications(prev => ({ ...prev, [key]: !prev[key] }));
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-gray-900">Settings</h1>
        <p className="mt-1 text-sm text-gray-500">
          Manage your organization settings
        </p>
      </div>

      <div className="flex flex-col lg:flex-row gap-6">
        {/* Sidebar */}
        <div className="lg:w-64">
          <nav className="space-y-1">
            {tabs.map((tab) => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`w-full flex items-center px-3 py-2 text-sm font-medium rounded-md ${activeTab === tab.id
                  ? 'bg-primary-50 text-primary-700'
                  : 'text-gray-700 hover:bg-gray-50'
                  }`}
              >
                <tab.icon className="mr-3 h-5 w-5 flex-shrink-0" />
                {tab.name}
              </button>
            ))}
          </nav>
        </div>

        {/* Content */}
        <div className="flex-1">
          {activeTab === 'notifications' && (
            <div className="card">
              <div className="px-6 py-4 border-b border-gray-200">
                <h3 className="text-lg font-medium text-gray-900">Notification Preferences</h3>
              </div>
              <div className="p-6 space-y-6">
                <div>
                  <h4 className="text-sm font-medium text-gray-900 mb-3">Channels</h4>
                  <div className="space-y-3">
                    {[
                      { key: 'email', label: 'Email Notifications' },
                      { key: 'slack', label: 'Slack Notifications' },
                      { key: 'webhook', label: 'Webhook Notifications' }
                    ].map((item) => (
                      <label key={item.key} className="flex items-center">
                        <input
                          type="checkbox"
                          checked={notifications[item.key]}
                          onChange={() => handleNotificationChange(item.key)}
                          className="h-4 w-4 text-primary-600 focus:ring-primary-500 border-gray-300 rounded"
                        />
                        <span className="ml-2 text-sm text-gray-700">{item.label}</span>
                      </label>
                    ))}
                  </div>
                </div>

                <div className="border-t border-gray-200 pt-6">
                  <h4 className="text-sm font-medium text-gray-900 mb-3">Alert Levels</h4>
                  <div className="space-y-3">
                    {[
                      { key: 'criticalAlerts', label: 'Critical Alerts' },
                      { key: 'highAlerts', label: 'High Alerts' },
                      { key: 'mediumAlerts', label: 'Medium Alerts' }
                    ].map((item) => (
                      <label key={item.key} className="flex items-center">
                        <input
                          type="checkbox"
                          checked={notifications[item.key]}
                          onChange={() => handleNotificationChange(item.key)}
                          className="h-4 w-4 text-primary-600 focus:ring-primary-500 border-gray-300 rounded"
                        />
                        <span className="ml-2 text-sm text-gray-700">{item.label}</span>
                      </label>
                    ))}
                  </div>
                </div>

                <div className="border-t border-gray-200 pt-6">
                  <h4 className="text-sm font-medium text-gray-900 mb-3">Reports</h4>
                  <label className="flex items-center">
                    <input
                      type="checkbox"
                      checked={notifications.dailySummary}
                      onChange={() => handleNotificationChange('dailySummary')}
                      className="h-4 w-4 text-primary-600 focus:ring-primary-500 border-gray-300 rounded"
                    />
                    <span className="ml-2 text-sm text-gray-700">Daily Summary Email</span>
                  </label>
                </div>

                <div className="pt-4">
                  <button className="btn-primary">
                    Save Changes
                  </button>
                </div>
              </div>
            </div>
          )}

          {activeTab === 'security' && (
            <div className="card">
              <div className="px-6 py-4 border-b border-gray-200">
                <h3 className="text-lg font-medium text-gray-900">Security Settings</h3>
              </div>
              <div className="p-6 space-y-6">
                <div>
                  <h4 className="text-sm font-medium text-gray-900 mb-3">Multi-Factor Authentication</h4>
                  <p className="text-sm text-gray-500 mb-3">
                    Require MFA for all users in your organization
                  </p>
                  <button className="btn-secondary">
                    Configure MFA
                  </button>
                </div>

                <div className="border-t border-gray-200 pt-6">
                  <h4 className="text-sm font-medium text-gray-900 mb-3">Session Timeout</h4>
                  <select className="block w-full border-gray-300 rounded-md shadow-sm focus:ring-primary-500 focus:border-primary-500 sm:text-sm">
                    <option>15 minutes</option>
                    <option>30 minutes</option>
                    <option>1 hour</option>
                    <option>4 hours</option>
                    <option>8 hours</option>
                  </select>
                </div>

                <div className="border-t border-gray-200 pt-6">
                  <h4 className="text-sm font-medium text-gray-900 mb-3">Password Policy</h4>
                  <div className="space-y-2">
                    <label className="flex items-center">
                      <input type="checkbox" checked className="h-4 w-4 text-primary-600 border-gray-300 rounded" readOnly />
                      <span className="ml-2 text-sm text-gray-700">Minimum 12 characters</span>
                    </label>
                    <label className="flex items-center">
                      <input type="checkbox" checked className="h-4 w-4 text-primary-600 border-gray-300 rounded" readOnly />
                      <span className="ml-2 text-sm text-gray-700">Require uppercase and lowercase</span>
                    </label>
                    <label className="flex items-center">
                      <input type="checkbox" checked className="h-4 w-4 text-primary-600 border-gray-300 rounded" readOnly />
                      <span className="ml-2 text-sm text-gray-700">Require numbers</span>
                    </label>
                    <label className="flex items-center">
                      <input type="checkbox" checked className="h-4 w-4 text-primary-600 border-gray-300 rounded" readOnly />
                      <span className="ml-2 text-sm text-gray-700">Require special characters</span>
                    </label>
                  </div>
                </div>
              </div>
            </div>
          )}

          {activeTab === 'api' && (
            <div className="card">
              <div className="px-6 py-4 border-b border-gray-200">
                <h3 className="text-lg font-medium text-gray-900">API Keys</h3>
              </div>
              <div className="p-6">
                <p className="text-sm text-gray-500 mb-4">
                  Manage API keys for programmatic access to NHI Shield
                </p>
                <div className="bg-gray-50 p-4 rounded-md">
                  {!apiKey ? (
                    <>
                      <p className="text-sm text-gray-500 text-center">
                        No API keys configured
                      </p>
                      <div className="mt-4 text-center">
                        <button className="btn-primary" onClick={handleGenerateApiKey}>
                          Generate API Key
                        </button>
                      </div>
                    </>
                  ) : (
                    <div className="text-center">
                      <p className="text-sm font-medium text-gray-900 mb-2">
                        {isNewKey ? 'Your New API Key' : 'Active API Key'}
                      </p>
                      <code className="bg-gray-200 px-3 py-1 rounded text-sm break-all">
                        {isNewKey ? apiKey : `${apiKey.substring(0, 12)}...****************`}
                      </code>

                      {isNewKey ? (
                        <p className="text-xs text-red-500 mt-2">Please copy this key now. It will not be shown again if you refresh the page.</p>
                      ) : (
                        <p className="text-xs text-gray-500 mt-2">For security reasons, your full API key is no longer visible.</p>
                      )}

                      <div className="mt-4 flex justify-center gap-4">
                        <button className="btn-secondary text-red-600 hover:text-red-700 border-red-200 hover:bg-red-50" onClick={handleRevokeApiKey}>
                          Revoke Key
                        </button>
                      </div>
                    </div>
                  )}
                </div>
              </div>
            </div>
          )}

          {activeTab === 'team' && (
            <div className="card">
              <div className="px-6 py-4 border-b border-gray-200">
                <h3 className="text-lg font-medium text-gray-900">Team Members</h3>
              </div>
              <div className="p-6">
                <div className="flex justify-between items-center mb-4">
                  <p className="text-sm text-gray-500">
                    Manage access for your team members
                  </p>
                  <div className="flex items-center gap-4">
                    {inviteStatus && (
                      <span className="text-sm text-green-600 bg-green-50 px-3 py-1 rounded-md font-medium animate-pulse">
                        Invitation sent to new member!
                      </span>
                    )}
                    <button className="btn-primary" onClick={() => {
                      setInviteStatus('sent');
                      setTimeout(() => setInviteStatus(null), 3000);
                    }}>
                      Invite Member
                    </button>
                  </div>
                </div>
                <div className="divide-y divide-gray-200">
                  <div className="py-4 flex items-center justify-between">
                    <div className="flex items-center">
                      <div className="h-10 w-10 rounded-full bg-primary-100 flex items-center justify-center">
                        <span className="text-primary-600 font-medium">A</span>
                      </div>
                      <div className="ml-4">
                        <p className="text-sm font-medium text-gray-900">admin@example.com</p>
                        <p className="text-sm text-gray-500">Super Admin</p>
                      </div>
                    </div>
                    <span className="text-sm text-green-600">Active</span>
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
};

export default Settings;
