import React, { useState, useEffect } from 'react';
import axios from 'axios';
import { 
  PlusIcon, 
  TrashIcon, 
  CheckCircleIcon,
  XCircleIcon
} from '@heroicons/react/24/outline';

const API_URL = process.env.REACT_APP_API_URL || 'http://localhost:3000/api';

const PLATFORM_CONFIGS = {
  github: {
    name: 'GitHub',
    fields: [
      { name: 'token', label: 'Personal Access Token', type: 'password' },
      { name: 'org', label: 'Organization Name', type: 'text' }
    ]
  },
  aws: {
    name: 'AWS',
    fields: [
      { name: 'access_key', label: 'Access Key ID', type: 'text' },
      { name: 'secret_key', label: 'Secret Access Key', type: 'password' },
      { name: 'region', label: 'Region', type: 'text' }
    ]
  },
  openai: {
    name: 'OpenAI',
    fields: [
      { name: 'admin_key', label: 'Admin API Key', type: 'password' }
    ]
  },
  slack: {
    name: 'Slack',
    fields: [
      { name: 'token', label: 'Bot User OAuth Token', type: 'password' }
    ]
  },
  google: {
    name: 'Google Cloud',
    fields: [
      { name: 'credentials_path', label: 'Service Account JSON Path', type: 'text' },
      { name: 'project_id', label: 'Project ID', type: 'text' }
    ]
  }
};

const Integrations = () => {
  const [integrations, setIntegrations] = useState([]);
  const [loading, setLoading] = useState(true);
  const [showAddModal, setShowAddModal] = useState(false);
  const [selectedPlatform, setSelectedPlatform] = useState('');
  const [formData, setFormData] = useState({});

  useEffect(() => {
    fetchIntegrations();
  }, []);

  const fetchIntegrations = async () => {
    try {
      const response = await axios.get(`${API_URL}/integrations`);
      setIntegrations(response.data.integrations);
    } catch (error) {
      console.error('Error fetching integrations:', error);
    } finally {
      setLoading(false);
    }
  };

  const handleAdd = async () => {
    try {
      await axios.post(`${API_URL}/integrations`, {
        platform: selectedPlatform,
        name: `${PLATFORM_CONFIGS[selectedPlatform].name} Integration`,
        config: formData
      });
      setShowAddModal(false);
      setSelectedPlatform('');
      setFormData({});
      fetchIntegrations();
    } catch (error) {
      console.error('Error adding integration:', error);
      alert('Failed to add integration');
    }
  };

  const handleDelete = async (id) => {
    if (!window.confirm('Are you sure you want to delete this integration?')) {
      return;
    }
    try {
      await axios.delete(`${API_URL}/integrations/${id}`);
      fetchIntegrations();
    } catch (error) {
      console.error('Error deleting integration:', error);
    }
  };

  return (
    <div className="space-y-6">
      <div className="flex justify-between items-center">
        <div>
          <h1 className="text-2xl font-bold text-gray-900">Integrations</h1>
          <p className="mt-1 text-sm text-gray-500">
            Connect platforms to discover non-human identities
          </p>
        </div>
        <button
          onClick={() => setShowAddModal(true)}
          className="btn-primary"
        >
          <PlusIcon className="h-4 w-4 mr-2" />
          Add Integration
        </button>
      </div>

      {/* Integrations Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {loading ? (
          <div className="col-span-full text-center py-12">
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary-600 mx-auto"></div>
          </div>
        ) : integrations.length === 0 ? (
          <div className="col-span-full text-center py-12 text-gray-500">
            <p>No integrations configured</p>
            <p className="text-sm mt-1">Add your first integration to start discovering identities</p>
          </div>
        ) : (
          integrations.map((integration) => (
            <div key={integration.id} className="card p-6">
              <div className="flex items-start justify-between">
                <div>
                  <h3 className="text-lg font-medium text-gray-900 capitalize">
                    {integration.platform}
                  </h3>
                  <p className="text-sm text-gray-500">{integration.name}</p>
                </div>
                <div className="flex items-center">
                  {integration.is_active ? (
                    <CheckCircleIcon className="h-5 w-5 text-green-500" />
                  ) : (
                    <XCircleIcon className="h-5 w-5 text-red-500" />
                  )}
                </div>
              </div>
              
              <div className="mt-4 space-y-2">
                <div className="flex justify-between text-sm">
                  <span className="text-gray-500">Status:</span>
                  <span className={integration.is_active ? 'text-green-600' : 'text-red-600'}>
                    {integration.is_active ? 'Active' : 'Inactive'}
                  </span>
                </div>
                {integration.last_sync && (
                  <div className="flex justify-between text-sm">
                    <span className="text-gray-500">Last Sync:</span>
                    <span>{new Date(integration.last_sync).toLocaleString()}</span>
                  </div>
                )}
              </div>
              
              <div className="mt-4 pt-4 border-t border-gray-200">
                <button
                  onClick={() => handleDelete(integration.id)}
                  className="text-red-600 hover:text-red-900 text-sm flex items-center"
                >
                  <TrashIcon className="h-4 w-4 mr-1" />
                  Delete
                </button>
              </div>
            </div>
          ))
        )}
      </div>

      {/* Add Integration Modal */}
      {showAddModal && (
        <div className="fixed inset-0 z-50 overflow-y-auto">
          <div className="flex items-end justify-center min-h-screen pt-4 px-4 pb-20 text-center sm:block sm:p-0">
            <div 
              className="fixed inset-0 bg-gray-500 bg-opacity-75 transition-opacity"
              onClick={() => setShowAddModal(false)}
            />
            <span className="hidden sm:inline-block sm:align-middle sm:h-screen">&#8203;</span>
            <div className="inline-block align-bottom bg-white rounded-lg text-left overflow-hidden shadow-xl transform transition-all sm:my-8 sm:align-middle sm:max-w-lg sm:w-full">
              <div className="bg-white px-4 pt-5 pb-4 sm:p-6">
                <h3 className="text-lg font-medium text-gray-900 mb-4">
                  Add Integration
                </h3>
                
                <div className="space-y-4">
                  <div>
                    <label className="block text-sm font-medium text-gray-700">
                      Platform
                    </label>
                    <select
                      className="mt-1 block w-full border-gray-300 rounded-md shadow-sm focus:ring-primary-500 focus:border-primary-500 sm:text-sm"
                      value={selectedPlatform}
                      onChange={(e) => {
                        setSelectedPlatform(e.target.value);
                        setFormData({});
                      }}
                    >
                      <option value="">Select platform...</option>
                      {Object.entries(PLATFORM_CONFIGS).map(([key, config]) => (
                        <option key={key} value={key}>{config.name}</option>
                      ))}
                    </select>
                  </div>
                  
                  {selectedPlatform && PLATFORM_CONFIGS[selectedPlatform].fields.map((field) => (
                    <div key={field.name}>
                      <label className="block text-sm font-medium text-gray-700">
                        {field.label}
                      </label>
                      <input
                        type={field.type}
                        className="mt-1 block w-full border-gray-300 rounded-md shadow-sm focus:ring-primary-500 focus:border-primary-500 sm:text-sm"
                        value={formData[field.name] || ''}
                        onChange={(e) => setFormData(prev => ({
                          ...prev,
                          [field.name]: e.target.value
                        }))}
                      />
                    </div>
                  ))}
                </div>
              </div>
              <div className="bg-gray-50 px-4 py-3 sm:px-6 sm:flex sm:flex-row-reverse">
                <button
                  type="button"
                  onClick={handleAdd}
                  disabled={!selectedPlatform}
                  className="w-full inline-flex justify-center rounded-md border border-transparent shadow-sm px-4 py-2 bg-primary-600 text-base font-medium text-white hover:bg-primary-700 focus:outline-none sm:ml-3 sm:w-auto sm:text-sm disabled:opacity-50"
                >
                  Add
                </button>
                <button
                  type="button"
                  onClick={() => setShowAddModal(false)}
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

export default Integrations;
