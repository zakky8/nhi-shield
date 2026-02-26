import React, { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import axios from 'axios';

const PLATFORMS = [
  { id: 'github',      label: 'GitHub',      icon: '🐙', fields: [{ name:'token', label:'Personal Access Token (org:read scope)', type:'password' }, { name:'org', label:'Organization Name', type:'text' }] },
  { id: 'aws',         label: 'AWS',          icon: '☁️',  fields: [{ name:'access_key', label:'Access Key ID', type:'text' }, { name:'secret_key', label:'Secret Access Key', type:'password' }, { name:'region', label:'Region (e.g. us-east-1)', type:'text' }] },
  { id: 'openai',      label: 'OpenAI',       icon: '🤖', fields: [{ name:'admin_key', label:'Admin API Key', type:'password' }] },
  { id: 'slack',       label: 'Slack',        icon: '💬', fields: [{ name:'token', label:'Bot / User OAuth Token', type:'password' }] },
  { id: 'google',      label: 'Google Cloud', icon: '🌐', fields: [{ name:'credentials_path', label:'Service Account JSON Path (inside container)', type:'text' }, { name:'project_id', label:'GCP Project ID', type:'text' }] },
  { id: 'azure',       label: 'Azure',        icon: '🔷', fields: [{ name:'tenant_id', label:'Tenant ID', type:'text' }, { name:'client_id', label:'Client ID', type:'text' }, { name:'client_secret', label:'Client Secret', type:'password' }] },
  { id: 'gitlab',      label: 'GitLab',       icon: '🦊', fields: [{ name:'token', label:'Personal Access Token', type:'password' }, { name:'group', label:'Group Name', type:'text' }] },
  { id: 'anthropic',   label: 'Anthropic',    icon: '🧠', fields: [{ name:'admin_key', label:'Admin API Key', type:'password' }] },
  { id: 'okta',        label: 'Okta',         icon: '🔐', fields: [{ name:'domain', label:'Domain (e.g. company.okta.com)', type:'text' }, { name:'api_token', label:'API Token', type:'password' }] },
  { id: 'jira',        label: 'Jira',         icon: '📋', fields: [{ name:'base_url', label:'Base URL (https://org.atlassian.net)', type:'text' }, { name:'email', label:'Admin Email', type:'text' }, { name:'api_token', label:'API Token', type:'password' }] },
  { id: 'salesforce',  label: 'Salesforce',   icon: '☁️',  fields: [{ name:'instance_url', label:'Instance URL', type:'text' }, { name:'access_token', label:'Access Token', type:'password' }] },
  { id: 'stripe',      label: 'Stripe',       icon: '💳', fields: [{ name:'secret_key', label:'Secret Key (sk_live_...)', type:'password' }] },
  { id: 'twilio',      label: 'Twilio',       icon: '📱', fields: [{ name:'account_sid', label:'Account SID', type:'text' }, { name:'auth_token', label:'Auth Token', type:'password' }] },
  { id: 'hubspot',     label: 'HubSpot',      icon: '🟠', fields: [{ name:'access_token', label:'Private App Token', type:'password' }] },
  { id: 'gcp',         label: 'GCP (IAM)',    icon: '🏗️', fields: [{ name:'credentials_path', label:'Service Account JSON Path', type:'text' }, { name:'project_id', label:'Project ID', type:'text' }] },
];

const STEPS = ['Welcome', 'Connect Platforms', 'Scan & Discover', 'Done'];

export default function Onboarding() {
  const navigate = useNavigate();
  const [step, setStep]           = useState(0);
  const [selected, setSelected]   = useState(new Set());
  const [configs, setConfigs]     = useState({});
  const [saving, setSaving]       = useState(false);
  const [scanning, setScanning]   = useState(false);
  const [scanResult, setScanResult] = useState(null);
  const [errors, setErrors]       = useState({});

  // ── Step helpers ──────────────────────────────────────────────────────────

  const togglePlatform = (id) => {
    setSelected(prev => {
      const next = new Set(prev);
      next.has(id) ? next.delete(id) : next.add(id);
      return next;
    });
    if (!configs[id]) {
      setConfigs(prev => ({ ...prev, [id]: {} }));
    }
  };

  const setField = (platform, field, value) => {
    setConfigs(prev => ({
      ...prev,
      [platform]: { ...(prev[platform] || {}), [field]: value }
    }));
  };

  const saveIntegrations = async () => {
    setSaving(true);
    setErrors({});
    let ok = 0;
    const errs = {};
    for (const pid of selected) {
      try {
        await axios.post('/api/integrations', { platform: pid, config: configs[pid] || {} });
        ok++;
      } catch (e) {
        errs[pid] = e.response?.data?.error || 'Connection failed';
      }
    }
    setSaving(false);
    setErrors(errs);
    if (ok > 0) setStep(2);
  };

  const runScan = async () => {
    setScanning(true);
    try {
      const r = await axios.post('/api/discovery/trigger');
      setScanResult(r.data);
      setStep(3);
    } catch (e) {
      setScanResult({ error: e.response?.data?.error || 'Scan failed' });
    }
    setScanning(false);
  };

  // ── Render ────────────────────────────────────────────────────────────────

  return (
    <div className="min-h-screen bg-gray-950 text-white flex flex-col items-center justify-start py-12 px-4">
      {/* Header */}
      <div className="mb-8 text-center">
        <div className="text-4xl mb-2">🛡️</div>
        <h1 className="text-3xl font-bold text-white">NHI Shield Setup</h1>
        <p className="text-gray-400 mt-1">Connect your platforms to begin discovering non-human identities</p>
      </div>

      {/* Stepper */}
      <div className="flex items-center mb-10 gap-2">
        {STEPS.map((s, i) => (
          <React.Fragment key={s}>
            <div className={`flex items-center gap-2 px-3 py-1 rounded-full text-sm font-medium
              ${i === step ? 'bg-blue-600 text-white' : i < step ? 'bg-green-700 text-white' : 'bg-gray-800 text-gray-400'}`}>
              {i < step ? '✓' : i + 1}. {s}
            </div>
            {i < STEPS.length - 1 && <div className="w-6 h-px bg-gray-700" />}
          </React.Fragment>
        ))}
      </div>

      <div className="w-full max-w-3xl">
        {/* ── Step 0: Welcome ── */}
        {step === 0 && (
          <div className="bg-gray-900 rounded-2xl p-8 text-center border border-gray-800">
            <div className="text-6xl mb-4">🔍</div>
            <h2 className="text-2xl font-bold mb-3">Welcome to NHI Shield</h2>
            <p className="text-gray-300 mb-6 max-w-lg mx-auto">
              We'll connect to your platforms, discover all non-human identities (API keys, service accounts, bots),
              score their risk, and alert you to anomalies — automatically.
            </p>
            <div className="grid grid-cols-3 gap-4 mb-8 text-sm">
              {[['🔗', '15+ Platforms', 'GitHub, AWS, GCP, Okta, Stripe...'],
                ['🤖', 'AI Detection', 'Behavioral anomaly ML engine'],
                ['📊', 'Zero Trust', 'Continuous policy enforcement']].map(([icon, title, sub]) => (
                <div key={title} className="bg-gray-800 rounded-xl p-4">
                  <div className="text-2xl mb-1">{icon}</div>
                  <div className="font-semibold">{title}</div>
                  <div className="text-gray-400">{sub}</div>
                </div>
              ))}
            </div>
            <button
              onClick={() => setStep(1)}
              className="bg-blue-600 hover:bg-blue-700 text-white font-semibold py-3 px-8 rounded-xl transition"
            >
              Get Started →
            </button>
          </div>
        )}

        {/* ── Step 1: Connect Platforms ── */}
        {step === 1 && (
          <div className="space-y-6">
            <h2 className="text-xl font-bold">Select platforms to connect</h2>

            {/* Platform selector */}
            <div className="grid grid-cols-3 sm:grid-cols-4 gap-3">
              {PLATFORMS.map(p => (
                <button
                  key={p.id}
                  onClick={() => togglePlatform(p.id)}
                  className={`rounded-xl p-3 text-center border transition text-sm
                    ${selected.has(p.id)
                      ? 'bg-blue-900 border-blue-500 text-white'
                      : 'bg-gray-800 border-gray-700 text-gray-300 hover:border-gray-500'}`}
                >
                  <div className="text-2xl mb-1">{p.icon}</div>
                  <div className="font-medium">{p.label}</div>
                  {errors[p.id] && <div className="text-red-400 text-xs mt-1">{errors[p.id]}</div>}
                </button>
              ))}
            </div>

            {/* Config fields for selected platforms */}
            {selected.size > 0 && (
              <div className="space-y-4">
                <h3 className="text-lg font-semibold text-gray-300">Configure selected platforms</h3>
                {PLATFORMS.filter(p => selected.has(p.id)).map(p => (
                  <div key={p.id} className="bg-gray-900 border border-gray-800 rounded-xl p-5">
                    <div className="font-semibold mb-3 flex items-center gap-2">
                      <span>{p.icon}</span> {p.label}
                    </div>
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                      {p.fields.map(f => (
                        <div key={f.name}>
                          <label className="text-sm text-gray-400 block mb-1">{f.label}</label>
                          <input
                            type={f.type}
                            placeholder={f.type === 'password' ? '••••••••' : f.label}
                            value={configs[p.id]?.[f.name] || ''}
                            onChange={e => setField(p.id, f.name, e.target.value)}
                            className="w-full bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:border-blue-500"
                          />
                        </div>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            )}

            <div className="flex justify-between">
              <button onClick={() => setStep(0)} className="text-gray-400 hover:text-white transition">← Back</button>
              <button
                onClick={saveIntegrations}
                disabled={selected.size === 0 || saving}
                className="bg-blue-600 hover:bg-blue-700 disabled:opacity-50 text-white font-semibold py-2 px-6 rounded-xl transition"
              >
                {saving ? 'Saving...' : `Connect ${selected.size} platform${selected.size !== 1 ? 's' : ''} →`}
              </button>
            </div>
          </div>
        )}

        {/* ── Step 2: Scan ── */}
        {step === 2 && (
          <div className="bg-gray-900 rounded-2xl p-8 text-center border border-gray-800">
            <div className="text-5xl mb-4">🔍</div>
            <h2 className="text-2xl font-bold mb-3">Ready to discover identities</h2>
            <p className="text-gray-300 mb-6">
              NHI Shield will now scan all connected platforms and build your identity inventory.
              This typically takes 1–5 minutes.
            </p>
            <button
              onClick={runScan}
              disabled={scanning}
              className="bg-green-600 hover:bg-green-700 disabled:opacity-50 text-white font-semibold py-3 px-8 rounded-xl transition"
            >
              {scanning ? (
                <span className="flex items-center gap-2">
                  <span className="animate-spin">⟳</span> Scanning platforms...
                </span>
              ) : 'Start Discovery Scan →'}
            </button>
          </div>
        )}

        {/* ── Step 3: Done ── */}
        {step === 3 && (
          <div className="bg-gray-900 rounded-2xl p-8 text-center border border-green-800">
            <div className="text-5xl mb-4">🎉</div>
            <h2 className="text-2xl font-bold mb-3 text-green-400">Setup Complete!</h2>
            {scanResult && !scanResult.error && (
              <div className="grid grid-cols-3 gap-4 mb-6 text-sm">
                {[
                  ['Identities Found', scanResult.discovered || 0, 'text-blue-400'],
                  ['Platforms Scanned', scanResult.platforms_scanned || 0, 'text-purple-400'],
                  ['High Risk', scanResult.high_risk || 0, 'text-red-400'],
                ].map(([label, val, color]) => (
                  <div key={label} className="bg-gray-800 rounded-xl p-4">
                    <div className={`text-3xl font-bold ${color}`}>{val}</div>
                    <div className="text-gray-400">{label}</div>
                  </div>
                ))}
              </div>
            )}
            {scanResult?.error && (
              <div className="text-red-400 mb-4 bg-red-900/30 rounded-lg p-3">{scanResult.error}</div>
            )}
            <button
              onClick={() => navigate('/dashboard')}
              className="bg-blue-600 hover:bg-blue-700 text-white font-semibold py-3 px-8 rounded-xl transition"
            >
              Go to Dashboard →
            </button>
          </div>
        )}
      </div>
    </div>
  );
}
