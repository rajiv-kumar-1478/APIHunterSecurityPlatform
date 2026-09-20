'use client';

import React, { useCallback, useEffect, useState } from 'react';
import { useRouter } from 'next/navigation';
import { AppLayout } from '@/components/AppLayout';
import { apiRequest } from '@/lib/api-client';

interface AiProviderDto {
  id: string;
  providerName: string;
  modelName: string;
  priority: number;
  isEnabled: boolean;
  isKeyConfigured: boolean;
  keyPreview: string;
  capabilities: string[];
  healthStatus: string;
  lastSuccessAtUtc: string | null;
  lastFailureAtUtc: string | null;
  lastErrorReason: string | null;
  rateLimitResetAtUtc: string | null;
  remainingQuota: number;
  totalCallsCount: number;
  failedCallsCount: number;
}

interface GlobalAiStateDto {
  isEnabled: boolean;
  statusMessage: string;
}

interface AiTestResultDto {
  status: string;
  message: string;
  isSuccess: boolean;
  testedAtUtc: string;
}

async function requestAiSettings(): Promise<[AiProviderDto[], GlobalAiStateDto]> {
  return Promise.all([
    apiRequest<AiProviderDto[]>('/api/v1/ai/providers'),
    apiRequest<GlobalAiStateDto>('/api/v1/ai/global-state'),
  ]);
}

export default function AdminAiSettingsPage() {
  const router = useRouter();
  const [user, setUser] = useState<{ isPlatformAdmin: boolean; email?: string } | null>(null);
  const [providers, setProviders] = useState<AiProviderDto[]>([]);
  const [globalState, setGlobalState] = useState<GlobalAiStateDto | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [actionMessage, setActionMessage] = useState<{ type: 'success' | 'error' | 'info'; text: string } | null>(null);
  const [editingProvider, setEditingProvider] = useState<AiProviderDto | null>(null);
  const [editModelName, setEditModelName] = useState('');
  const [editPriority, setEditPriority] = useState(100);
  const [editRawApiKey, setEditRawApiKey] = useState('');
  const [showAddModal, setShowAddModal] = useState(false);
  const [addProviderName, setAddProviderName] = useState('Cohere');
  const [addModelName, setAddModelName] = useState('command-r-plus-08-2024');
  const [addPriority, setAddPriority] = useState(100);
  const [addRawApiKey, setAddRawApiKey] = useState('');

  const fetchAiSettings = useCallback(async () => {
    try {
      const [providerData, globalData] = await requestAiSettings();
      setProviders(providerData);
      setGlobalState(globalData);
    } catch (error: unknown) {
      console.error('Failed to load AI provider settings:', error);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    async function init() {
      try {
        const me = await apiRequest<{ isPlatformAdmin: boolean; email?: string }>('/api/v1/auth/me');
        if (!me.isPlatformAdmin) {
          router.replace('/dashboard');
          return;
        }
        setUser(me);
        await fetchAiSettings();
      } catch {
        router.replace('/login');
      }
    }
    void init();
  }, [router, fetchAiSettings]);

  const handleProviderSelect = (name: string) => {
    setAddProviderName(name);
    switch (name) {
      case 'Cohere':
        setAddModelName('command-r-plus-08-2024');
        break;
      case 'OpenAI':
        setAddModelName('gpt-4o');
        break;
      case 'Anthropic':
        setAddModelName('claude-3-5-sonnet-20241022');
        break;
      case 'DeepSeek':
        setAddModelName('deepseek-chat');
        break;
      case 'Groq':
        setAddModelName('llama-3.3-70b-versatile');
        break;
      default:
        break;
    }
  };

  const handleCreateProvider = async () => {
    try {
      await apiRequest<unknown>('/api/v1/ai/providers', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          providerName: addProviderName,
          modelName: addModelName,
          priority: addPriority,
          isEnabled: true,
          rawApiKey: addRawApiKey ? addRawApiKey : null,
          capabilities: ['JsonOutput'],
        }),
      });
      setActionMessage({ type: 'success', text: `Provider ${addProviderName} configured successfully.` });
      setShowAddModal(false);
      setAddRawApiKey('');
      await fetchAiSettings();
    } catch {
      setActionMessage({ type: 'error', text: 'Failed to create provider configuration.' });
    }
  };

  const toggleGlobalAi = async () => {
    if (!globalState) return;
    try {
      const data = await apiRequest<GlobalAiStateDto>('/api/v1/ai/global-state', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ isEnabled: !globalState.isEnabled }),
      });
      setGlobalState(data);
      setActionMessage({
        type: 'info',
        text: data.isEnabled ? 'Global AI Analysis ENABLED.' : 'Global AI Analysis PAUSED. Queued jobs are preserved.',
      });
    } catch {
      setActionMessage({ type: 'error', text: 'Failed to update global AI pause state.' });
    }
  };

  const toggleProvider = async (id: string, currentEnabled: boolean) => {
    try {
      await apiRequest<unknown>(`/api/v1/ai/providers/${id}/toggle`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ isEnabled: !currentEnabled }),
      });
      setActionMessage({ type: 'success', text: 'Provider enabled status updated.' });
      await fetchAiSettings();
    } catch {
      setActionMessage({ type: 'error', text: 'Failed to toggle provider status.' });
    }
  };

  const resetCooldown = async (id: string) => {
    try {
      await apiRequest<unknown>(`/api/v1/ai/providers/${id}/reset-cooldown`, {
        method: 'POST',
      });
      setActionMessage({ type: 'success', text: 'Provider cooldown & health status reset.' });
      await fetchAiSettings();
    } catch {
      setActionMessage({ type: 'error', text: 'Failed to reset provider cooldown.' });
    }
  };

  const testProvider = async (id: string) => {
    try {
      setActionMessage({ type: 'info', text: 'Testing provider connection...' });
      const testResult = await apiRequest<AiTestResultDto>(`/api/v1/ai/providers/${id}/test`, {
        method: 'POST',
      });
      setActionMessage({
        type: testResult.isSuccess ? 'success' : 'error',
        text: `[${testResult.status}] ${testResult.message}`,
      });
      await fetchAiSettings();
    } catch {
      setActionMessage({ type: 'error', text: 'Error testing provider connectivity.' });
    }
  };

  const handleSaveEdit = async () => {
    if (!editingProvider) return;
    try {
      await apiRequest<unknown>(`/api/v1/ai/providers/${editingProvider.id}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          modelName: editModelName,
          priority: editPriority,
          rawApiKey: editRawApiKey ? editRawApiKey : null,
        }),
      });
      setActionMessage({ type: 'success', text: 'Provider configuration saved successfully.' });
      setEditingProvider(null);
      setEditRawApiKey('');
      await fetchAiSettings();
    } catch {
      setActionMessage({ type: 'error', text: 'Failed to update provider configuration.' });
    }
  };

  if (!user) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-[#080c14]">
        <div className="w-8 h-8 border-2 border-[#00d4ff] border-t-transparent rounded-full animate-spin" />
      </div>
    );
  }

  return (
    <AppLayout
      isAdmin={user.isPlatformAdmin}
      userEmail={user.email}
      title="AI Intelligence Providers"
      subtitle="Manage provider priority, fallback routing, API key isolation, and rate-limit cooldowns."
      actions={
        <div className="flex flex-wrap items-center gap-3">
          <button
            onClick={() => setShowAddModal(true)}
            className="btn-primary text-xs flex items-center gap-1.5"
          >
            <svg className="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><line x1="12" y1="5" x2="12" y2="19" /><line x1="5" y1="12" x2="19" y2="12" /></svg>
            <span>Add Provider</span>
          </button>
          {globalState && (
            <button
              onClick={toggleGlobalAi}
              className={`px-3 py-1.5 rounded-lg text-xs font-bold transition flex items-center gap-2 border ${
                globalState.isEnabled
                  ? 'bg-[#00ff88]/10 text-[#00ff88] border-[#00ff88]/30 hover:bg-[#00ff88]/20'
                  : 'bg-[#ff4757]/10 text-[#ff4757] border-[#ff4757]/30 hover:bg-[#ff4757]/20'
              }`}
            >
              <span className={`w-2 h-2 rounded-full ${globalState.isEnabled ? 'bg-[#00ff88]' : 'bg-[#ff4757]'}`} />
              <span>{globalState.isEnabled ? 'Global AI Active' : 'Global AI Paused'}</span>
            </button>
          )}
        </div>
      }
    >
      {/* Action Messages */}
      {actionMessage && (
        <div
          className={`p-4 rounded-xl border text-xs font-semibold flex items-center justify-between fade-in ${
            actionMessage.type === 'success'
              ? 'bg-[#00ff88]/10 border-[#00ff88]/30 text-[#00ff88]'
              : actionMessage.type === 'error'
              ? 'bg-[#ff4757]/10 border-[#ff4757]/30 text-[#ff4757]'
              : 'bg-[#00d4ff]/10 border-[#00d4ff]/30 text-[#00d4ff]'
          }`}
        >
          <span>{actionMessage.text}</span>
          <button onClick={() => setActionMessage(null)} className="hover:underline font-bold">✕</button>
        </div>
      )}

      {/* Provider Registry Table Card */}
      <div className="glass-card overflow-hidden fade-in">
        <div className="overflow-x-auto">
          <table className="w-full text-left border-collapse min-w-[800px]">
            <thead>
              <tr className="border-b border-[#00d4ff]/10 text-xs font-semibold uppercase text-[#4a6580] bg-white/[0.02]">
                <th className="p-4">Provider</th>
                <th className="p-4">Model</th>
                <th className="p-4">Priority</th>
                <th className="p-4">Status</th>
                <th className="p-4">Health</th>
                <th className="p-4">API Key</th>
                <th className="p-4">Quota / Reset</th>
                <th className="p-4 text-right">Actions</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#00d4ff]/10 text-xs">
              {loading ? (
                <tr>
                  <td colSpan={8} className="p-8 text-center text-[#7ba3c8]">
                    Loading AI provider configurations...
                  </td>
                </tr>
              ) : providers.length === 0 ? (
                <tr>
                  <td colSpan={8} className="p-8 text-center text-[#7ba3c8]">
                    No AI provider configurations found. Click &quot;Add Provider&quot; to configure.
                  </td>
                </tr>
              ) : (
                providers.map((p) => (
                  <tr key={p.id} className="hover:bg-white/[0.02] transition-colors">
                    <td className="p-4 font-bold text-[#e8f4ff]">{p.providerName}</td>
                    <td className="p-4 font-mono text-[#00d4ff]">{p.modelName}</td>
                    <td className="p-4">
                      <span className="badge badge-admin">P-{p.priority}</span>
                    </td>
                    <td className="p-4">
                      <span className={`badge ${p.isEnabled ? 'badge-healthy' : 'badge-unhealthy'}`}>
                        {p.isEnabled ? 'Enabled' : 'Disabled'}
                      </span>
                    </td>
                    <td className="p-4">
                      <span
                        className={`font-semibold ${
                          p.healthStatus === 'Healthy'
                            ? 'text-[#00ff88]'
                            : p.healthStatus === 'RateLimited'
                            ? 'text-[#ffa502]'
                            : 'text-[#ff4757]'
                        }`}
                      >
                        {p.healthStatus}
                      </span>
                    </td>
                    <td className="p-4 font-mono text-[#7ba3c8]">
                      {p.isKeyConfigured ? (
                        <span className="text-[#00ff88]">Configured ({p.keyPreview})</span>
                      ) : (
                        <span className="text-[#ffa502]">Not Configured</span>
                      )}
                    </td>
                    <td className="p-4 text-[#7ba3c8]">
                      <div>{p.remainingQuota ? `${p.remainingQuota} remaining` : 'Dynamic'}</div>
                      {p.rateLimitResetAtUtc && (
                        <div className="text-[#ffa502] text-[10px] mt-0.5">
                          Reset: {new Date(p.rateLimitResetAtUtc).toLocaleTimeString()}
                        </div>
                      )}
                    </td>
                    <td className="p-4 text-right">
                      <div className="flex items-center justify-end gap-2">
                        <button
                          onClick={() => toggleProvider(p.id, p.isEnabled)}
                          className="btn-secondary text-[11px] py-1 px-2.5"
                        >
                          {p.isEnabled ? 'Disable' : 'Enable'}
                        </button>
                        <button
                          onClick={() => testProvider(p.id)}
                          className="btn-primary text-[11px] py-1 px-2.5"
                        >
                          Test
                        </button>
                        {p.healthStatus === 'RateLimited' && (
                          <button
                            onClick={() => resetCooldown(p.id)}
                            className="px-2.5 py-1 rounded-lg text-[11px] font-semibold bg-[#ffa502]/20 text-[#ffa502] hover:bg-[#ffa502]/30 border border-[#ffa502]/40 transition"
                          >
                            Reset
                          </button>
                        )}
                        <button
                          onClick={() => {
                            setEditingProvider(p);
                            setEditModelName(p.modelName);
                            setEditPriority(p.priority);
                          }}
                          className="btn-secondary text-[11px] py-1 px-2.5"
                        >
                          Edit
                        </button>
                      </div>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Edit Provider Modal */}
      {editingProvider && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-md flex items-center justify-center p-4 fade-in">
          <div className="glass-card max-w-md w-full p-6 border-[#00d4ff]/30 space-y-4">
            <h3 className="text-base font-bold text-[#e8f4ff]" style={{ fontFamily: 'Outfit, sans-serif' }}>
              Configure {editingProvider.providerName}
            </h3>

            <div className="space-y-1">
              <label className="text-xs text-[#7ba3c8] font-medium">Model Name</label>
              <input
                type="text"
                value={editModelName}
                onChange={(e) => setEditModelName(e.target.value)}
                className="w-full bg-[#080c14] border border-[#00d4ff]/20 rounded-xl p-2.5 text-xs text-[#e8f4ff] focus:outline-none focus:border-[#00d4ff]"
              />
            </div>

            <div className="space-y-1">
              <label className="text-xs text-[#7ba3c8] font-medium">Priority (Higher = Preferred Fallback)</label>
              <input
                type="number"
                value={editPriority}
                onChange={(e) => setEditPriority(Number(e.target.value))}
                className="w-full bg-[#080c14] border border-[#00d4ff]/20 rounded-xl p-2.5 text-xs text-[#e8f4ff] focus:outline-none focus:border-[#00d4ff]"
              />
            </div>

            <div className="space-y-1">
              <label className="text-xs text-[#7ba3c8] font-medium">New API Key (Leave blank to keep existing)</label>
              <input
                type="password"
                placeholder="Paste API Key here..."
                value={editRawApiKey}
                onChange={(e) => setEditRawApiKey(e.target.value)}
                className="w-full bg-[#080c14] border border-[#00d4ff]/20 rounded-xl p-2.5 text-xs text-[#e8f4ff] placeholder-[#4a6580] focus:outline-none focus:border-[#00d4ff]"
              />
            </div>

            <div className="flex justify-end gap-3 pt-2">
              <button
                onClick={() => setEditingProvider(null)}
                className="btn-secondary text-xs"
              >
                Cancel
              </button>
              <button
                onClick={handleSaveEdit}
                className="btn-primary text-xs"
              >
                Save Provider
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Add Provider Modal */}
      {showAddModal && (
        <div className="fixed inset-0 z-50 bg-black/80 backdrop-blur-md flex items-center justify-center p-4 fade-in">
          <div className="glass-card max-w-md w-full p-6 border-[#00d4ff]/30 space-y-4">
            <h3 className="text-base font-bold text-[#e8f4ff]" style={{ fontFamily: 'Outfit, sans-serif' }}>
              Add AI Intelligence Provider
            </h3>

            <div className="space-y-1">
              <label className="text-xs text-[#7ba3c8] font-medium">Provider</label>
              <select
                value={addProviderName}
                onChange={(e) => handleProviderSelect(e.target.value)}
                className="w-full bg-[#080c14] border border-[#00d4ff]/20 rounded-xl p-2.5 text-xs text-[#e8f4ff] focus:outline-none focus:border-[#00d4ff]"
              >
                <option value="Cohere">Cohere</option>
                <option value="OpenAI">OpenAI</option>
                <option value="Anthropic">Anthropic</option>
                <option value="DeepSeek">DeepSeek</option>
                <option value="Groq">Groq</option>
              </select>
            </div>

            <div className="space-y-1">
              <label className="text-xs text-[#7ba3c8] font-medium">Model Name</label>
              <input
                type="text"
                value={addModelName}
                onChange={(e) => setAddModelName(e.target.value)}
                placeholder="e.g. command-r-plus-08-2024"
                className="w-full bg-[#080c14] border border-[#00d4ff]/20 rounded-xl p-2.5 text-xs text-[#e8f4ff] placeholder-[#4a6580] focus:outline-none focus:border-[#00d4ff]"
              />
            </div>

            <div className="space-y-1">
              <label className="text-xs text-[#7ba3c8] font-medium">Priority (Higher = Preferred Fallback)</label>
              <input
                type="number"
                value={addPriority}
                onChange={(e) => setAddPriority(Number(e.target.value))}
                className="w-full bg-[#080c14] border border-[#00d4ff]/20 rounded-xl p-2.5 text-xs text-[#e8f4ff] focus:outline-none focus:border-[#00d4ff]"
              />
            </div>

            <div className="space-y-1">
              <label className="text-xs text-[#7ba3c8] font-medium">Provider API Key</label>
              <input
                type="password"
                placeholder="Paste API Key here..."
                value={addRawApiKey}
                onChange={(e) => setAddRawApiKey(e.target.value)}
                className="w-full bg-[#080c14] border border-[#00d4ff]/20 rounded-xl p-2.5 text-xs text-[#e8f4ff] placeholder-[#4a6580] focus:outline-none focus:border-[#00d4ff]"
              />
            </div>

            <div className="flex justify-end gap-3 pt-2">
              <button
                onClick={() => setShowAddModal(false)}
                className="btn-secondary text-xs"
              >
                Cancel
              </button>
              <button
                onClick={handleCreateProvider}
                className="btn-primary text-xs"
              >
                Save Provider
              </button>
            </div>
          </div>
        </div>
      )}
    </AppLayout>
  );
}
