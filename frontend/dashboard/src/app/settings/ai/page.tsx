'use client';

import React, { useCallback, useEffect, useState } from 'react';
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
  const [providers, setProviders] = useState<AiProviderDto[]>([]);
  const [globalState, setGlobalState] = useState<GlobalAiStateDto | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [actionMessage, setActionMessage] = useState<{ type: 'success' | 'error' | 'info'; text: string } | null>(null);
  const [editingProvider, setEditingProvider] = useState<AiProviderDto | null>(null);
  const [editModelName, setEditModelName] = useState('');
  const [editPriority, setEditPriority] = useState(100);
  const [editRawApiKey, setEditRawApiKey] = useState('');

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
    let cancelled = false;
    void requestAiSettings()
      .then(([providerData, globalData]) => {
        if (cancelled) return;
        setProviders(providerData);
        setGlobalState(globalData);
      })
      .catch((error: unknown) => {
        if (!cancelled) console.error('Failed to load AI provider settings:', error);
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });

    return () => {
      cancelled = true;
    };
  }, []);

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

  return (
    <div style={{ padding: '24px', backgroundColor: '#0b0f19', color: '#f3f4f6', minHeight: '100vh', fontFamily: 'Inter, sans-serif' }}>
      {/* Header Banner */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '24px', borderBottom: '1px solid #1f2937', paddingBottom: '16px' }}>
        <div>
          <h1 style={{ fontSize: '24px', fontWeight: '700', color: '#6366f1', margin: 0 }}>AI Intelligence Provider Routing Controls</h1>
          <p style={{ color: '#9ca3af', fontSize: '14px', marginTop: '4px' }}>
            Manage provider priority, fallback routing, API key isolation, and rate-limit cooldowns.
          </p>
        </div>

        {/* Global AI Pause Toggle */}
        {globalState && (
          <div style={{ display: 'flex', alignItems: 'center', gap: '12px', backgroundColor: '#111827', padding: '10px 16px', borderRadius: '8px', border: '1px solid #374151' }}>
            <span style={{ fontSize: '13px', fontWeight: '600', color: '#d1d5db' }}>GLOBAL AI ANALYSIS:</span>
            <button
              onClick={toggleGlobalAi}
              style={{
                backgroundColor: globalState.isEnabled ? '#10b981' : '#ef4444',
                color: '#ffffff',
                border: 'none',
                padding: '6px 14px',
                borderRadius: '6px',
                fontWeight: '700',
                fontSize: '12px',
                cursor: 'pointer',
                letterSpacing: '0.5px'
              }}
            >
              {globalState.isEnabled ? '[ ENABLED ]' : '[ PAUSED ]'}
            </button>
          </div>
        )}
      </div>

      {actionMessage && (
        <div style={{
          padding: '12px 16px',
          borderRadius: '6px',
          marginBottom: '20px',
          backgroundColor: actionMessage.type === 'success' ? '#064e3b' : actionMessage.type === 'error' ? '#7f1d1d' : '#1e3a8a',
          color: actionMessage.type === 'success' ? '#34d399' : actionMessage.type === 'error' ? '#fca5a5' : '#93c5fd',
          border: '1px solid currentColor',
          fontSize: '14px'
        }}>
          {actionMessage.text}
        </div>
      )}

      {/* Provider Registry Table */}
      <div style={{ backgroundColor: '#111827', borderRadius: '8px', border: '1px solid #1f2937', overflow: 'hidden' }}>
        <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '14px' }}>
          <thead>
            <tr style={{ backgroundColor: '#1f2937', color: '#9ca3af', textTransform: 'uppercase', fontSize: '11px', letterSpacing: '0.05em' }}>
              <th style={{ padding: '14px 16px' }}>Provider</th>
              <th style={{ padding: '14px 16px' }}>Model</th>
              <th style={{ padding: '14px 16px' }}>Priority</th>
              <th style={{ padding: '14px 16px' }}>Status</th>
              <th style={{ padding: '14px 16px' }}>Health</th>
              <th style={{ padding: '14px 16px' }}>API Key</th>
              <th style={{ padding: '14px 16px' }}>Quota / Reset</th>
              <th style={{ padding: '14px 16px' }}>Actions</th>
            </tr>
          </thead>
          <tbody>
            {loading ? (
              <tr>
                <td colSpan={8} style={{ padding: '24px', textAlign: 'center', color: '#6b7280' }}>Loading AI provider configurations...</td>
              </tr>
            ) : providers.length === 0 ? (
              <tr>
                <td colSpan={8} style={{ padding: '24px', textAlign: 'center', color: '#6b7280' }}>No AI provider configurations found.</td>
              </tr>
            ) : (
              providers.map((p) => (
                <tr key={p.id} style={{ borderBottom: '1px solid #1f2937' }}>
                  <td style={{ padding: '14px 16px', fontWeight: '600', color: '#ffffff' }}>{p.providerName}</td>
                  <td style={{ padding: '14px 16px', color: '#818cf8', fontFamily: 'monospace' }}>{p.modelName}</td>
                  <td style={{ padding: '14px 16px' }}>
                    <span style={{ backgroundColor: '#374151', color: '#f3f4f6', padding: '2px 8px', borderRadius: '4px', fontSize: '12px', fontWeight: '600' }}>
                      P-{p.priority}
                    </span>
                  </td>
                  <td style={{ padding: '14px 16px' }}>
                    <span style={{
                      color: p.isEnabled ? '#34d399' : '#9ca3af',
                      backgroundColor: p.isEnabled ? '#064e3b' : '#374151',
                      padding: '2px 8px', borderRadius: '4px', fontSize: '12px'
                    }}>
                      {p.isEnabled ? 'Enabled' : 'Disabled'}
                    </span>
                  </td>
                  <td style={{ padding: '14px 16px' }}>
                    <span style={{
                      color: p.healthStatus === 'Healthy' ? '#34d399' : p.healthStatus === 'RateLimited' ? '#f59e0b' : '#ef4444',
                      fontWeight: '600', fontSize: '12px'
                    }}>
                      {p.healthStatus}
                    </span>
                  </td>
                  <td style={{ padding: '14px 16px', fontFamily: 'monospace', color: '#9ca3af' }}>
                    {p.isKeyConfigured ? <span style={{ color: '#10b981' }}>Configured ({p.keyPreview})</span> : <span style={{ color: '#f59e0b' }}>Not Configured</span>}
                  </td>
                  <td style={{ padding: '14px 16px', fontSize: '12px', color: '#9ca3af' }}>
                    {p.remainingQuota ? `${p.remainingQuota} remaining` : 'Dynamic'}
                    {p.rateLimitResetAtUtc && (
                      <div style={{ color: '#f59e0b', marginTop: '2px' }}>Reset: {new Date(p.rateLimitResetAtUtc).toLocaleTimeString()}</div>
                    )}
                  </td>
                  <td style={{ padding: '14px 16px' }}>
                    <div style={{ display: 'flex', gap: '8px' }}>
                      <button
                        onClick={() => toggleProvider(p.id, p.isEnabled)}
                        style={{ backgroundColor: '#374151', color: '#ffffff', border: 'none', padding: '4px 10px', borderRadius: '4px', fontSize: '12px', cursor: 'pointer' }}
                      >
                        {p.isEnabled ? 'Disable' : 'Enable'}
                      </button>
                      <button
                        onClick={() => testProvider(p.id)}
                        style={{ backgroundColor: '#4f46e5', color: '#ffffff', border: 'none', padding: '4px 10px', borderRadius: '4px', fontSize: '12px', cursor: 'pointer' }}
                      >
                        Test
                      </button>
                      {p.healthStatus === 'RateLimited' && (
                        <button
                          onClick={() => resetCooldown(p.id)}
                          style={{ backgroundColor: '#d97706', color: '#ffffff', border: 'none', padding: '4px 10px', borderRadius: '4px', fontSize: '12px', cursor: 'pointer' }}
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
                        style={{ backgroundColor: '#1f2937', color: '#9ca3af', border: '1px solid #374151', padding: '4px 10px', borderRadius: '4px', fontSize: '12px', cursor: 'pointer' }}
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

      {/* Edit Provider Modal */}
      {editingProvider && (
        <div style={{ position: 'fixed', top: 0, left: 0, right: 0, bottom: 0, backgroundColor: 'rgba(0,0,0,0.7)', display: 'flex', alignItems: 'center', justifyContent: 'center', zIndex: 100 }}>
          <div style={{ backgroundColor: '#111827', padding: '24px', borderRadius: '8px', width: '400px', border: '1px solid #374151' }}>
            <h3 style={{ margin: '0 0 16px 0', color: '#ffffff' }}>Configure {editingProvider.providerName}</h3>
            
            <div style={{ marginBottom: '14px' }}>
              <label style={{ display: 'block', fontSize: '12px', color: '#9ca3af', marginBottom: '4px' }}>Model Name</label>
              <input
                type="text"
                value={editModelName}
                onChange={(e) => setEditModelName(e.target.value)}
                style={{ width: '100%', padding: '8px', backgroundColor: '#1f2937', border: '1px solid #374151', color: '#ffffff', borderRadius: '4px' }}
              />
            </div>

            <div style={{ marginBottom: '14px' }}>
              <label style={{ display: 'block', fontSize: '12px', color: '#9ca3af', marginBottom: '4px' }}>Priority (Higher = Preferred)</label>
              <input
                type="number"
                value={editPriority}
                onChange={(e) => setEditPriority(Number(e.target.value))}
                style={{ width: '100%', padding: '8px', backgroundColor: '#1f2937', border: '1px solid #374151', color: '#ffffff', borderRadius: '4px' }}
              />
            </div>

            <div style={{ marginBottom: '18px' }}>
              <label style={{ display: 'block', fontSize: '12px', color: '#9ca3af', marginBottom: '4px' }}>New API Key (Leave blank to keep existing key)</label>
              <input
                type="password"
                placeholder="Paste API Key here..."
                value={editRawApiKey}
                onChange={(e) => setEditRawApiKey(e.target.value)}
                style={{ width: '100%', padding: '8px', backgroundColor: '#1f2937', border: '1px solid #374151', color: '#ffffff', borderRadius: '4px' }}
              />
            </div>

            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '10px' }}>
              <button
                onClick={() => setEditingProvider(null)}
                style={{ backgroundColor: '#374151', color: '#ffffff', border: 'none', padding: '6px 14px', borderRadius: '4px', cursor: 'pointer' }}
              >
                Cancel
              </button>
              <button
                onClick={handleSaveEdit}
                style={{ backgroundColor: '#4f46e5', color: '#ffffff', border: 'none', padding: '6px 14px', borderRadius: '4px', cursor: 'pointer' }}
              >
                Save
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
