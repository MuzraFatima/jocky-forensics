import React, { useState, useEffect, useRef } from 'react';
import { api, getExternalServerUrl } from './api.js';
import { getUniqueTargetDevices, getUniqueDeviceCards } from './deviceUtils.js';

/**
 * Format relative time string (e.g. "12s ago", "3m ago", "never")
 */
function formatRelativeTime(dateString) {
  if (!dateString) return 'Never';
  try {
    const then = new Date(dateString).getTime();
    if (isNaN(then)) return 'Never';
    const now = Date.now();
    const diffSec = Math.max(0, Math.floor((now - then) / 1000));
    if (diffSec < 5) return 'Just now';
    if (diffSec < 60) return `${diffSec}s ago`;
    const diffMin = Math.floor(diffSec / 60);
    if (diffMin < 60) return `${diffMin}m ago`;
    const diffHr = Math.floor(diffMin / 60);
    if (diffHr < 24) return `${diffHr}h ago`;
    return `${Math.floor(diffHr / 24)}d ago`;
  } catch {
    return 'Never';
  }
}

/**
 * Computes live online status based on backend is_online flag and last_heartbeat
 */
function isDeviceOnline(device) {
  if (!device) return false;
  if (device.is_revoked || device.status === 'revoked') return false;
  if (device.is_online !== undefined) return Boolean(device.is_online);
  const hb = device.last_seen || device.last_heartbeat;
  if (!hb) return false;
  try {
    const lastHb = new Date(hb).getTime();
    return Date.now() - lastHb < 90000; // 90 seconds
  } catch {
    return false;
  }
}

export default function EndpointDevices({
  selectedDeviceId = null,
  onSelectTarget = () => {},
  onNavigateToScript = null,
}) {
  const [devices, setDevices] = useState([]);
  const [loading, setLoading] = useState(false);
  const [errorMsg, setErrorMsg] = useState(null);
  const [successMsg, setSuccessMsg] = useState(null);

  // Pairing Modal State
  const [isPairModalOpen, setIsPairModalOpen] = useState(false);
  const [pairingLoading, setPairingLoading] = useState(false);
  const [pairingData, setPairingData] = useState(null);
  const [customDeviceName, setCustomDeviceName] = useState('');
  const [pairingError, setPairingError] = useState(null);
  const [copyCodeSuccess, setCopyCodeSuccess] = useState(false);
  const [copyCmdSuccess, setCopyCmdSuccess] = useState(false);
  const [countdown, setCountdown] = useState(600); // 10 minutes

  // Revoke Modal State
  const [deviceToRevoke, setDeviceToRevoke] = useState(null);
  const [revokeLoading, setRevokeLoading] = useState(false);

  // Fetch devices list
  const fetchDevices = async (isBackground = false) => {
    if (!isBackground) setLoading(true);
    setErrorMsg(null);
    try {
      const res = await api.getDevices();
      if (res.ok && res.data) {
        const list = Array.isArray(res.data) ? res.data : (res.data.devices || []);
        setDevices(list);
      } else {
        if (!isBackground) {
          setErrorMsg(res.data?.detail || res.data?.message || 'Failed to fetch endpoint devices.');
        }
      }
    } catch (err) {
      if (!isBackground) {
        setErrorMsg('Network error fetching devices: ' + err.message);
      }
    } finally {
      if (!isBackground) setLoading(false);
    }
  };

  // Periodic polling every 10 seconds (reasonable 5-15s interval)
  useEffect(() => {
    fetchDevices(false);
    const interval = setInterval(() => {
      fetchDevices(true);
    }, 10000);
    return () => clearInterval(interval);
  }, []);

  // Countdown timer for pairing code expiry
  useEffect(() => {
    let timer = null;
    if (isPairModalOpen && pairingData && countdown > 0) {
      timer = setInterval(() => {
        setCountdown((prev) => (prev > 0 ? prev - 1 : 0));
      }, 1000);
    }
    return () => {
      if (timer) clearInterval(timer);
    };
  }, [isPairModalOpen, pairingData, countdown]);

  // Generate pairing code
  const handleOpenPairModal = async () => {
    setIsPairModalOpen(true);
    setPairingLoading(true);
    setPairingError(null);
    setPairingData(null);
    setCopyCodeSuccess(false);
    setCopyCmdSuccess(false);
    setCountdown(600);

    try {
      const name = customDeviceName.trim() || null;
      const res = await api.generatePairingCode(name);
      if (res.ok && res.data) {
        setPairingData(res.data);
        if (res.data.expires_in_seconds) {
          setCountdown(res.data.expires_in_seconds);
        }
      } else {
        setPairingError(res.data?.detail || res.data?.message || 'Failed to generate pairing code.');
      }
    } catch (err) {
      setPairingError('Network error connecting to backend: ' + err.message);
    } finally {
      setPairingLoading(false);
    }
  };

  const handleCopyCode = () => {
    if (!pairingData?.pairing_code) return;
    navigator.clipboard.writeText(pairingData.pairing_code);
    setCopyCodeSuccess(true);
    setTimeout(() => setCopyCodeSuccess(false), 2500);
  };

  const serverUrl = getExternalServerUrl();
  const pairingCommand = pairingData?.pairing_code
    ? `python jocky-agent.py pair --server ${serverUrl} --code ${pairingData.pairing_code}`
    : '';

  const handleCopyCommand = () => {
    if (!pairingCommand) return;
    navigator.clipboard.writeText(pairingCommand);
    setCopyCmdSuccess(true);
    setTimeout(() => setCopyCmdSuccess(false), 2500);
  };

  // Revoke device
  const handleConfirmRevoke = async () => {
    if (!deviceToRevoke) return;
    setRevokeLoading(true);
    try {
      const res = await api.revokeDevice(deviceToRevoke.device_id);
      if (res.ok) {
        setSuccessMsg(`Endpoint '${deviceToRevoke.hostname || deviceToRevoke.device_id}' has been revoked.`);
        setTimeout(() => setSuccessMsg(null), 4000);
        // If revoked device was selected target, reset to Local
        if (selectedDeviceId === deviceToRevoke.device_id) {
          onSelectTarget(null);
        }
        setDeviceToRevoke(null);
        await fetchDevices(false);
      } else {
        setErrorMsg(res.data?.detail || 'Failed to revoke device.');
      }
    } catch (err) {
      setErrorMsg('Error revoking device: ' + err.message);
    } finally {
      setRevokeLoading(false);
    }
  };

  // Countdown display formatting mm:ss
  const formatCountdown = (seconds) => {
    const mins = Math.floor(seconds / 60);
    const secs = seconds % 60;
    return `${String(mins).padStart(2, '0')}:${String(secs).padStart(2, '0')}`;
  };

  const activeEndpoints = getUniqueTargetDevices(devices, selectedDeviceId);
  const onlineCount = activeEndpoints.filter((d) => isDeviceOnline(d)).length;
  const uniqueDeviceCards = getUniqueDeviceCards(devices, selectedDeviceId);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      {/* Target Selector Banner */}
      <div
        style={{
          background: 'linear-gradient(180deg, #FFFFFF 0%, #E8ECEF 100%)',
          borderRadius: '12px',
          border: '1px solid var(--border-color)',
          padding: '1.25rem 1.5rem',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          flexWrap: 'wrap',
          gap: '1rem',
          boxShadow: '0 2px 10px rgba(34, 36, 38, 0.04)',
        }}
      >
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
            <span style={{ fontSize: '1.4rem' }}>🛰️</span>
            <h2 style={{ fontSize: '1.25rem', fontWeight: 800, color: 'var(--color-lava)', margin: 0 }}>
              Endpoint Device Management
            </h2>
            <span
              style={{
                fontSize: '0.72rem',
                fontWeight: 700,
                padding: '0.2rem 0.6rem',
                borderRadius: '4px',
                background: onlineCount > 0 ? 'rgba(92, 128, 43, 0.14)' : 'rgba(34, 36, 38, 0.08)',
                color: onlineCount > 0 ? 'var(--color-algae)' : 'var(--text-muted)',
                border: `1px solid ${onlineCount > 0 ? 'rgba(92, 128, 43, 0.35)' : 'var(--border-subtle)'}`,
              }}
            >
              {onlineCount} OF {activeEndpoints.length} ONLINE
            </span>
          </div>
          <p style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', marginTop: '0.35rem', marginBottom: 0 }}>
            Connect investigator endpoints to execute forensic collectors locally while streaming cryptographic evidence to the central vault.
          </p>
        </div>

        {/* Action Controls */}
        <div style={{ display: 'flex', gap: '0.6rem', alignItems: 'center', flexWrap: 'wrap' }}>
          {/* Target Selector Dropdown */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <span style={{ fontSize: '0.78rem', fontWeight: 700, color: 'var(--text-secondary)' }}>
              Execution Target:
            </span>
            <select
              value={selectedDeviceId || ''}
              onChange={(e) => onSelectTarget(e.target.value || null)}
              style={{
                background: '#FFFFFF',
                border: '1px solid var(--border-color)',
                color: 'var(--color-lava)',
                fontWeight: 600,
                fontSize: '0.82rem',
                padding: '0.45rem 0.8rem',
                borderRadius: '6px',
                cursor: 'pointer',
                outline: 'none',
              }}
            >
              <option value="">💻 Local Machine (Default)</option>
              {activeEndpoints.map((d) => (
                <option key={d.device_id} value={d.device_id}>
                  🛰️ {d.hostname || d.device_id} ({isDeviceOnline(d) ? 'ONLINE' : 'OFFLINE'})
                </option>
              ))}
            </select>
          </div>

          <button
            onClick={() => fetchDevices(false)}
            disabled={loading}
            style={{
              background: 'var(--bg-surface)',
              border: '1px solid var(--border-color)',
              color: 'var(--text-primary)',
              borderRadius: '6px',
              padding: '0.5rem 0.8rem',
              fontSize: '0.8rem',
              fontWeight: 600,
              cursor: loading ? 'not-allowed' : 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: '0.4rem',
            }}
            title="Refresh devices from backend"
          >
            <span style={{ display: 'inline-block', transform: loading ? 'rotate(180deg)' : 'none', transition: 'transform 0.3s' }}>
              ↻
            </span>
            <span>Refresh</span>
          </button>

          <button
            onClick={handleOpenPairModal}
            style={{
              background: '#8BD4E8',
              border: '1px solid #72c7dc',
              color: '#222426',
              borderRadius: '6px',
              padding: '0.5rem 1.1rem',
              fontSize: '0.82rem',
              fontWeight: 800,
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: '0.4rem',
              boxShadow: '0 4px 14px rgba(139, 212, 232, 0.4)',
            }}
          >
            <span>+</span>
            <span>Pair New Endpoint</span>
          </button>
        </div>
      </div>

      {/* Notifications / Alerts */}
      {successMsg && (
        <div
          style={{
            padding: '0.75rem 1rem',
            borderRadius: '8px',
            background: 'rgba(16, 185, 129, 0.12)',
            border: '1px solid rgba(16, 185, 129, 0.3)',
            color: 'var(--accent-emerald)',
            fontSize: '0.82rem',
            display: 'flex',
            alignItems: 'center',
            gap: '0.5rem',
          }}
        >
          <span>✓</span>
          <span>{successMsg}</span>
        </div>
      )}

      {errorMsg && (
        <div
          style={{
            padding: '0.75rem 1rem',
            borderRadius: '8px',
            background: 'rgba(239, 68, 68, 0.12)',
            border: '1px solid rgba(239, 68, 68, 0.3)',
            color: 'var(--accent-rose)',
            fontSize: '0.82rem',
            display: 'flex',
            alignItems: 'center',
            gap: '0.5rem',
          }}
        >
          <span>⚠</span>
          <span>{errorMsg}</span>
        </div>
      )}

      {/* Currently Selected Target Card */}
      <div
        style={{
          background: selectedDeviceId ? 'rgba(14, 165, 233, 0.05)' : 'rgba(99, 102, 241, 0.05)',
          border: `1px solid ${selectedDeviceId ? 'rgba(56, 189, 248, 0.3)' : 'rgba(99, 102, 241, 0.3)'}`,
          borderRadius: '10px',
          padding: '1rem 1.25rem',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'center',
          flexWrap: 'wrap',
          gap: '0.75rem',
        }}
      >
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
          <span style={{ fontSize: '1.3rem' }}>{selectedDeviceId ? '🛰️' : '💻'}</span>
          <div>
            <div style={{ fontSize: '0.75rem', textTransform: 'uppercase', letterSpacing: '0.05em', color: 'var(--text-muted)' }}>
              Active Investigation Target
            </div>
            <div style={{ fontSize: '0.95rem', fontWeight: 700, color: 'var(--text-primary)', marginTop: '0.1rem' }}>
              {selectedDeviceId ? (
                (() => {
                  const dev = devices.find((d) => d.device_id === selectedDeviceId);
                  const online = isDeviceOnline(dev);
                  return (
                    <span style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                      <span>Endpoint: {dev?.hostname || selectedDeviceId}</span>
                      <span
                        style={{
                          fontSize: '0.7rem',
                          fontWeight: 700,
                          padding: '0.1rem 0.45rem',
                          borderRadius: '4px',
                          background: online ? 'rgba(16, 185, 129, 0.15)' : 'rgba(239, 68, 68, 0.15)',
                          color: online ? 'var(--accent-emerald)' : 'var(--accent-rose)',
                          border: `1px solid ${online ? 'rgba(16, 185, 129, 0.3)' : 'rgba(239, 68, 68, 0.3)'}`,
                        }}
                      >
                        {online ? '● ONLINE' : '○ OFFLINE'}
                      </span>
                    </span>
                  );
                })()
              ) : (
                <span>Local Cloud Server (Render / Localhost)</span>
              )}
            </div>
          </div>
        </div>

        <div style={{ display: 'flex', gap: '0.5rem' }}>
          {selectedDeviceId && (
            <button
              onClick={() => onSelectTarget(null)}
              style={{
                background: 'var(--bg-surface)',
                border: '1px solid var(--border-color)',
                color: 'var(--text-secondary)',
                borderRadius: '6px',
                padding: '0.4rem 0.75rem',
                fontSize: '0.75rem',
                fontWeight: 600,
                cursor: 'pointer',
              }}
            >
              Reset to Local
            </button>
          )}
          {onNavigateToScript && (
            <button
              onClick={onNavigateToScript}
              style={{
                background: 'rgba(56, 189, 248, 0.12)',
                border: '1px solid rgba(56, 189, 248, 0.3)',
                color: 'var(--accent-cyan)',
                borderRadius: '6px',
                padding: '0.4rem 0.8rem',
                fontSize: '0.75rem',
                fontWeight: 700,
                cursor: 'pointer',
              }}
            >
              Execute Script on Target →
            </button>
          )}
        </div>
      </div>

      {/* Enrolled Device List / Cards */}
      {devices.length === 0 && !loading ? (
        <div
          style={{
            background: 'var(--bg-card)',
            borderRadius: '12px',
            border: '1px dashed var(--border-color)',
            padding: '3rem 2rem',
            textAlign: 'center',
            display: 'flex',
            flexDirection: 'column',
            alignItems: 'center',
            gap: '1rem',
          }}
        >
          <div
            style={{
              width: '56px',
              height: '56px',
              borderRadius: '50%',
              background: 'rgba(56, 189, 248, 0.1)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              fontSize: '1.75rem',
              color: 'var(--accent-cyan)',
            }}
          >
            🛰️
          </div>
          <div>
            <h3 style={{ fontSize: '1.1rem', fontWeight: 700, color: 'var(--text-primary)', margin: 0 }}>
              No Endpoint Devices Enrolled
            </h3>
            <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', maxWidth: '480px', marginTop: '0.4rem' }}>
              Pair your local laptop, desktop, or cloud VM using the JOCKY CLI agent. Once paired, you can run forensic investigations directly on your device from this dashboard.
            </p>
          </div>
          <button
            onClick={handleOpenPairModal}
            style={{
              background: '#8BD4E8',
              border: '1px solid #72c7dc',
              color: '#222426',
              borderRadius: '6px',
              padding: '0.6rem 1.25rem',
              fontSize: '0.85rem',
              fontWeight: 800,
              cursor: 'pointer',
              boxShadow: '0 4px 14px rgba(139, 212, 232, 0.4)',
            }}
          >
            + Pair First Endpoint
          </button>
        </div>
      ) : (
        <div
          style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fill, minmax(340px, 1fr))',
            gap: '1.25rem',
          }}
        >
          {uniqueDeviceCards.map((device) => {
            const online = isDeviceOnline(device);
            const isSelected = selectedDeviceId === device.device_id;
            const isRevoked = device.is_revoked || device.status === 'revoked';

            return (
              <div
                key={device.device_id}
                style={{
                  background: 'var(--bg-card)',
                  borderRadius: '10px',
                  border: isSelected
                    ? '2px solid var(--accent-cyan)'
                    : '1px solid var(--border-color)',
                  padding: '1.25rem',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '0.9rem',
                  position: 'relative',
                  boxShadow: isSelected ? '0 0 15px rgba(56, 189, 248, 0.15)' : 'none',
                }}
              >
                {/* Header: Name & Status */}
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                  <div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                      <span style={{ fontSize: '1.1rem' }}>
                        {device.platform === 'Windows' ? '🪟' : device.platform === 'Darwin' ? '🍎' : '🐧'}
                      </span>
                      <h3 style={{ fontSize: '0.95rem', fontWeight: 800, color: 'var(--text-primary)', margin: 0 }}>
                        {device.hostname || 'Endpoint Device'}
                      </h3>
                    </div>
                    <div
                      className="font-mono"
                      style={{ fontSize: '0.72rem', color: 'var(--text-muted)', marginTop: '0.2rem' }}
                    >
                      {device.device_id}
                    </div>
                  </div>

                  {/* Status Badge */}
                  <span
                    style={{
                      fontSize: '0.72rem',
                      fontWeight: 700,
                      padding: '0.2rem 0.55rem',
                      borderRadius: '4px',
                      background: isRevoked
                        ? 'rgba(197, 48, 48, 0.12)'
                        : online
                        ? 'rgba(92, 128, 43, 0.14)'
                        : 'rgba(245, 158, 11, 0.12)',
                      color: isRevoked
                        ? '#C53030'
                        : online
                        ? 'var(--color-algae)'
                        : 'var(--accent-amber)',
                      border: `1px solid ${
                        isRevoked
                          ? 'rgba(197, 48, 48, 0.3)'
                          : online
                          ? 'rgba(92, 128, 43, 0.35)'
                          : 'rgba(245, 158, 11, 0.3)'
                      }`,
                      display: 'flex',
                      alignItems: 'center',
                      gap: '0.3rem',
                    }}
                  >
                    <span>{isRevoked ? '✕' : online ? '●' : '○'}</span>
                    <span>{isRevoked ? 'REVOKED' : online ? 'ONLINE' : 'OFFLINE'}</span>
                  </span>
                </div>

                {/* Safe Metadata Grid */}
                <div
                  style={{
                    display: 'grid',
                    gridTemplateColumns: '1fr 1fr',
                    gap: '0.5rem',
                    background: 'var(--bg-surface)',
                    padding: '0.65rem',
                    borderRadius: '6px',
                    border: '1px solid var(--border-subtle)',
                  }}
                >
                  <div>
                    <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>Platform</div>
                    <div style={{ fontSize: '0.78rem', fontWeight: 600, color: 'var(--text-primary)', marginTop: '0.1rem' }}>
                      {device.platform || 'Unknown'} {device.os_version ? `(${device.os_version})` : ''}
                    </div>
                  </div>

                  <div>
                    <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>Agent Version</div>
                    <div className="font-mono" style={{ fontSize: '0.78rem', fontWeight: 600, color: 'var(--text-primary)', marginTop: '0.1rem' }}>
                      v{device.agent_version || '1.0.0'}
                    </div>
                  </div>

                  <div>
                    <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>Last Heartbeat</div>
                    <div style={{ fontSize: '0.78rem', fontWeight: 600, color: online ? 'var(--accent-emerald)' : 'var(--text-secondary)', marginTop: '0.1rem' }}>
                      {formatRelativeTime(device.last_seen || device.last_heartbeat)}
                    </div>
                  </div>

                  <div>
                    <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>Enrolled</div>
                    <div style={{ fontSize: '0.78rem', fontWeight: 600, color: 'var(--text-secondary)', marginTop: '0.1rem' }}>
                      {formatRelativeTime(device.created_at || device.paired_at)}
                    </div>
                  </div>
                </div>

                {/* Card Actions Footer */}
                <div
                  style={{
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center',
                    marginTop: 'auto',
                    paddingTop: '0.5rem',
                    borderTop: '1px solid var(--border-subtle)',
                  }}
                >
                  <button
                    onClick={() => onSelectTarget(isSelected ? null : device.device_id)}
                    disabled={isRevoked}
                    style={{
                      background: isSelected
                        ? 'rgba(56, 189, 248, 0.2)'
                        : 'var(--bg-surface)',
                      border: `1px solid ${isSelected ? 'var(--accent-cyan)' : 'var(--border-color)'}`,
                      color: isSelected ? 'var(--accent-cyan)' : 'var(--text-primary)',
                      borderRadius: '6px',
                      padding: '0.4rem 0.75rem',
                      fontSize: '0.75rem',
                      fontWeight: 700,
                      cursor: isRevoked ? 'not-allowed' : 'pointer',
                      display: 'flex',
                      alignItems: 'center',
                      gap: '0.35rem',
                    }}
                  >
                    <span>{isSelected ? '✓ Selected as Target' : 'Select Target'}</span>
                  </button>

                  <button
                    onClick={() => setDeviceToRevoke(device)}
                    style={{
                      background: 'transparent',
                      border: '1px solid rgba(239, 68, 68, 0.3)',
                      color: 'var(--accent-rose)',
                      borderRadius: '6px',
                      padding: '0.4rem 0.75rem',
                      fontSize: '0.75rem',
                      fontWeight: 600,
                      cursor: 'pointer',
                    }}
                  >
                    Revoke
                  </button>
                </div>
              </div>
            );
          })}
        </div>
      )}

      {/* ─── PAIRING MODAL ──────────────────────────────────────────────── */}
      {isPairModalOpen && (
        <div
          style={{
            position: 'fixed',
            inset: 0,
            background: 'rgba(34, 36, 38, 0.45)',
            backdropFilter: 'blur(6px)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            zIndex: 1000,
            padding: '1rem',
          }}
        >
          <div
            style={{
              background: '#FFFFFF',
              border: '1.5px solid var(--border-color)',
              borderRadius: '12px',
              maxWidth: '540px',
              width: '100%',
              padding: '1.75rem',
              display: 'flex',
              flexDirection: 'column',
              gap: '1.25rem',
              boxShadow: '0 20px 45px rgba(34, 36, 38, 0.15)',
            }}
          >
            {/* Modal Header */}
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <span style={{ fontSize: '1.25rem' }}>🛰️</span>
                <h3 style={{ fontSize: '1.1rem', fontWeight: 800, color: 'var(--text-primary)', margin: 0 }}>
                  Pair New Endpoint
                </h3>
              </div>
              <button
                onClick={() => {
                  setIsPairModalOpen(false);
                  fetchDevices(false);
                }}
                style={{
                  background: 'none',
                  border: 'none',
                  color: 'var(--text-muted)',
                  fontSize: '1.2rem',
                  cursor: 'pointer',
                }}
              >
                ✕
              </button>
            </div>

            {pairingLoading ? (
              <div style={{ textAlign: 'center', padding: '2rem 0', color: 'var(--accent-cyan)' }}>
                Generating cryptographic pairing code...
              </div>
            ) : pairingError ? (
              <div
                style={{
                  padding: '1rem',
                  borderRadius: '8px',
                  background: 'rgba(239, 68, 68, 0.12)',
                  border: '1px solid rgba(239, 68, 68, 0.3)',
                  color: 'var(--accent-rose)',
                  fontSize: '0.85rem',
                }}
              >
                {pairingError}
              </div>
            ) : (
              <>
                <p style={{ fontSize: '0.82rem', color: 'var(--text-secondary)', margin: 0 }}>
                  Enter this single-use pairing code on your endpoint to enroll it securely. The code is strictly scoped to your investigator account and expires in 10 minutes.
                </p>

                {/* Big Pairing Code Card */}
                <div
                  style={{
                    background: 'var(--bg-surface)',
                    border: '1.5px solid var(--border-color)',
                    borderRadius: '8px',
                    padding: '1.2rem',
                    textAlign: 'center',
                    display: 'flex',
                    flexDirection: 'column',
                    alignItems: 'center',
                    gap: '0.5rem',
                  }}
                >
                  <div style={{ fontSize: '0.72rem', textTransform: 'uppercase', letterSpacing: '0.08em', color: 'var(--text-muted)' }}>
                    Single-Use Pairing Code
                  </div>
                  <div
                    className="font-mono"
                    style={{
                      fontSize: '2rem',
                      fontWeight: 800,
                      letterSpacing: '0.2em',
                      color: 'var(--color-lava)',
                    }}
                  >
                    {pairingData?.pairing_code || '--------'}
                  </div>
                  <button
                    onClick={handleCopyCode}
                    style={{
                      background: copyCodeSuccess ? 'rgba(92, 128, 43, 0.2)' : 'rgba(139, 212, 232, 0.25)',
                      border: `1px solid ${copyCodeSuccess ? 'rgba(92, 128, 43, 0.4)' : 'rgba(139, 212, 232, 0.6)'}`,
                      color: copyCodeSuccess ? 'var(--color-algae)' : 'var(--color-lava)',
                      borderRadius: '4px',
                      padding: '0.3rem 0.8rem',
                      fontSize: '0.75rem',
                      fontWeight: 700,
                      cursor: 'pointer',
                    }}
                  >
                    {copyCodeSuccess ? '✓ Code Copied' : 'Copy Code'}
                  </button>
                </div>

                {/* Expiration & Server Metadata */}
                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                  <span>Server: <strong style={{ color: 'var(--color-lava)' }}>{serverUrl}</strong></span>
                  <span>Code expires in: <strong style={{ color: countdown < 60 ? 'var(--accent-rose)' : 'var(--accent-amber)' }}>{formatCountdown(countdown)}</strong></span>
                </div>

                {/* Copyable CLI Command */}
                <div>
                  <div style={{ fontSize: '0.75rem', fontWeight: 700, color: 'var(--text-secondary)', marginBottom: '0.4rem' }}>
                    Run this command on your endpoint terminal:
                  </div>
                  <div
                    style={{
                      background: 'var(--bg-surface)',
                      border: '1px solid var(--border-color)',
                      borderRadius: '6px',
                      padding: '0.75rem',
                      fontSize: '0.78rem',
                      fontFamily: 'monospace',
                      color: 'var(--color-lava)',
                      wordBreak: 'break-all',
                      position: 'relative',
                    }}
                  >
                    {pairingCommand}
                  </div>
                </div>

                <div style={{ display: 'flex', gap: '0.6rem' }}>
                  <button
                    onClick={handleCopyCommand}
                    style={{
                      flex: 1,
                      background: copyCmdSuccess ? 'rgba(92, 128, 43, 0.2)' : 'var(--color-lagoon)',
                      border: copyCmdSuccess ? '1px solid rgba(92, 128, 43, 0.4)' : '1px solid #72c7dc',
                      color: copyCmdSuccess ? 'var(--color-algae)' : 'var(--color-lava)',
                      borderRadius: '6px',
                      padding: '0.6rem 1rem',
                      fontSize: '0.82rem',
                      fontWeight: 800,
                      cursor: 'pointer',
                    }}
                  >
                    {copyCmdSuccess ? '✓ Command Copied to Clipboard!' : 'Copy Pairing Command'}
                  </button>

                  <button
                    onClick={async () => {
                      await fetchDevices(false);
                      setIsPairModalOpen(false);
                    }}
                    style={{
                      background: 'var(--bg-surface)',
                      border: '1px solid var(--border-color)',
                      color: 'var(--text-primary)',
                      borderRadius: '6px',
                      padding: '0.6rem 1rem',
                      fontSize: '0.82rem',
                      fontWeight: 600,
                      cursor: 'pointer',
                    }}
                  >
                    Done / Close
                  </button>
                </div>
              </>
            )}
          </div>
        </div>
      )}

      {/* ─── REVOKE CONFIRMATION MODAL ───────────────────────────────────── */}
      {deviceToRevoke && (
        <div
          style={{
            position: 'fixed',
            inset: 0,
            background: 'rgba(34, 36, 38, 0.45)',
            backdropFilter: 'blur(6px)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            zIndex: 1000,
            padding: '1rem',
          }}
        >
          <div
            style={{
              background: '#FFFFFF',
              border: '1.5px solid rgba(197, 48, 48, 0.35)',
              borderRadius: '12px',
              maxWidth: '460px',
              width: '100%',
              padding: '1.75rem',
              display: 'flex',
              flexDirection: 'column',
              gap: '1.2rem',
              boxShadow: '0 20px 45px rgba(34, 36, 38, 0.15)',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
              <span style={{ fontSize: '1.4rem', color: 'var(--accent-rose)' }}>⚠</span>
              <h3 style={{ fontSize: '1.1rem', fontWeight: 800, color: 'var(--text-primary)', margin: 0 }}>
                Revoke Endpoint Access?
              </h3>
            </div>

            <p style={{ fontSize: '0.82rem', color: 'var(--text-secondary)', lineHeight: 1.5, margin: 0 }}>
              Are you sure you want to revoke endpoint{' '}
              <strong style={{ color: 'var(--text-primary)' }}>
                '{deviceToRevoke.hostname || deviceToRevoke.device_id}'
              </strong>{' '}
              ({deviceToRevoke.device_id})?
            </p>

            <div
              style={{
                fontSize: '0.78rem',
                color: 'var(--accent-rose)',
                background: 'rgba(239, 68, 68, 0.08)',
                padding: '0.75rem',
                borderRadius: '6px',
                border: '1px solid rgba(239, 68, 68, 0.2)',
              }}
            >
              The device's cryptographic token will be immediately invalidated. The agent will no longer be able to receive collection jobs or submit evidence until it is re-enrolled with a new pairing code.
            </div>

            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.6rem', marginTop: '0.5rem' }}>
              <button
                onClick={() => setDeviceToRevoke(null)}
                disabled={revokeLoading}
                style={{
                  background: 'var(--bg-surface)',
                  border: '1px solid var(--border-color)',
                  color: 'var(--text-primary)',
                  borderRadius: '6px',
                  padding: '0.5rem 1rem',
                  fontSize: '0.8rem',
                  fontWeight: 600,
                  cursor: 'pointer',
                }}
              >
                Cancel
              </button>
              <button
                onClick={handleConfirmRevoke}
                disabled={revokeLoading}
                style={{
                  background: 'var(--accent-rose)',
                  border: 'none',
                  color: '#fff',
                  borderRadius: '6px',
                  padding: '0.5rem 1.1rem',
                  fontSize: '0.8rem',
                  fontWeight: 700,
                  cursor: revokeLoading ? 'not-allowed' : 'pointer',
                }}
              >
                {revokeLoading ? 'Revoking...' : 'Confirm Revoke'}
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
