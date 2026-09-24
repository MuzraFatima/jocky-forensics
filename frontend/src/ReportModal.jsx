import React, { useState } from 'react';
import { API_BASE } from './config.js';

export default function ReportModal({
  isOpen,
  onClose,
  caseId = 'LAB-2026-001',
  session,
  isLogoutWorkflow = false,
  onLogoutAfterReport,
}) {
  const [format, setFormat] = useState('HTML');
  const [destination, setDestination] = useState('SOC-INGESTION-SERVICE');
  const [loading, setLoading] = useState(false);
  const [deliveryResult, setDeliveryResult] = useState(null);
  const [errorMsg, setErrorMsg] = useState(null);
  const [serviceReachable, setServiceReachable] = useState(true);
  const [retrying, setRetrying] = useState(false);

  if (!isOpen) return null;

  // Toggle simulated service reachability to demonstrate both SENT and QUEUED states
  const handleToggleService = async () => {
    const nextState = !serviceReachable;
    try {
      const res = await fetch(`${API_BASE}/api/security/service/toggle`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ reachable: nextState }),
      });
      if (res.ok) {
        setServiceReachable(nextState);
      }
    } catch (e) {
      console.error(e);
    }
  };

  const handleGenerateAndSend = async () => {
    setLoading(true);
    setErrorMsg(null);
    setDeliveryResult(null);

    try {
      const res = await fetch(`${API_BASE}/api/security/report/send`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: session?.token ? `Bearer ${session.token}` : '',
        },
        body: JSON.stringify({
          case_id: caseId,
          target: 'LAB-PC',
          format: format,
          destination: destination,
          examiner: session?.username || 'JOCKY Lead Forensic Examiner',
        }),
      });

      const data = await res.json();
      if (res.ok && data.success) {
        setDeliveryResult(data.delivery);
      } else {
        setErrorMsg(data.error || 'Failed to dispatch forensic report.');
      }
    } catch (err) {
      setErrorMsg(`Network communication error: ${err.message}`);
    } finally {
      setLoading(false);
    }
  };

  const handleGenerateOnly = () => {
    // Downloads directly using existing live download endpoint
    const url = `${API_BASE}/api/forensics/report/download?format=${format.toLowerCase()}&case_id=${encodeURIComponent(caseId)}`;
    window.open(url, '_blank');
    onClose();
  };

  const handleRetry = async (reportId) => {
    setRetrying(true);
    try {
      const res = await fetch(`${API_BASE}/api/security/report/retry/${reportId}`, {
        method: 'POST',
        headers: {
          Authorization: session?.token ? `Bearer ${session.token}` : '',
        },
      });
      const data = await res.json();
      if (res.ok && data.success) {
        setDeliveryResult(data.report);
      }
    } catch (err) {
      console.error(err);
    } finally {
      setRetrying(false);
    }
  };

  return (
    <div style={{
      position: 'fixed',
      inset: 0,
      background: 'rgba(4, 7, 14, 0.8)',
      backdropFilter: 'blur(8px)',
      zIndex: 2000,
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      padding: '1.5rem',
    }}>
      <div style={{
        width: '100%',
        maxWidth: '560px',
        background: '#0d1322',
        border: '1px solid var(--border-color)',
        borderRadius: '14px',
        padding: '2rem',
        boxShadow: '0 25px 60px rgba(0, 0, 0, 0.8), 0 0 35px rgba(14, 165, 233, 0.15)',
      }}>
        {/* Header */}
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '1.25rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
            <span style={{ fontSize: '1.3rem' }}>📄</span>
            <h3 style={{ fontSize: '1.2rem', fontWeight: 800, color: '#fff' }}>
              {isLogoutWorkflow ? 'End Session: Generate & Send Report?' : 'Generate & Send Report?'}
            </h3>
          </div>
          {!loading && (
            <button
              onClick={onClose}
              style={{ background: 'none', border: 'none', color: 'var(--text-muted)', fontSize: '1.2rem', cursor: 'pointer' }}
            >
              ✕
            </button>
          )}
        </div>

        {/* Warning & Scope Description */}
        <div style={{
          background: 'rgba(56, 189, 248, 0.05)',
          border: '1px solid rgba(56, 189, 248, 0.2)',
          borderRadius: '8px',
          padding: '0.85rem 1rem',
          fontSize: '0.78rem',
          color: 'var(--text-secondary)',
          lineHeight: 1.45,
          marginBottom: '1.25rem',
        }}>
          ⚠️ <strong>Sensitive Forensic Data Notice:</strong> The generated report compiles volatile process trees, network sockets, active persistence mechanisms, and SHA-256 attestation certificates.
          Transmissions are queued into the secure SOC delivery pipeline.
        </div>

        {/* Delivery Result Display */}
        {deliveryResult ? (
          <div style={{
            background: deliveryResult.status === 'SENT' ? 'rgba(16, 185, 129, 0.1)' : 'rgba(245, 158, 11, 0.1)',
            border: `1px solid ${deliveryResult.status === 'SENT' ? 'rgba(16, 185, 129, 0.35)' : 'rgba(245, 158, 11, 0.35)'}`,
            borderRadius: '10px',
            padding: '1.25rem',
            marginBottom: '1.5rem',
          }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.65rem' }}>
              <span style={{
                fontSize: '0.75rem',
                fontWeight: 800,
                color: deliveryResult.status === 'SENT' ? 'var(--accent-emerald)' : 'var(--accent-amber)',
                background: deliveryResult.status === 'SENT' ? 'rgba(16, 185, 129, 0.2)' : 'rgba(245, 158, 11, 0.2)',
                padding: '0.2rem 0.6rem',
                borderRadius: '4px',
                letterSpacing: '0.05em',
              }}>
                STATUS: {deliveryResult.status}
              </span>

              <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', fontFamily: 'monospace' }}>
                {deliveryResult.report_id}
              </span>
            </div>

            <div style={{ fontSize: '0.82rem', color: '#fff', marginBottom: '0.4rem' }}>
              <strong>Case:</strong> {deliveryResult.case_id} &bull; <strong>Format:</strong> {deliveryResult.format}
            </div>

            <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', fontFamily: 'monospace', marginBottom: '0.6rem' }}>
              SHA-256: {deliveryResult.sha256?.slice(0, 32)}...
            </div>

            {deliveryResult.status === 'SENT' && deliveryResult.delivery_receipt && (
              <div style={{ fontSize: '0.75rem', color: 'var(--accent-emerald)', lineHeight: 1.4 }}>
                ✓ Certified Receipt: <code>{deliveryResult.delivery_receipt.receipt_id}</code>
                <div style={{ color: 'var(--text-muted)', fontSize: '0.7rem' }}>
                  Acknowledged by {deliveryResult.delivery_receipt.verifier}
                </div>
              </div>
            )}

            {deliveryResult.status === 'QUEUED' && (
              <div>
                <div style={{ fontSize: '0.75rem', color: '#fef3c7', marginBottom: '0.5rem' }}>
                  Reason: {deliveryResult.error_reason}
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
                  <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>
                    Attempts: {deliveryResult.attempt_count} &bull; Auto-Retry Scheduled
                  </span>
                  <button
                    type="button"
                    onClick={() => handleRetry(deliveryResult.report_id)}
                    disabled={retrying}
                    style={{
                      background: 'rgba(245, 158, 11, 0.2)',
                      border: '1px solid rgba(245, 158, 11, 0.4)',
                      borderRadius: '4px',
                      color: 'var(--accent-amber)',
                      fontSize: '0.72rem',
                      padding: '0.25rem 0.6rem',
                      fontWeight: 700,
                      cursor: retrying ? 'not-allowed' : 'pointer',
                    }}
                  >
                    {retrying ? 'Retrying...' : '🔄 Retry Delivery Now'}
                  </button>
                </div>
              </div>
            )}

            {/* Post-result action buttons */}
            <div style={{ marginTop: '1.25rem', display: 'flex', gap: '0.75rem', justifyContent: 'flex-end' }}>
              {isLogoutWorkflow ? (
                <button
                  type="button"
                  onClick={onLogoutAfterReport}
                  style={{
                    background: 'linear-gradient(135deg, #0ea5e9, #6366f1)',
                    border: 'none',
                    borderRadius: '6px',
                    color: '#fff',
                    padding: '0.55rem 1.25rem',
                    fontSize: '0.85rem',
                    fontWeight: 700,
                    cursor: 'pointer',
                  }}
                >
                  Proceed with Logout ▶
                </button>
              ) : (
                <button
                  type="button"
                  onClick={onClose}
                  style={{
                    background: 'rgba(255, 255, 255, 0.08)',
                    border: '1px solid var(--border-color)',
                    borderRadius: '6px',
                    color: '#fff',
                    padding: '0.55rem 1.25rem',
                    fontSize: '0.85rem',
                    fontWeight: 600,
                    cursor: 'pointer',
                  }}
                >
                  Close
                </button>
              )}
            </div>
          </div>
        ) : (
          /* Form Controls Before Send */
          <div>
            {/* Options Selection */}
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '1rem', marginBottom: '1.25rem' }}>
              <div>
                <label style={{ display: 'block', fontSize: '0.75rem', color: 'var(--text-secondary)', fontWeight: 600, marginBottom: '0.35rem' }}>
                  Report Format
                </label>
                <select
                  value={format}
                  onChange={(e) => setFormat(e.target.value)}
                  disabled={loading}
                  style={{
                    width: '100%',
                    padding: '0.55rem 0.75rem',
                    background: 'rgba(10, 15, 26, 0.8)',
                    border: '1px solid var(--border-color)',
                    borderRadius: '6px',
                    color: '#fff',
                    fontSize: '0.82rem',
                  }}
                >
                  <option value="HTML">Interactive HTML (.html)</option>
                  <option value="MARKDOWN">Markdown Document (.md)</option>
                  <option value="JSON">Structured JSON (.json)</option>
                </select>
              </div>

              <div>
                <label style={{ display: 'block', fontSize: '0.75rem', color: 'var(--text-secondary)', fontWeight: 600, marginBottom: '0.35rem' }}>
                  Delivery Destination
                </label>
                <select
                  value={destination}
                  onChange={(e) => setDestination(e.target.value)}
                  disabled={loading}
                  style={{
                    width: '100%',
                    padding: '0.55rem 0.75rem',
                    background: 'rgba(10, 15, 26, 0.8)',
                    border: '1px solid var(--border-color)',
                    borderRadius: '6px',
                    color: '#fff',
                    fontSize: '0.82rem',
                  }}
                >
                  <option value="SOC-INGESTION-SERVICE">SOC Primary Ingestion Service</option>
                  <option value="OFFLINE-BACKUP-VAULT">Offline Air-Gapped Vault</option>
                  <option value="NATIONAL-CERT-DISPATCH">National CERT Escalation Gateway</option>
                </select>
              </div>
            </div>

            {/* Simulation Service Toggle */}
            <div style={{
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
              background: 'rgba(255, 255, 255, 0.02)',
              border: '1px solid var(--border-subtle)',
              borderRadius: '8px',
              padding: '0.6rem 0.85rem',
              marginBottom: '1.25rem',
              fontSize: '0.75rem',
            }}>
              <div>
                <span style={{ color: 'var(--text-secondary)' }}>Destination Service Status: </span>
                <span style={{ fontWeight: 700, color: serviceReachable ? 'var(--accent-emerald)' : 'var(--accent-amber)' }}>
                  {serviceReachable ? 'ONLINE (Yields SENT)' : 'SIMULATED OFFLINE (Yields QUEUED)'}
                </span>
              </div>
              <button
                type="button"
                onClick={handleToggleService}
                style={{
                  background: 'rgba(255, 255, 255, 0.06)',
                  border: '1px solid var(--border-subtle)',
                  borderRadius: '4px',
                  color: 'var(--text-secondary)',
                  fontSize: '0.68rem',
                  padding: '0.2rem 0.5rem',
                  cursor: 'pointer',
                }}
              >
                Toggle {serviceReachable ? 'Offline' : 'Online'}
              </button>
            </div>

            {errorMsg && (
              <div style={{ color: '#fda4af', fontSize: '0.78rem', marginBottom: '1rem' }}>
                ⚠ {errorMsg}
              </div>
            )}

            {/* Actions */}
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'flex-end', gap: '0.75rem' }}>
              <button
                type="button"
                onClick={onClose}
                disabled={loading}
                style={{
                  background: 'none',
                  border: '1px solid var(--border-subtle)',
                  borderRadius: '6px',
                  color: 'var(--text-secondary)',
                  padding: '0.55rem 1rem',
                  fontSize: '0.82rem',
                  fontWeight: 600,
                  cursor: 'pointer',
                }}
              >
                Cancel
              </button>

              <button
                type="button"
                onClick={handleGenerateOnly}
                disabled={loading}
                style={{
                  background: 'rgba(56, 189, 248, 0.1)',
                  border: '1px solid rgba(56, 189, 248, 0.3)',
                  borderRadius: '6px',
                  color: 'var(--accent-cyan)',
                  padding: '0.55rem 1rem',
                  fontSize: '0.82rem',
                  fontWeight: 600,
                  cursor: 'pointer',
                }}
              >
                ⬇ Generate Only (Direct Download)
              </button>

              <button
                type="button"
                onClick={handleGenerateAndSend}
                disabled={loading}
                style={{
                  background: loading ? 'rgba(14, 165, 233, 0.4)' : 'linear-gradient(135deg, #0ea5e9, #6366f1)',
                  border: 'none',
                  borderRadius: '6px',
                  color: '#fff',
                  padding: '0.55rem 1.25rem',
                  fontSize: '0.85rem',
                  fontWeight: 700,
                  cursor: loading ? 'not-allowed' : 'pointer',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '0.4rem',
                }}
              >
                {loading ? 'Processing Pipeline...' : '📤 Generate & Send'}
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
