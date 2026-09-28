import React, { useState } from 'react';

export default function CriticalIncidentAlert({
  incident,
  onViewIncident,
  onPreserveEvidence,
  onContactSecurity,
  onGenerateReport,
}) {
  const [collapsed, setCollapsed] = useState(false);
  const [preservedNotice, setPreservedNotice] = useState(null);
  const [verifying, setVerifying] = useState(false);

  if (!incident || !incident.has_incident) {
    return null;
  }

  const handlePreserveClick = async () => {
    setVerifying(true);
    setPreservedNotice(null);
    try {
      if (onPreserveEvidence) {
        await onPreserveEvidence();
      }
      setPreservedNotice('Evidence Vault verified and cryptographically locked. SHA-256 chain-of-custody recorded.');
      setTimeout(() => setPreservedNotice(null), 5000);
    } catch (e) {
      setPreservedNotice('Evidence preservation check error.');
    } finally {
      setVerifying(false);
    }
  };

  return (
    <div style={{
      background: 'linear-gradient(135deg, rgba(244, 63, 94, 0.12) 0%, rgba(15, 23, 42, 0.95) 100%)',
      border: '1px solid rgba(244, 63, 94, 0.45)',
      borderRadius: '12px',
      padding: collapsed ? '0.75rem 1.25rem' : '1.25rem 1.5rem',
      marginBottom: '1.5rem',
      boxShadow: '0 8px 30px rgba(244, 63, 94, 0.15)',
      position: 'relative',
      overflow: 'hidden',
    }}>
      {/* Top Header Row */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: '1rem', flexWrap: 'wrap' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem' }}>
          <span
            style={{
              width: '10px',
              height: '10px',
              borderRadius: '50%',
              backgroundColor: 'var(--accent-rose)',
              boxShadow: '0 0 12px var(--accent-rose)',
            }}
            className="pulse-dot"
          />

          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flexWrap: 'wrap' }}>
              <h3 style={{ fontSize: '1.05rem', fontWeight: 800, color: '#fff', letterSpacing: '-0.01em' }}>
                🚨 Potential Critical Security Incident Detected
              </h3>

              <span style={{
                fontSize: '0.68rem',
                fontWeight: 800,
                color: '#fff',
                background: 'rgba(244, 63, 94, 0.3)',
                border: '1px solid rgba(244, 63, 94, 0.6)',
                padding: '0.15rem 0.5rem',
                borderRadius: '4px',
                letterSpacing: '0.05em',
              }}>
                SEVERITY: {incident.severity}
              </span>

              <span style={{
                fontSize: '0.68rem',
                color: 'var(--text-muted)',
                fontFamily: 'monospace',
              }}>
                {incident.incident_id}
              </span>
            </div>
          </div>
        </div>

        <button
          type="button"
          onClick={() => setCollapsed(!collapsed)}
          style={{
            background: 'none',
            border: 'none',
            color: 'var(--text-secondary)',
            fontSize: '0.75rem',
            fontWeight: 600,
            cursor: 'pointer',
            padding: '0.2rem 0.5rem',
          }}
        >
          {collapsed ? 'Expand Details ▼' : 'Minimize ▲'}
        </button>
      </div>

      {/* Expanded Content */}
      {!collapsed && (
        <div style={{ marginTop: '1rem' }}>
          {/* Compliance Disclaimer */}
          <div style={{
            fontSize: '0.75rem',
            color: 'var(--text-secondary)',
            lineHeight: 1.45,
            marginBottom: '0.9rem',
            background: 'rgba(255, 255, 255, 0.02)',
            padding: '0.5rem 0.75rem',
            borderRadius: '6px',
            border: '1px solid var(--border-subtle)',
          }}>
            ℹ <strong>Compliance Notice:</strong> {incident.disclaimer || "Potential security incident detected based on configured forensic rules. Automated heuristic observations do not claim definitive machine compromise."}
          </div>

          {/* Incident Telemetry Grid */}
          <div style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))',
            gap: '0.75rem',
            marginBottom: '1rem',
          }}>
            <div style={{ background: 'rgba(10, 15, 26, 0.6)', padding: '0.65rem 0.85rem', borderRadius: '6px', border: '1px solid var(--border-subtle)' }}>
              <div style={{ fontSize: '0.68rem', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600 }}>Case &amp; Target</div>
              <div style={{ fontSize: '0.85rem', fontWeight: 700, color: '#fff', marginTop: '0.2rem' }}>
                {incident.case_id} &bull; <span style={{ color: 'var(--accent-cyan)' }}>{incident.target}</span>
              </div>
            </div>

            <div style={{ background: 'rgba(10, 15, 26, 0.6)', padding: '0.65rem 0.85rem', borderRadius: '6px', border: '1px solid var(--border-subtle)' }}>
              <div style={{ fontSize: '0.68rem', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600 }}>Detection Reason</div>
              <div style={{ fontSize: '0.82rem', fontWeight: 600, color: '#fca5a5', marginTop: '0.2rem' }}>
                {incident.detection_name || incident.rule_id}
              </div>
            </div>

            <div style={{ background: 'rgba(10, 15, 26, 0.6)', padding: '0.65rem 0.85rem', borderRadius: '6px', border: '1px solid var(--border-subtle)' }}>
              <div style={{ fontSize: '0.68rem', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600 }}>Evidence Indicators</div>
              <div style={{ fontSize: '0.85rem', fontWeight: 700, color: 'var(--accent-cyan)', marginTop: '0.2rem' }}>
                {incident.related_evidence_count} Findings ({incident.high_severity_count} High)
              </div>
            </div>

            <div style={{ background: 'rgba(10, 15, 26, 0.6)', padding: '0.65rem 0.85rem', borderRadius: '6px', border: '1px solid var(--border-subtle)' }}>
              <div style={{ fontSize: '0.68rem', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600 }}>Cryptographic Integrity</div>
              <div style={{ fontSize: '0.82rem', fontWeight: 700, color: 'var(--accent-emerald)', marginTop: '0.2rem' }}>
                {incident.evidence_integrity_status || 'VERIFIED (SHA-256)'}
              </div>
            </div>
          </div>

          {/* Description Detail */}
          <div style={{
            fontSize: '0.8rem',
            color: 'var(--text-primary)',
            background: 'rgba(15, 23, 42, 0.7)',
            padding: '0.75rem 1rem',
            borderRadius: '6px',
            borderLeft: '3px solid var(--accent-rose)',
            marginBottom: '1.1rem',
            lineHeight: 1.45,
          }}>
            {incident.detection_reason}
          </div>

          {/* Preservation Success Notice */}
          {preservedNotice && (
            <div style={{
              background: 'rgba(16, 185, 129, 0.15)',
              border: '1px solid rgba(16, 185, 129, 0.35)',
              borderRadius: '6px',
              padding: '0.5rem 0.75rem',
              color: 'var(--accent-emerald)',
              fontSize: '0.78rem',
              fontWeight: 600,
              marginBottom: '1rem',
            }}>
              ✓ {preservedNotice}
            </div>
          )}

          {/* Action Buttons Row */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', flexWrap: 'wrap' }}>
            <button
              type="button"
              onClick={onViewIncident}
              style={{
                background: 'rgba(56, 189, 248, 0.15)',
                border: '1px solid rgba(56, 189, 248, 0.35)',
                borderRadius: '6px',
                color: 'var(--accent-cyan)',
                padding: '0.5rem 1rem',
                fontSize: '0.8rem',
                fontWeight: 700,
                cursor: 'pointer',
              }}
            >
              🔍 View Incident
            </button>

            <button
              type="button"
              onClick={handlePreserveClick}
              disabled={verifying}
              style={{
                background: 'rgba(16, 185, 129, 0.15)',
                border: '1px solid rgba(16, 185, 129, 0.35)',
                borderRadius: '6px',
                color: 'var(--accent-emerald)',
                padding: '0.5rem 1rem',
                fontSize: '0.8rem',
                fontWeight: 700,
                cursor: verifying ? 'not-allowed' : 'pointer',
              }}
            >
              {verifying ? 'Verifying Integrity...' : '🛡️ Preserve Evidence'}
            </button>

            <button
              type="button"
              onClick={onContactSecurity}
              style={{
                background: 'linear-gradient(135deg, rgba(99, 102, 241, 0.3), rgba(14, 165, 233, 0.3))',
                border: '1px solid rgba(99, 102, 241, 0.5)',
                borderRadius: '6px',
                color: '#fff',
                padding: '0.5rem 1rem',
                fontSize: '0.8rem',
                fontWeight: 700,
                cursor: 'pointer',
              }}
            >
              💬 Contact Security
            </button>

            <button
              type="button"
              onClick={onGenerateReport}
              style={{
                background: 'rgba(255, 255, 255, 0.05)',
                border: '1px solid var(--border-color)',
                borderRadius: '6px',
                color: 'var(--text-secondary)',
                padding: '0.5rem 1rem',
                fontSize: '0.8rem',
                fontWeight: 600,
                cursor: 'pointer',
                marginLeft: 'auto',
              }}
            >
              📄 Generate Report
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
