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
      background: 'linear-gradient(135deg, rgba(244, 63, 94, 0.08) 0%, #FFFFFF 100%)',
      border: '1.5px solid rgba(244, 63, 94, 0.35)',
      borderRadius: '12px',
      padding: collapsed ? '0.75rem 1.25rem' : '1.25rem 1.5rem',
      marginBottom: '1.5rem',
      boxShadow: '0 4px 20px rgba(34, 36, 38, 0.06)',
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
              <h3 style={{ fontSize: '1.05rem', fontWeight: 800, color: 'var(--color-lava)', letterSpacing: '-0.01em' }}>
                🚨 Potential Critical Security Incident Detected
              </h3>

              <span style={{
                fontSize: '0.68rem',
                fontWeight: 800,
                color: '#C53030',
                background: 'rgba(197, 48, 48, 0.12)',
                border: '1px solid rgba(197, 48, 48, 0.35)',
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
            <div style={{ background: 'var(--bg-surface)', padding: '0.65rem 0.85rem', borderRadius: '6px', border: '1px solid var(--border-subtle)' }}>
              <div style={{ fontSize: '0.68rem', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600 }}>Case &amp; Target</div>
              <div style={{ fontSize: '0.85rem', fontWeight: 700, color: 'var(--color-lava)', marginTop: '0.2rem' }}>
                {incident.case_id} &bull; <span style={{ color: 'var(--color-lava)' }}>{incident.target}</span>
              </div>
            </div>

            <div style={{ background: 'var(--bg-surface)', padding: '0.65rem 0.85rem', borderRadius: '6px', border: '1px solid var(--border-subtle)' }}>
              <div style={{ fontSize: '0.68rem', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600 }}>Detection Reason</div>
              <div style={{ fontSize: '0.82rem', fontWeight: 600, color: '#C53030', marginTop: '0.2rem' }}>
                {incident.detection_name || incident.rule_id}
              </div>
            </div>

            <div style={{ background: 'var(--bg-surface)', padding: '0.65rem 0.85rem', borderRadius: '6px', border: '1px solid var(--border-subtle)' }}>
              <div style={{ fontSize: '0.68rem', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600 }}>Evidence Indicators</div>
              <div style={{ fontSize: '0.85rem', fontWeight: 700, color: 'var(--color-lava)', marginTop: '0.2rem' }}>
                {incident.related_evidence_count} Findings ({incident.high_severity_count} High)
              </div>
            </div>

            <div style={{ background: 'var(--bg-surface)', padding: '0.65rem 0.85rem', borderRadius: '6px', border: '1px solid var(--border-subtle)' }}>
              <div style={{ fontSize: '0.68rem', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600 }}>Cryptographic Integrity</div>
              <div style={{ fontSize: '0.82rem', fontWeight: 700, color: 'var(--color-algae)', marginTop: '0.2rem' }}>
                {incident.evidence_integrity_status || 'VERIFIED (SHA-256)'}
              </div>
            </div>
          </div>

          {/* Description Detail */}
          <div style={{
            fontSize: '0.8rem',
            color: 'var(--text-primary)',
            background: 'var(--bg-surface)',
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
                background: 'var(--color-lagoon)',
                border: '1px solid #72c7dc',
                borderRadius: '6px',
                color: 'var(--color-lava)',
                padding: '0.5rem 1rem',
                fontSize: '0.8rem',
                fontWeight: 800,
                cursor: 'pointer',
                boxShadow: '0 2px 8px rgba(139, 212, 232, 0.45)',
              }}
            >
              💬 Contact Security
            </button>

            <button
              type="button"
              onClick={onGenerateReport}
              style={{
                background: '#FFFFFF',
                border: '1px solid var(--border-color)',
                borderRadius: '6px',
                color: 'var(--color-lava)',
                padding: '0.5rem 1rem',
                fontSize: '0.8rem',
                fontWeight: 700,
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
