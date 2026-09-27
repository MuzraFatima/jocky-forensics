import React, { useState, useMemo } from 'react';

/**
 * AdvancedTechniques: JOCKY Advanced Technique Analysis & MITRE ATT&CK Mapping
 *
 * Implements the full forensic pipeline:
 * Evidence → Advanced Finding → Correlation → Timeline → MITRE Mapping → Forensic Explanation
 *
 * Invariants:
 * - Read-only analytical interpretation
 * - Clearly distinguishes observed evidence from analytical interpretation
 * - Every finding is traceable back to the sealed Evidence Vault
 * - Zero secret or token exposure
 */
export default function AdvancedTechniques({
  investigationData,
  techniqueFindings = [],
  mitreAnalysis = null,
  onNavigateTab = () => {},
}) {
  const [searchTerm, setSearchTerm] = useState('');
  const [severityFilter, setSeverityFilter] = useState('ALL');
  const [tacticFilter, setTacticFilter] = useState('ALL');
  const [selectedFinding, setSelectedFinding] = useState(null);

  // Extract case metadata
  const caseId = investigationData?.case_id || 'UNKNOWN-CASE';
  const targetHost = investigationData?.target || 'localhost';
  const executionId = investigationData?.execution_id || 'LOCAL-EXEC';

  // Normalize findings list
  const findings = useMemo(() => {
    if (Array.isArray(techniqueFindings) && techniqueFindings.length > 0) {
      return techniqueFindings;
    }
    if (Array.isArray(investigationData?.technique_findings) && investigationData.technique_findings.length > 0) {
      return investigationData.technique_findings;
    }
    if (Array.isArray(investigationData?.analysis?.technique_findings)) {
      return investigationData.analysis.technique_findings;
    }
    return [];
  }, [techniqueFindings, investigationData]);

  // Normalize MITRE analysis
  const mitre = useMemo(() => {
    return (
      mitreAnalysis ||
      investigationData?.mitre_analysis ||
      investigationData?.analysis?.mitre_analysis ||
      {}
    );
  }, [mitreAnalysis, investigationData]);

  // Tactics breakdown
  const tacticsPresent = useMemo(() => {
    if (Array.isArray(mitre?.tactics_present)) {
      return mitre.tactics_present;
    }
    const tSet = new Set();
    findings.forEach((f) => {
      const t = f.technique?.mitre_tactic;
      if (t) tSet.add(t);
    });
    return Array.from(tSet);
  }, [mitre, findings]);

  // Filtered findings
  const filteredFindings = useMemo(() => {
    return findings.filter((f) => {
      const q = searchTerm.toLowerCase();
      const tObj = f.technique || {};
      const tName = (tObj.name || '').toLowerCase();
      const tId = (tObj.technique_id || '').toLowerCase();
      const mId = (tObj.mitre_id || '').toLowerCase();
      const ind = (f.observed_indicator || '').toLowerCase();
      const fId = (f.finding_id || '').toLowerCase();

      const matchesSearch =
        !q ||
        tName.includes(q) ||
        tId.includes(q) ||
        mId.includes(q) ||
        ind.includes(q) ||
        fId.includes(q);

      const sev = (f.severity || 'MEDIUM').toUpperCase();
      const matchesSeverity = severityFilter === 'ALL' || sev === severityFilter;

      const tac = tObj.mitre_tactic || '';
      const matchesTactic = tacticFilter === 'ALL' || tac === tacticFilter;

      return matchesSearch && matchesSeverity && matchesTactic;
    });
  }, [findings, searchTerm, severityFilter, tacticFilter]);

  // KPI Metrics
  const highSevCount = findings.filter((f) => (f.severity || '').toUpperCase() === 'HIGH').length;
  const medSevCount = findings.filter((f) => (f.severity || '').toUpperCase() === 'MEDIUM').length;
  const lowSevCount = findings.filter((f) => (f.severity || '').toUpperCase() === 'LOW').length;

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      {/* ── Header Banner & Scope ── */}
      <div
        style={{
          background: 'var(--bg-card)',
          borderRadius: '10px',
          border: '1px solid var(--border-color)',
          padding: '1.5rem',
          display: 'flex',
          justifyContent: 'space-between',
          alignItems: 'flex-start',
          flexWrap: 'wrap',
          gap: '1rem',
        }}
      >
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '0.4rem' }}>
            <h2 style={{ fontSize: '1.25rem', fontWeight: 800, color: 'var(--text-primary)', margin: 0 }}>
              Advanced Technique Analysis &amp; MITRE ATT&amp;CK Mapping
            </h2>
            <span
              style={{
                fontSize: '0.65rem',
                fontWeight: 700,
                padding: '0.15rem 0.5rem',
                borderRadius: '4px',
                background: 'rgba(56, 189, 248, 0.12)',
                color: 'var(--accent-cyan)',
                border: '1px solid rgba(56, 189, 248, 0.25)',
                textTransform: 'uppercase',
              }}
            >
              Defensive Analysis Only
            </span>
          </div>
          <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', margin: 0, maxWidth: '780px', lineHeight: 1.5 }}>
            Synthesizes safe forensic indicators across active processes, network telemetry, files, and persistence into
            verifiable technique findings. Every finding is cryptographically traceable back to Evidence Vault artifacts.
          </p>
        </div>

        {/* Traceability Indicator */}
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            gap: '0.5rem',
            background: 'rgba(16, 185, 129, 0.08)',
            border: '1px solid rgba(16, 185, 129, 0.25)',
            padding: '0.5rem 0.85rem',
            borderRadius: '6px',
            fontSize: '0.75rem',
            color: 'var(--accent-emerald)',
            fontWeight: 600,
          }}
        >
          <span>🔒</span> Evidence Vault Sealed &amp; Traceable
        </div>
      </div>

      {/* ── Metadata Bar ── */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))',
          gap: '1rem',
        }}
      >
        <div
          style={{
            background: 'var(--bg-card)',
            border: '1px solid var(--border-color)',
            borderRadius: '8px',
            padding: '1rem',
          }}
        >
          <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 700 }}>
            Case Identifier
          </div>
          <div className="font-mono" style={{ fontSize: '0.95rem', fontWeight: 700, color: 'var(--accent-cyan)', marginTop: '0.25rem' }}>
            {caseId}
          </div>
        </div>

        <div
          style={{
            background: 'var(--bg-card)',
            border: '1px solid var(--border-color)',
            borderRadius: '8px',
            padding: '1rem',
          }}
        >
          <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 700 }}>
            Target System / Device
          </div>
          <div className="font-mono" style={{ fontSize: '0.95rem', fontWeight: 700, color: 'var(--text-primary)', marginTop: '0.25rem' }}>
            {targetHost}
          </div>
        </div>

        <div
          style={{
            background: 'var(--bg-card)',
            border: '1px solid var(--border-color)',
            borderRadius: '8px',
            padding: '1rem',
          }}
        >
          <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 700 }}>
            Total Findings
          </div>
          <div style={{ fontSize: '1.2rem', fontWeight: 800, color: findings.length > 0 ? 'var(--accent-amber)' : 'var(--accent-emerald)', marginTop: '0.15rem' }}>
            {findings.length}
          </div>
        </div>

        <div
          style={{
            background: 'var(--bg-card)',
            border: '1px solid var(--border-color)',
            borderRadius: '8px',
            padding: '1rem',
          }}
        >
          <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 700 }}>
            MITRE Tactics
          </div>
          <div style={{ fontSize: '1.2rem', fontWeight: 800, color: 'var(--accent-cyan)', marginTop: '0.15rem' }}>
            {tacticsPresent.length}
          </div>
        </div>
      </div>

      {/* ── MITRE ATT&CK Kill-Chain Progress / Distribution ── */}
      {tacticsPresent.length > 0 && (
        <div
          style={{
            background: 'var(--bg-card)',
            border: '1px solid var(--border-color)',
            borderRadius: '10px',
            padding: '1.25rem',
          }}
        >
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.75rem' }}>
            <div style={{ fontSize: '0.85rem', fontWeight: 700, color: 'var(--text-primary)' }}>
              MITRE ATT&amp;CK® Enterprise Tactics Observed
            </div>
            <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>
              {tacticsPresent.length} Tactic Stage(s) Identified
            </div>
          </div>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.5rem' }}>
            {tacticsPresent.map((tac, idx) => (
              <span
                key={idx}
                style={{
                  fontSize: '0.75rem',
                  fontWeight: 600,
                  padding: '0.35rem 0.75rem',
                  borderRadius: '6px',
                  background: 'rgba(99, 102, 241, 0.12)',
                  color: 'var(--accent-indigo)',
                  border: '1px solid rgba(99, 102, 241, 0.25)',
                }}
              >
                ⚡ {tac}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* ── Search & Filter Controls ── */}
      <div
        style={{
          display: 'flex',
          flexWrap: 'wrap',
          gap: '1rem',
          alignItems: 'center',
          justifyContent: 'space-between',
          background: 'rgba(255, 255, 255, 0.02)',
          padding: '1rem',
          borderRadius: '8px',
          border: '1px solid var(--border-subtle)',
        }}
      >
        <div style={{ display: 'flex', gap: '0.75rem', flex: 1, minWidth: '280px' }}>
          <input
            type="text"
            placeholder="Search technique, indicator, or finding ID..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            style={{
              flex: 1,
              padding: '0.6rem 0.9rem',
              borderRadius: '6px',
              border: '1px solid var(--border-color)',
              background: 'var(--bg-input)',
              color: 'var(--text-primary)',
              fontSize: '0.85rem',
              outline: 'none',
            }}
          />
        </div>

        <div style={{ display: 'flex', gap: '0.75rem', alignItems: 'center', flexWrap: 'wrap' }}>
          {/* Severity Filter */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
            <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>Severity:</span>
            {['ALL', 'HIGH', 'MEDIUM', 'LOW'].map((s) => (
              <button
                key={s}
                type="button"
                onClick={() => setSeverityFilter(s)}
                style={{
                  padding: '0.3rem 0.6rem',
                  borderRadius: '4px',
                  fontSize: '0.75rem',
                  fontWeight: 600,
                  cursor: 'pointer',
                  border: severityFilter === s ? '1px solid var(--accent-cyan)' : '1px solid var(--border-subtle)',
                  background: severityFilter === s ? 'rgba(56, 189, 248, 0.15)' : 'transparent',
                  color: severityFilter === s ? 'var(--accent-cyan)' : 'var(--text-secondary)',
                }}
              >
                {s}
              </button>
            ))}
          </div>

          {/* Tactic Filter */}
          {tacticsPresent.length > 0 && (
            <select
              value={tacticFilter}
              onChange={(e) => setTacticFilter(e.target.value)}
              style={{
                padding: '0.4rem 0.75rem',
                borderRadius: '4px',
                border: '1px solid var(--border-color)',
                background: 'var(--bg-input)',
                color: 'var(--text-primary)',
                fontSize: '0.78rem',
              }}
            >
              <option value="ALL">All Tactics</option>
              {tacticsPresent.map((t) => (
                <option key={t} value={t}>
                  {t}
                </option>
              ))}
            </select>
          )}
        </div>
      </div>

      {/* ── Findings Table / Cards ── */}
      {filteredFindings.length === 0 ? (
        <div
          style={{
            background: 'var(--bg-card)',
            borderRadius: '10px',
            border: '1px solid var(--border-color)',
            padding: '3rem 2rem',
            textAlign: 'center',
          }}
        >
          <div style={{ fontSize: '2rem', marginBottom: '0.5rem' }}>🛡️</div>
          <h3 style={{ fontSize: '1.1rem', fontWeight: 700, color: 'var(--text-primary)', marginBottom: '0.5rem' }}>
            {findings.length === 0 ? 'No Advanced Technique Findings in Current Session' : 'No Findings Match Filter'}
          </h3>
          <p style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', maxWidth: '540px', margin: '0 auto 1.5rem', lineHeight: 1.5 }}>
            {findings.length === 0
              ? 'Execute a JOCKY investigation script containing "ANALYZE" or "ANALYZE PROCESS_NETWORK". The forensic analyzer will extract observable indicators, synthesize technique findings, and correlate them back to the Evidence Vault.'
              : 'Try clearing the search query or adjusting the severity / tactic filters above.'}
          </p>
          {findings.length === 0 && (
            <button
              type="button"
              onClick={() => onNavigateTab('script')}
              style={{
                padding: '0.6rem 1.25rem',
                borderRadius: '6px',
                background: 'linear-gradient(135deg, #0ea5e9, #6366f1)',
                border: 'none',
                color: '#fff',
                fontWeight: 700,
                fontSize: '0.85rem',
                cursor: 'pointer',
              }}
            >
              Open Script Editor &amp; Run Investigation
            </button>
          )}
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          {filteredFindings.map((f, idx) => {
            const tObj = f.technique || {};
            const tName = tObj.name || 'Unspecified Technique';
            const tId = tObj.technique_id || 'TECH-UNKNOWN';
            const mId = tObj.mitre_id || 'TXXXX';
            const mTactic = tObj.mitre_tactic || '';
            const sev = (f.severity || 'MEDIUM').toUpperCase();
            const conf = f.confidence || 'HIGH';
            const status = f.status || 'ANALYZED';
            const fId = f.finding_id || `FIND-${idx + 1}`;
            const eids = f.evidence_ids || [];

            const sevColor =
              sev === 'HIGH' ? '#ef4444' : sev === 'MEDIUM' ? '#f59e0b' : '#38bdf8';
            const sevBg =
              sev === 'HIGH'
                ? 'rgba(239, 68, 68, 0.12)'
                : sev === 'MEDIUM'
                ? 'rgba(245, 158, 11, 0.12)'
                : 'rgba(56, 189, 248, 0.12)';

            return (
              <div
                key={fId}
                style={{
                  background: 'var(--bg-card)',
                  borderRadius: '10px',
                  border: '1px solid var(--border-color)',
                  padding: '1.25rem 1.5rem',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '0.85rem',
                  transition: 'border-color 0.2s',
                }}
              >
                {/* Finding Header */}
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '0.5rem' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem', flexWrap: 'wrap' }}>
                    <span className="font-mono" style={{ fontSize: '0.8rem', fontWeight: 700, color: 'var(--accent-cyan)' }}>
                      {fId}
                    </span>
                    <span style={{ color: 'var(--text-muted)' }}>|</span>
                    <span style={{ fontSize: '0.95rem', fontWeight: 700, color: 'var(--text-primary)' }}>
                      {tName}
                    </span>
                    <span
                      style={{
                        fontSize: '0.7rem',
                        fontWeight: 700,
                        padding: '0.15rem 0.45rem',
                        borderRadius: '4px',
                        background: 'rgba(99, 102, 241, 0.15)',
                        color: 'var(--accent-indigo)',
                        border: '1px solid rgba(99, 102, 241, 0.3)',
                      }}
                    >
                      MITRE: {mId} {mTactic ? `• ${mTactic}` : ''}
                    </span>
                  </div>

                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                    <span
                      style={{
                        fontSize: '0.7rem',
                        fontWeight: 700,
                        padding: '0.2rem 0.55rem',
                        borderRadius: '4px',
                        color: sevColor,
                        background: sevBg,
                        border: `1px solid ${sevColor}50`,
                      }}
                    >
                      {sev} SEVERITY
                    </span>
                    <span
                      style={{
                        fontSize: '0.7rem',
                        fontWeight: 600,
                        padding: '0.2rem 0.55rem',
                        borderRadius: '4px',
                        background: 'rgba(255, 255, 255, 0.05)',
                        color: 'var(--text-secondary)',
                      }}
                    >
                      {conf} CONFIDENCE
                    </span>
                  </div>
                </div>

                {/* Observable Indicator */}
                <div
                  style={{
                    background: 'rgba(255, 255, 255, 0.02)',
                    border: '1px solid var(--border-subtle)',
                    borderRadius: '6px',
                    padding: '0.75rem 1rem',
                  }}
                >
                  <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 700, marginBottom: '0.25rem' }}>
                    Observable Forensic Indicator (Observed Evidence)
                  </div>
                  <div style={{ fontSize: '0.85rem', color: 'var(--text-primary)', lineHeight: 1.4 }}>
                    {f.observed_indicator || 'No indicator details recorded.'}
                  </div>
                </div>

                {/* Analytical Explanation */}
                <div style={{ fontSize: '0.85rem', color: 'var(--text-secondary)', lineHeight: 1.5 }}>
                  <strong style={{ color: 'var(--accent-amber)', fontSize: '0.75rem', textTransform: 'uppercase', letterSpacing: '0.04em' }}>
                    [ANALYTICAL INTERPRETATION]:{' '}
                  </strong>
                  {f.explanation || 'Analytical explanation generated by forensic technique rules.'}
                </div>

                {/* Traceability Bar */}
                <div
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                    flexWrap: 'wrap',
                    gap: '0.75rem',
                    paddingTop: '0.75rem',
                    borderTop: '1px solid var(--border-subtle)',
                    fontSize: '0.75rem',
                  }}
                >
                  {/* Traceability Breadcrumb */}
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', color: 'var(--text-muted)', flexWrap: 'wrap' }}>
                    <span style={{ color: 'var(--accent-cyan)' }}>Finding</span>
                    <span>→</span>
                    <span style={{ color: 'var(--accent-emerald)' }}>Evidence Vault</span>
                    <span>→</span>
                    <span style={{ color: 'var(--accent-indigo)' }}>Timeline</span>
                    <span>→</span>
                    <span style={{ color: '#ec4899' }}>MITRE ATT&amp;CK</span>
                    <span>→</span>
                    <span style={{ color: '#fff' }}>Forensic Report</span>
                  </div>

                  {/* Evidence IDs */}
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', flexWrap: 'wrap' }}>
                    <span style={{ color: 'var(--text-muted)' }}>Evidence Artifacts:</span>
                    {eids.length > 0 ? (
                      eids.map((eid) => (
                        <button
                          key={eid}
                          type="button"
                          onClick={() => onNavigateTab('evidence')}
                          title="View sealed artifact in Evidence Vault"
                          className="font-mono"
                          style={{
                            background: 'rgba(56, 189, 248, 0.08)',
                            border: '1px solid rgba(56, 189, 248, 0.25)',
                            borderRadius: '4px',
                            padding: '0.15rem 0.45rem',
                            color: 'var(--accent-cyan)',
                            fontSize: '0.7rem',
                            cursor: 'pointer',
                          }}
                        >
                          📦 {eid}
                        </button>
                      ))
                    ) : (
                      <span className="font-mono" style={{ color: 'var(--text-muted)' }}>
                        N/A
                      </span>
                    )}
                  </div>
                </div>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
