import React, { useState } from 'react';
import { API_BASE } from './config.js';

export default function ReportSection({
  investigationData,
  reportResult,
  reportLoading,
  reportFormat,
  setReportFormat,
  reportExaminer,
  setReportExaminer,
  onGenerateReport,
  onDownloadReport,
}) {
  const [activePreviewFormat, setActivePreviewFormat] = useState('RENDERED'); // RENDERED, SOURCE, METADATA
  const [reportError, setReportError] = useState(null);

  const caseId = investigationData?.case_id || 'LAB-2026-001';

  const handleGenerate = async (fmt) => {
    setReportError(null);
    if (setReportFormat) setReportFormat(fmt);
    try {
      await onGenerateReport(fmt);
    } catch (err) {
      setReportError(err?.message || 'Failed to generate forensic report.');
    }
  };

  const handleDownload = (fmt) => {
    const selectedFormat = fmt || reportFormat;
    if (onDownloadReport) {
      onDownloadReport(selectedFormat);
    } else {
      window.open(
        `${API_BASE}/api/forensics/report/download?format=${selectedFormat.toLowerCase()}&case_id=${encodeURIComponent(caseId)}`,
        '_blank'
      );
    }
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      {/* Action Header Card */}
      <div
        style={{
          background: 'linear-gradient(180deg, rgba(15, 23, 42, 0.9) 0%, rgba(12, 17, 29, 0.9) 100%)',
          borderRadius: '12px',
          border: '1px solid var(--border-color)',
          padding: '1.5rem',
          display: 'flex',
          flexDirection: 'column',
          gap: '1.25rem',
        }}
      >
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexWrap: 'wrap', gap: '1rem' }}>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
              <span style={{ fontSize: '1.4rem' }}>📄</span>
              <h2 style={{ fontSize: '1.25rem', fontWeight: 800, color: 'var(--text-primary)', margin: 0 }}>
                Forensic Investigation Report Engine
              </h2>
              <span
                style={{
                  fontSize: '0.72rem',
                  fontWeight: 700,
                  padding: '0.2rem 0.55rem',
                  borderRadius: '4px',
                  background: 'rgba(56, 189, 248, 0.1)',
                  color: 'var(--accent-cyan)',
                  border: '1px solid rgba(56, 189, 248, 0.25)',
                }}
              >
                Official Attestation
              </span>
            </div>
            <p style={{ fontSize: '0.82rem', color: 'var(--text-secondary)', marginTop: '0.35rem' }}>
              Generate structured, tamper-evident forensic reports for Case <span className="font-mono" style={{ color: 'var(--accent-cyan)' }}>{caseId}</span>.
            </p>
          </div>

          {/* Quick Download Button if report is generated */}
          {reportResult && (
            <button
              onClick={() => handleDownload(reportFormat)}
              style={{
                background: 'rgba(16, 185, 129, 0.15)',
                border: '1px solid var(--accent-emerald)',
                color: 'var(--accent-emerald)',
                borderRadius: '6px',
                padding: '0.5rem 1rem',
                fontSize: '0.82rem',
                fontWeight: 700,
                cursor: 'pointer',
                display: 'flex',
                alignItems: 'center',
                gap: '0.4rem',
              }}
            >
              <span>⬇</span>
              <span>Download {reportFormat} Report</span>
            </button>
          )}
        </div>

        {/* Examiner & Config Controls */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(240px, 1fr))', gap: '1rem', alignItems: 'flex-end' }}>
          <div>
            <label style={{ fontSize: '0.72rem', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 700, display: 'block', marginBottom: '0.35rem' }}>
              Lead Forensic Examiner
            </label>
            <input
              type="text"
              value={reportExaminer}
              onChange={(e) => setReportExaminer(e.target.value)}
              placeholder="e.g. JOCKY Lead Forensic Examiner"
              style={{
                width: '100%',
                background: '#04070d',
                border: '1px solid var(--border-color)',
                borderRadius: '6px',
                padding: '0.55rem 0.85rem',
                color: 'var(--text-primary)',
                fontSize: '0.85rem',
              }}
            />
          </div>

          <div>
            <label style={{ fontSize: '0.72rem', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 700, display: 'block', marginBottom: '0.35rem' }}>
              Active Target / Case
            </label>
            <div
              className="font-mono"
              style={{
                background: 'rgba(0, 0, 0, 0.3)',
                border: '1px solid var(--border-subtle)',
                borderRadius: '6px',
                padding: '0.55rem 0.85rem',
                color: 'var(--accent-cyan)',
                fontSize: '0.82rem',
              }}
            >
              {caseId} • {investigationData?.target || 'LAB-PC'}
            </div>
          </div>
        </div>

        {/* Required Format Buttons: Generate HTML, Generate JSON, Generate Markdown */}
        <div style={{ display: 'flex', gap: '0.75rem', flexWrap: 'wrap', paddingTop: '0.5rem', borderTop: '1px solid var(--border-subtle)' }}>
          <button
            onClick={() => handleGenerate('HTML')}
            disabled={reportLoading}
            style={{
              background: reportFormat === 'HTML' ? 'linear-gradient(135deg, #0ea5e9, #0284c7)' : 'rgba(14, 165, 233, 0.15)',
              border: '1px solid var(--accent-cyan)',
              color: '#fff',
              borderRadius: '6px',
              padding: '0.55rem 1.1rem',
              fontSize: '0.82rem',
              fontWeight: 700,
              cursor: reportLoading ? 'not-allowed' : 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: '0.4rem',
            }}
          >
            <span>🌐</span>
            <span>Generate HTML Report</span>
          </button>

          <button
            onClick={() => handleGenerate('JSON')}
            disabled={reportLoading}
            style={{
              background: reportFormat === 'JSON' ? 'linear-gradient(135deg, #6366f1, #4f46e5)' : 'rgba(99, 102, 241, 0.15)',
              border: '1px solid var(--accent-indigo)',
              color: '#fff',
              borderRadius: '6px',
              padding: '0.55rem 1.1rem',
              fontSize: '0.82rem',
              fontWeight: 700,
              cursor: reportLoading ? 'not-allowed' : 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: '0.4rem',
            }}
          >
            <span>{'{ }'}</span>
            <span>Generate JSON Report</span>
          </button>

          <button
            onClick={() => handleGenerate('MARKDOWN')}
            disabled={reportLoading}
            style={{
              background: reportFormat === 'MARKDOWN' ? 'linear-gradient(135deg, #10b981, #059669)' : 'rgba(16, 185, 129, 0.15)',
              border: '1px solid var(--accent-emerald)',
              color: '#fff',
              borderRadius: '6px',
              padding: '0.55rem 1.1rem',
              fontSize: '0.82rem',
              fontWeight: 700,
              cursor: reportLoading ? 'not-allowed' : 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: '0.4rem',
            }}
          >
            <span>📝</span>
            <span>Generate Markdown Report</span>
          </button>
        </div>

        {/* Loading Indicator */}
        {reportLoading && (
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem', color: 'var(--accent-cyan)', fontSize: '0.85rem' }}>
            <span className="pulse-dot" style={{ width: '8px', height: '8px', borderRadius: '50%', background: 'var(--accent-cyan)' }} />
            <span>Compiling forensic findings and calculating cryptographic hashes...</span>
          </div>
        )}

        {/* Error Notification */}
        {reportError && (
          <div
            style={{
              background: 'rgba(239, 68, 68, 0.12)',
              border: '1px solid var(--accent-rose)',
              borderRadius: '6px',
              padding: '0.75rem 1rem',
              color: 'var(--accent-rose)',
              fontSize: '0.82rem',
            }}
          >
            ⚠️ {reportError}
          </div>
        )}
      </div>

      {/* Report Preview Section */}
      <div
        style={{
          background: 'var(--bg-card)',
          borderRadius: '12px',
          border: '1px solid var(--border-color)',
          padding: '1.25rem',
          display: 'flex',
          flexDirection: 'column',
          gap: '1rem',
        }}
      >
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '0.75rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
            <h3 style={{ fontSize: '1rem', fontWeight: 700, color: 'var(--text-primary)', margin: 0 }}>
              Report Preview ({reportFormat})
            </h3>
            {reportResult && (
              <span
                style={{
                  fontSize: '0.7rem',
                  fontWeight: 700,
                  padding: '0.15rem 0.5rem',
                  borderRadius: '4px',
                  background: 'rgba(16, 185, 129, 0.15)',
                  color: 'var(--accent-emerald)',
                }}
              >
                ✓ COMPILED
              </span>
            )}
          </div>

          {reportResult && (
            <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
              <div style={{ display: 'flex', background: 'rgba(0,0,0,0.4)', borderRadius: '6px', padding: '0.15rem' }}>
                <button
                  onClick={() => setActivePreviewFormat('RENDERED')}
                  style={{
                    background: activePreviewFormat === 'RENDERED' ? 'rgba(56, 189, 248, 0.2)' : 'transparent',
                    color: activePreviewFormat === 'RENDERED' ? 'var(--accent-cyan)' : 'var(--text-muted)',
                    border: 'none',
                    borderRadius: '4px',
                    padding: '0.3rem 0.65rem',
                    fontSize: '0.75rem',
                    fontWeight: 600,
                    cursor: 'pointer',
                  }}
                >
                  View
                </button>
                <button
                  onClick={() => setActivePreviewFormat('SOURCE')}
                  style={{
                    background: activePreviewFormat === 'SOURCE' ? 'rgba(56, 189, 248, 0.2)' : 'transparent',
                    color: activePreviewFormat === 'SOURCE' ? 'var(--accent-cyan)' : 'var(--text-muted)',
                    border: 'none',
                    borderRadius: '4px',
                    padding: '0.3rem 0.65rem',
                    fontSize: '0.75rem',
                    fontWeight: 600,
                    cursor: 'pointer',
                  }}
                >
                  Raw Source
                </button>
              </div>

              <button
                onClick={() => handleDownload(reportFormat)}
                style={{
                  background: 'linear-gradient(135deg, #0ea5e9, #6366f1)',
                  border: 'none',
                  color: '#fff',
                  borderRadius: '6px',
                  padding: '0.4rem 0.9rem',
                  fontSize: '0.78rem',
                  fontWeight: 700,
                  cursor: 'pointer',
                }}
              >
                Download Report
              </button>
            </div>
          )}
        </div>

        {/* Preview Container */}
        {!reportResult ? (
          <div
            style={{
              padding: '3rem',
              textAlign: 'center',
              color: 'var(--text-muted)',
              background: 'rgba(10, 15, 26, 0.5)',
              borderRadius: '8px',
              border: '1px dashed var(--border-subtle)',
            }}
          >
            <div style={{ fontSize: '2rem', marginBottom: '0.5rem' }}>📋</div>
            <div style={{ fontSize: '0.9rem', fontWeight: 600, color: 'var(--text-secondary)' }}>
              No forensic report generated yet.
            </div>
            <div style={{ fontSize: '0.78rem', marginTop: '0.25rem' }}>
              Click &ldquo;Generate HTML Report&rdquo;, &ldquo;Generate JSON Report&rdquo;, or &ldquo;Generate Markdown Report&rdquo; above.
            </div>
          </div>
        ) : activePreviewFormat === 'RENDERED' && reportFormat === 'HTML' ? (
          <div style={{ border: '1px solid var(--border-subtle)', borderRadius: '8px', overflow: 'hidden', minHeight: '450px' }}>
            <iframe
              title="HTML Report Preview"
              srcDoc={reportResult.content || ''}
              style={{
                width: '100%',
                height: '520px',
                border: 'none',
                background: '#ffffff',
              }}
            />
          </div>
        ) : (
          <div style={{ position: 'relative' }}>
            <pre
              className="font-mono"
              style={{
                margin: 0,
                background: '#04070d',
                border: '1px solid var(--border-color)',
                borderRadius: '8px',
                padding: '1.25rem',
                color: reportFormat === 'JSON' ? '#38bdf8' : '#e2e8f0',
                fontSize: '0.8rem',
                lineHeight: 1.5,
                maxHeight: '520px',
                overflowY: 'auto',
                whiteSpace: 'pre-wrap',
                wordBreak: 'break-word',
              }}
            >
              {typeof reportResult.content === 'object'
                ? JSON.stringify(reportResult.content, null, 2)
                : String(reportResult.content || '')}
            </pre>
          </div>
        )}
      </div>
    </div>
  );
}
