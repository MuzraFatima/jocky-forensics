import React, { useState, useEffect } from 'react';
import { API_BASE } from './config.js';
import Sidebar from './Sidebar.jsx';
import Login from './Login.jsx';
import CyberSupport from './CyberSupport.jsx';
import CriticalIncidentAlert from './CriticalIncidentAlert.jsx';
import ReportModal from './ReportModal.jsx';
import LogoutModal from './LogoutModal.jsx';
import CommandSearch, { SUPPORTED_COMMANDS } from './CommandSearch.jsx';
import ReportSection from './ReportSection.jsx';

const CANONICAL_SCRIPT = `CASE "LAB-2026-001"
TARGET "LAB-PC"

COLLECT SYSTEM

COLLECT PROCESSES
    WHERE status == RUNNING

COLLECT NETWORK
    WHERE state == ESTABLISHED

ANALYZE PROCESS_NETWORK

VERIFY INTEGRITY

REPORT FORMAT JSON`;

const EXAMPLE_SCRIPT = `CASE "INCIDENT-2026-ALPHA"
TARGET "LOCAL-HOST"

COLLECT SYSTEM

COLLECT PROCESSES
    WHERE status == RUNNING

COLLECT NETWORK
    WHERE state == ESTABLISHED

COLLECT FILES "evidence"

COLLECT USERS

COLLECT REGISTRY

ANALYZE PROCESS_NETWORK

VERIFY INTEGRITY

REPORT FORMAT JSON`;

function ProcessTreeNode({ node, depth = 0 }) {
  const [expanded, setExpanded] = useState(depth < 2);
  const hasChildren = node.children && node.children.length > 0;

  return (
    <div style={{
      marginLeft: depth > 0 ? '1.5rem' : '0',
      marginTop: '0.4rem',
      borderLeft: depth > 0 ? '1px dashed rgba(56, 189, 248, 0.25)' : 'none',
      paddingLeft: depth > 0 ? '0.75rem' : '0'
    }}>
      <div style={{
        display: 'flex',
        alignItems: 'center',
        gap: '0.5rem',
        padding: '0.45rem 0.75rem',
        borderRadius: '6px',
        background: depth === 0 ? 'rgba(30, 41, 59, 0.7)' : 'rgba(15, 23, 42, 0.5)',
        border: '1px solid var(--border-color)',
        fontSize: '0.8rem',
      }}>
        {hasChildren ? (
          <button
            onClick={() => setExpanded(!expanded)}
            style={{
              background: 'none',
              border: 'none',
              color: 'var(--accent-cyan)',
              cursor: 'pointer',
              padding: '0 0.2rem',
              fontWeight: 700,
              fontSize: '0.75rem',
            }}
          >
            {expanded ? '▼' : '▶'}
          </button>
        ) : (
          <span style={{ color: 'var(--text-muted)', fontSize: '0.7rem' }}>•</span>
        )}
        <span style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{node.name}</span>
        <span style={{ color: 'var(--accent-cyan)', fontFamily: 'monospace', fontSize: '0.72rem' }}>PID: {node.pid}</span>
        <span style={{
          fontSize: '0.65rem',
          padding: '0.1rem 0.4rem',
          borderRadius: '4px',
          background: 'rgba(56, 189, 248, 0.1)',
          color: 'var(--accent-cyan)',
          fontFamily: 'monospace',
        }}>
          {node.entity_id}
        </span>
        {node.username && (
          <span style={{ color: 'var(--text-muted)', fontSize: '0.72rem' }}>({node.username})</span>
        )}
        {hasChildren && (
          <span style={{
            fontSize: '0.65rem',
            padding: '0.1rem 0.45rem',
            borderRadius: '999px',
            background: 'rgba(99, 102, 241, 0.15)',
            color: 'var(--accent-indigo)',
            fontWeight: 600,
          }}>
            {node.children.length} {node.children.length === 1 ? 'child' : 'children'}
          </span>
        )}
      </div>

      {hasChildren && expanded && (
        <div style={{ marginTop: '0.2rem' }}>
          {node.children.map((childNode, idx) => (
            <ProcessTreeNode key={childNode.pid || idx} node={childNode} depth={depth + 1} />
          ))}
        </div>
      )}
    </div>
  );
}

export default function App() {
  const [scriptText, setScriptText] = useState(CANONICAL_SCRIPT);
  const VALID_TABS = [
    'overview', 'support', 'correlation', 'timeline', 'system',
    'processes', 'network', 'files', 'users',
    'windows', 'evidence', 'reports', 'execute', 'script', 'commands'
  ];

  const [scriptToast, setScriptToast] = useState(null);
  const [isCommandModalOpen, setIsCommandModalOpen] = useState(false);

  const getInitialTab = () => {
    try {
      const hash = window.location.hash.replace('#', '').trim();
      return VALID_TABS.includes(hash) ? hash : 'overview';
    } catch {
      return 'overview';
    }
  };

  const [activeTab, setActiveTab] = useState(getInitialTab);
  const [sidebarCollapsed, setSidebarCollapsed] = useState(() => {
    try {
      return localStorage.getItem('jocky_sidebar_collapsed') === 'true';
    } catch {
      return false;
    }
  });
  const [mobileOpen, setMobileOpen] = useState(false);
  const [isMobile, setIsMobile] = useState(() => typeof window !== 'undefined' && window.innerWidth <= 900);

  // Base Forensic & Telemetry State
  const [loading, setLoading] = useState(false);
  const [apiError, setApiError] = useState(null);
  const [investigationData, setInvestigationData] = useState(null);
  const [backendHealth, setBackendHealth] = useState({ status: 'checking', details: null });

  // Filter states
  const [processSearch, setProcessSearch] = useState('');
  const [networkSearch, setNetworkSearch] = useState('');
  const [networkProtoFilter, setNetworkProtoFilter] = useState('ALL'); // ALL, TCP, UDP, LISTEN, ESTABLISHED
  const [copiedHash, setCopiedHash] = useState(null);
  // Compiler state (Phase 1 DSL)
  const [compilerResult, setCompilerResult] = useState(null);
  const [compiling, setCompiling] = useState(false);
  // Phase 2 Execute state
  const [executeData, setExecuteData] = useState(null);
  const [executeLoading, setExecuteLoading] = useState(false);
  const [executeError, setExecuteError] = useState(null);
  const [collectorProgress, setCollectorProgress] = useState(null);

  // Phase 3 Forensic Collector states
  const [filesData, setFilesData] = useState(null);
  const [usersData, setUsersData] = useState(null);
  const [windowsData, setWindowsData] = useState(null);
  const [directLoading, setDirectLoading] = useState({});
  const [fileSearch, setFileSearch] = useState('');
  const [serviceSearch, setServiceSearch] = useState('');

  // Phase 4 Correlation state
  const [correlationData, setCorrelationData] = useState(null);
  const [correlationLoading, setCorrelationLoading] = useState(false);
  const [correlationSearch, setCorrelationSearch] = useState('');
  const [correlationSubTab, setCorrelationSubTab] = useState('chains'); // chains, tree, entities

  // Phase 5 Timeline & Heuristics state
  const [timelineData, setTimelineData] = useState(null);
  const [analysisData, setAnalysisData] = useState(null);
  const [timelineLoading, setTimelineLoading] = useState(false);
  const [timelineSearch, setTimelineSearch] = useState('');
  const [timelineEventTypeFilter, setTimelineEventTypeFilter] = useState('ALL');
  const [ruleSeverityFilter, setRuleSeverityFilter] = useState('ALL');

  // Phase 6 Evidence Vault state
  const [vaultAudit, setVaultAudit] = useState(null);
  const [vaultLedger, setVaultLedger] = useState([]);
  const [vaultLoading, setVaultLoading] = useState(false);
  const [showLedger, setShowLedger] = useState(false);
  const [vaultTamperMsg, setVaultTamperMsg] = useState(null);

  // Phase 7 Platform state
  const [platformInfo, setPlatformInfo] = useState(null);

  // Phase 8 Report state
  const [reportFormat, setReportFormat] = useState('HTML');
  const [reportExaminer, setReportExaminer] = useState('JOCKY Lead Forensic Examiner');
  const [reportResult, setReportResult] = useState(null);
  const [reportLoading, setReportLoading] = useState(false);

  // Authentication & Security Workflow State
  const [session, setSession] = useState(() => {
    try {
      const stored = sessionStorage.getItem('jocky_session');
      return stored ? JSON.parse(stored) : null;
    } catch {
      return null;
    }
  });

  const [currentIncident, setCurrentIncident] = useState(null);
  const [isReportModalOpen, setIsReportModalOpen] = useState(false);
  const [isLogoutModalOpen, setIsLogoutModalOpen] = useState(false);
  const [isLogoutWorkflow, setIsLogoutWorkflow] = useState(false);
  const [analystStatus, setAnalystStatus] = useState('ONLINE');

  const handleLoginSuccess = (newSession) => {
    setSession(newSession);
    try {
      sessionStorage.setItem('jocky_session', JSON.stringify(newSession));
    } catch (e) {}
  };

  const handleInsertCommand = (syntax) => {
    setScriptText((prev) => {
      const trimmed = prev.trim();
      if (!trimmed) return syntax;
      return `${trimmed}\n\n${syntax}`;
    });
    setScriptToast(`Inserted: ${syntax.split('\n')[0]}`);
    setTimeout(() => setScriptToast(null), 2500);
    setActiveTab('script');
  };

  const handleClearScript = () => {
    setScriptText('CASE "INCIDENT-NEW"\nTARGET "LOCAL-HOST"\n\n');
    setScriptToast('Script reset to base template');
    setTimeout(() => setScriptToast(null), 2000);
  };

  const handleLoadExample = () => {
    setScriptText(EXAMPLE_SCRIPT);
    setScriptToast('Loaded INCIDENT-2026-ALPHA example');
    setTimeout(() => setScriptToast(null), 2000);
  };

  const handleLogoutWithoutSending = async () => {
    try {
      if (session?.token) {
        await fetch(`${API_BASE}/api/auth/logout`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            token: session.token,
            report_sent_status: 'LOGOUT_WITHOUT_SENDING',
            case_id: investigationData?.case_id || 'LAB-2026-001',
          }),
        });
      }
    } catch (e) {
      console.error(e);
    }
    setSession(null);
    setIsLogoutModalOpen(false);
    try {
      sessionStorage.removeItem('jocky_session');
    } catch (e) {}
  };

  const handleLogoutAfterReport = async () => {
    try {
      if (session?.token) {
        await fetch(`${API_BASE}/api/auth/logout`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            token: session.token,
            report_sent_status: 'REPORT_DISPATCHED_BEFORE_LOGOUT',
            case_id: investigationData?.case_id || 'LAB-2026-001',
          }),
        });
      }
    } catch (e) {
      console.error(e);
    }
    setSession(null);
    setIsReportModalOpen(false);
    setIsLogoutModalOpen(false);
    try {
      sessionStorage.removeItem('jocky_session');
    } catch (e) {}
  };

  const fetchIncidentData = async () => {
    try {
      const cId = investigationData?.case_id || 'LAB-2026-001';
      const tgt = investigationData?.target || 'LAB-PC';
      const res = await fetch(`${API_BASE}/api/security/incident/current?case_id=${encodeURIComponent(cId)}&target=${encodeURIComponent(tgt)}`);
      if (res.ok) {
        const data = await res.json();
        if (data.success && data.incident) {
          setCurrentIncident(data.incident);
        }
      }
    } catch (e) {
      console.error('Failed to fetch current incident:', e);
    }
  };

  const fetchAnalystStatus = async () => {
    try {
      const res = await fetch(`${API_BASE}/api/security/analyst/status`);
      if (res.ok) {
        const data = await res.json();
        if (data.status) setAnalystStatus(data.status);
      }
    } catch (e) {}
  };

  useEffect(() => {
    if (session) {
      fetchIncidentData();
      fetchAnalystStatus();
    }
  }, [session, investigationData]);

  const navigateToTab = (tabId) => {
    setActiveTab(tabId);
    try {
      window.location.hash = tabId;
    } catch (e) {}
    if (isMobile) {
      setMobileOpen(false);
    }
  };

  const handleToggleSidebar = () => {
    setSidebarCollapsed((prev) => {
      const next = !prev;
      try {
        localStorage.setItem('jocky_sidebar_collapsed', String(next));
      } catch (e) {}
      return next;
    });
  };

  useEffect(() => {
    const handleHashChange = () => {
      const hash = window.location.hash.replace('#', '').trim();
      if (VALID_TABS.includes(hash)) {
        setActiveTab(hash);
      }
    };
    window.addEventListener('hashchange', handleHashChange);
    return () => window.removeEventListener('hashchange', handleHashChange);
  }, []);

  useEffect(() => {
    const handleResize = () => {
      const mobile = window.innerWidth <= 900;
      setIsMobile(mobile);
      if (!mobile) {
        setMobileOpen(false);
      }
    };
    window.addEventListener('resize', handleResize);
    return () => window.removeEventListener('resize', handleResize);
  }, []);

  const handleFetchVault = async (caseId) => {
    setVaultLoading(true);
    try {
      const q = caseId ? `?case_id=${encodeURIComponent(caseId)}` : '';
      const res = await fetch(`${API_BASE}/api/forensics/vault/audit${q}`);
      const json = await res.json();
      if (json.success) {
        setVaultAudit(json.audit_summary);
        setVaultLedger(json.custody_ledger || []);
      }
    } catch (err) {
      console.error('Error fetching vault audit:', err);
    } finally {
      setVaultLoading(false);
    }
  };

  const handleVerifyArtifact = async (evidenceId) => {
    try {
      const res = await fetch(`${API_BASE}/api/forensics/vault/verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ evidence_id: evidenceId }),
      });
      const json = await res.json();
      if (json.success) {
        handleFetchVault();
      }
    } catch (err) {
      console.error('Error verifying artifact:', err);
    }
  };

  const handleAuditEntireVault = async () => {
    setVaultLoading(true);
    try {
      const res = await fetch(`${API_BASE}/api/forensics/vault/verify`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({}),
      });
      const json = await res.json();
      if (json.success) {
        handleFetchVault();
      }
    } catch (err) {
      console.error('Error auditing vault:', err);
    } finally {
      setVaultLoading(false);
    }
  };

  const handleSimulateTamper = async (evidenceId) => {
    if (!evidenceId) return;
    try {
      const res = await fetch(`${API_BASE}/api/forensics/vault/simulate-tampering`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ evidence_id: evidenceId, new_val: 'SIMULATED_MALICIOUS_INJECTION' }),
      });
      const json = await res.json();
      if (json.success) {
        setVaultTamperMsg(`Tampered payload for ${evidenceId}. Re-auditing vault...`);
        await fetch(`${API_BASE}/api/forensics/vault/verify`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ evidence_id: evidenceId }),
        });
        handleFetchVault();
      }
    } catch (err) {
      console.error('Error simulating tampering:', err);
    }
  };

  const handleExportBundle = (caseId) => {
    const cId = caseId || investigationData?.case_id || 'LAB-2026-001';
    window.open(`${API_BASE}/api/forensics/vault/export/${encodeURIComponent(cId)}`, '_blank');
  };

  const handleGenerateReport = async (fmtOverride) => {
    setReportLoading(true);
    const chosenFormat = (fmtOverride || reportFormat || 'HTML').toUpperCase();
    const collected = investigationData?.collected_data || executeData?.collected_data || null;
    const caseId = investigationData?.case_id || executeData?.case_id || 'LAB-2026-001';
    const target = investigationData?.target || executeData?.target || 'LAB-PC';
    try {
      const res = await fetch(`${API_BASE}/api/reports/generate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          case_id: caseId,
          target: target,
          format: chosenFormat,
          examiner: reportExaminer || 'JOCKY Lead Forensic Examiner',
          evidence: collected,
        }),
      });
      const json = await res.json();
      if (json.success) {
        setReportResult(json);
      }
    } catch (err) {
      console.error('Error generating report:', err);
    } finally {
      setReportLoading(false);
    }
  };

  const handleDownloadReport = (fmt) => {
    const cId = investigationData?.case_id || executeData?.case_id || 'LAB-2026-001';
    window.open(`${API_BASE}/api/forensics/report/download?format=${(fmt || reportFormat).toLowerCase()}&case_id=${encodeURIComponent(cId)}`, '_blank');
  };

  const handleAnalyzeEvidenceCorrelate = async (customEvidence = null) => {
    setCorrelationLoading(true);
    try {
      const evidence = customEvidence || investigationData?.collected_data || executeData?.collected_data || {};
      const res = await fetch(`${API_BASE}/api/forensics/correlate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ evidence }),
      });
      const json = await res.json();
      if (json.success && json.correlation) {
        setCorrelationData(json.correlation);
      }
    } catch (err) {
      console.error('Error correlating evidence:', err);
    } finally {
      setCorrelationLoading(false);
    }
  };
  const handleFetchCorrelation = handleAnalyzeEvidenceCorrelate;


  const handleFetchTimeline = async () => {
    setTimelineLoading(true);
    try {
      const [tlRes, anRes] = await Promise.all([
        fetch(`${API_BASE}/api/forensics/timeline`),
        fetch(`${API_BASE}/api/forensics/analysis`)
      ]);
      const tlJson = await tlRes.json();
      const anJson = await anRes.json();
      if (tlJson.success) setTimelineData(tlJson.timeline);
      if (anJson.success) setAnalysisData(anJson);
    } catch (err) {
      console.error('Error fetching timeline or analysis:', err);
    } finally {
      setTimelineLoading(false);
    }
  };

  const handleDirectCollect = async (source) => {
    setDirectLoading((prev) => ({ ...prev, [source]: true }));
    try {
      const res = await fetch(`${API_BASE}/api/forensics/collect/${source}`);
      const json = await res.json();
      if (json.success) {
        if (source === 'files') setFilesData(json.artifact);
        if (source === 'users') setUsersData(json.artifact);
        if (source === 'windows_metadata' || source === 'registry') setWindowsData(json.artifact);
      }
    } catch (err) {
      console.error(`Error in direct collect ${source}:`, err);
    } finally {
      setDirectLoading((prev) => ({ ...prev, [source]: false }));
    }
  };

  // Check backend health on mount and auto-trigger initial run if online
  useEffect(() => {
    fetch(`${API_BASE}/api/health`)
      .then((res) => res.json())
      .then((data) => {
        setBackendHealth({ status: 'online', details: data });
        // Run initial live investigation
        handleRunInvestigation(CANONICAL_SCRIPT);
      })
      .catch((err) => {
        setBackendHealth({ status: 'offline', error: err.message });
      });

    // Fetch cross-platform status and initial vault audit
    fetch(`${API_BASE}/api/forensics/platform`)
      .then((res) => res.json())
      .then((data) => { if (data.success) setPlatformInfo(data); })
      .catch(() => {});

    handleFetchVault();
  }, []);

  const handleExecuteScript = async (codeToRun = scriptText) => {
    setLoading(true);
    setExecuteLoading(true);
    setApiError(null);
    setExecuteError(null);

    // Normalize bare COLLECT FILES so scripts without paths execute seamlessly
    const normalizedCode = (codeToRun || '').replace(
      /^\s*COLLECT\s+FILES\s*$/gim,
      'COLLECT FILES "evidence"'
    );

    // Initialize collector progress pipeline: SYSTEM → PROCESSES → NETWORK → FILES
    setCollectorProgress({
      active: true,
      system: normalizedCode.includes('COLLECT SYSTEM') ? 'running' : 'skipped',
      processes: normalizedCode.includes('COLLECT PROCESSES') ? 'pending' : 'skipped',
      network: normalizedCode.includes('COLLECT NETWORK') ? 'pending' : 'skipped',
      files: normalizedCode.includes('COLLECT FILES') ? 'pending' : 'skipped',
    });

    try {
      const response = await fetch(`${API_BASE}/api/jocky/execute`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ script: normalizedCode }),
      });

      const result = await response.json();
      const { success, execution_id, evidence_collected, errors } = result;

      if (!response.ok || success === false || (errors && errors.length > 0)) {
        const errMsg = (errors && errors.length > 0)
          ? errors.join('; ')
          : (result.message || 'The script failed to execute.');
        setApiError({
          error_type: result.error_type || 'ExecutionError',
          message: errMsg,
          line: result.line,
          column: result.column,
        });
        setExecuteError(result);
        setCollectorProgress((prev) => ({
          ...(prev || {}),
          system: prev?.system === 'running' ? 'failed' : (prev?.system || 'failed'),
          processes: prev?.processes === 'running' ? 'failed' : (prev?.processes || 'failed'),
          network: prev?.network === 'running' ? 'failed' : (prev?.network || 'failed'),
          files: prev?.files === 'running' ? 'failed' : (prev?.files || 'failed'),
        }));
      } else {
        setInvestigationData(result);
        setExecuteData(result);

        const cd = result.collected_data || {};
        setCollectorProgress({
          active: true,
          system: cd.system ? 'completed' : 'skipped',
          processes: cd.processes ? 'completed' : 'skipped',
          network: cd.network ? 'completed' : 'skipped',
          files: cd.files ? 'completed' : 'skipped',
        });

        if (result.correlation) {
          setCorrelationData(result.correlation);
        } else if (result.collected_data) {
          handleAnalyzeEvidenceCorrelate(result.collected_data);
        }

        if (result.timeline) setTimelineData(result.timeline);
        if (result.detections) setAnalysisData({ detections: result.detections });

        handleFetchVault(result.case_id);
      }
    } catch (err) {
      const netErr = {
        error_type: 'NetworkError',
        message: `Failed to connect to JOCKY backend: ${err.message}`,
      };
      setApiError(netErr);
      setExecuteError(netErr);
    } finally {
      setLoading(false);
      setExecuteLoading(false);
    }
  };

  const handleRunInvestigation = handleExecuteScript;
  const handleRunExecute = handleExecuteScript;


  useEffect(() => {
    if (activeTab === 'correlation' && !correlationData && !correlationLoading) {
      handleFetchCorrelation();
    }
    if (activeTab === 'timeline' && !timelineData && !timelineLoading) {
      handleFetchTimeline();
    }
  }, [activeTab]);

  const handleCompile = async () => {
    setCompiling(true);
    setCompilerResult(null);
    try {
      const response = await fetch(`${API_BASE}/api/jocky/compile`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ script: scriptText }),
      });
      const data = await response.json();
      setCompilerResult(data);
    } catch (err) {
      setCompilerResult({
        success: false,
        error_type: 'NetworkError',
        message: `Failed to connect to JOCKY backend: ${err.message}`,
        line: null,
        column: null,
      });
    } finally {
      setCompiling(false);
    }
  };

  const renderCollectorProgressUI = () => {
    if (!collectorProgress && !loading && !executeLoading) return null;
    return (
      <div id="collector-pipeline-ui" style={{
        background: 'rgba(15, 23, 42, 0.85)',
        border: '1px solid rgba(99, 102, 241, 0.3)',
        borderRadius: '10px',
        padding: '1.25rem',
        marginTop: '1rem',
        marginBottom: '1.25rem',
        boxShadow: '0 8px 32px rgba(0, 0, 0, 0.37)',
      }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '0.85rem' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
            <span style={{ fontSize: '1.1rem' }}>⚡</span>
            <span style={{ fontWeight: 700, fontSize: '0.92rem', color: 'var(--text-primary)' }}>
              Collector Execution Pipeline
            </span>
            <span style={{
              fontSize: '0.72rem',
              padding: '0.2rem 0.6rem',
              borderRadius: '4px',
              fontWeight: 700,
              background: (loading || executeLoading) ? 'rgba(14, 165, 233, 0.15)' : 'rgba(16, 185, 129, 0.15)',
              color: (loading || executeLoading) ? 'var(--accent-cyan)' : 'var(--accent-emerald)',
              border: `1px solid ${(loading || executeLoading) ? 'rgba(14, 165, 233, 0.3)' : 'rgba(16, 185, 129, 0.3)'}`,
            }}>
              {(loading || executeLoading) ? 'Executing...' : 'Completed'}
            </span>
          </div>
          {(investigationData?.execution_id || executeData?.execution_id) && (
            <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)', fontFamily: 'JetBrains Mono, monospace' }}>
              Execution ID: {investigationData?.execution_id || executeData?.execution_id}
            </span>
          )}
        </div>

        {/* Stage Progress: SYSTEM → PROCESSES → NETWORK → FILES */}
        <div style={{
          display: 'flex',
          alignItems: 'center',
          gap: '0.5rem',
          flexWrap: 'wrap',
          padding: '0.75rem',
          background: 'rgba(0, 0, 0, 0.25)',
          borderRadius: '8px',
          border: '1px solid var(--border-subtle)',
        }}>
          {['SYSTEM', 'PROCESSES', 'NETWORK', 'FILES'].map((stage, idx, arr) => {
            const stageKey = stage.toLowerCase();
            const status = collectorProgress?.[stageKey] || ((loading || executeLoading) ? 'running' : 'completed');
            const isRunning = (loading || executeLoading) && (status === 'running' || status === 'pending');
            const isDone = !loading && !executeLoading && (status === 'completed' || status === 'done' || !!investigationData?.collected_data?.[stageKey]);
            const hasData = investigationData?.collected_data?.[stageKey] || executeData?.collected_data?.[stageKey];

            let badgeLabel = stage;
            if (stage === 'SYSTEM' && hasData) {
              badgeLabel = `SYSTEM (${hasData.hostname || hasData.os || 'Verified'})`;
            } else if (stage === 'PROCESSES' && hasData) {
              const pCount = hasData.count || (hasData.processes && hasData.processes.length) || 0;
              badgeLabel = `PROCESSES (${pCount} active)`;
            } else if (stage === 'NETWORK' && hasData) {
              const nCount = hasData.count || (hasData.connections && hasData.connections.length) || 0;
              badgeLabel = `NETWORK (${nCount} sockets)`;
            } else if (stage === 'FILES' && hasData) {
              const fCount = hasData.count || (hasData.files && hasData.files.length) || 0;
              badgeLabel = `FILES (${fCount} files)`;
            }

            return (
              <React.Fragment key={stage}>
                <div style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '0.45rem',
                  padding: '0.45rem 0.85rem',
                  borderRadius: '6px',
                  fontFamily: 'JetBrains Mono, monospace',
                  fontSize: '0.8rem',
                  fontWeight: 700,
                  background: isDone
                    ? 'rgba(16, 185, 129, 0.12)'
                    : isRunning
                    ? 'rgba(14, 165, 233, 0.15)'
                    : 'rgba(255, 255, 255, 0.04)',
                  color: isDone
                    ? 'var(--accent-emerald)'
                    : isRunning
                    ? 'var(--accent-cyan)'
                    : 'var(--text-muted)',
                  border: `1px solid ${
                    isDone
                      ? 'rgba(16, 185, 129, 0.3)'
                      : isRunning
                      ? 'rgba(14, 165, 233, 0.4)'
                      : 'rgba(255, 255, 255, 0.08)'
                  }`,
                  transition: 'all 0.2s ease',
                }}>
                  <span>{isDone ? '✓' : isRunning ? '⚡' : '○'}</span>
                  <span>{badgeLabel}</span>
                </div>
                {idx < arr.length - 1 && (
                  <span style={{ color: 'var(--text-muted)', fontWeight: 700, fontSize: '0.9rem' }}>→</span>
                )}
              </React.Fragment>
            );
          })}
        </div>

        {/* Display Collector Results & Evidence Hashes */}
        {investigationData?.evidence_collected && investigationData.evidence_collected.length > 0 && (
          <div style={{ marginTop: '0.85rem', display: 'flex', flexDirection: 'column', gap: '0.4rem' }}>
            <div style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-secondary)' }}>
              Collected Evidence Artifacts ({investigationData.evidence_collected.length} sealed):
            </div>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(260px, 1fr))', gap: '0.5rem' }}>
              {investigationData.evidence_collected.map((ev, i) => (
                <div key={i} style={{
                  background: 'rgba(255, 255, 255, 0.02)',
                  border: '1px solid var(--border-subtle)',
                  borderRadius: '6px',
                  padding: '0.5rem 0.75rem',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '0.2rem',
                }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <span style={{ fontWeight: 700, fontSize: '0.78rem', color: 'var(--accent-indigo)' }}>
                      {ev.category?.toUpperCase()}
                    </span>
                    <span style={{ fontSize: '0.68rem', color: 'var(--accent-emerald)', fontWeight: 600 }}>
                      ✓ SEALED IN VAULT
                    </span>
                  </div>
                  <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', fontFamily: 'JetBrains Mono, monospace' }}>
                    {ev.evidence_id}
                  </div>
                  {ev.sha256 && (
                    <div style={{ fontSize: '0.68rem', color: 'var(--text-secondary)', fontFamily: 'JetBrains Mono, monospace' }}>
                      SHA: {ev.sha256.slice(0, 16)}...
                    </div>
                  )}
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    );
  };


  const handleExportJSON = () => {
    if (!investigationData) return;
    const blob = new Blob([JSON.stringify(investigationData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `JOCKY_INVESTIGATION_${investigationData.case_id || 'EXPORT'}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  const handleCopy = (text, key = text) => {
    if (!text) return;
    navigator.clipboard?.writeText(text);
    setCopiedHash(key);
    setTimeout(() => setCopiedHash(null), 2000);
  };

  // Derived filtered data
  const processesList = investigationData?.collected_data?.processes?.processes || [];
  const filteredProcesses = processesList.filter((p) => {
    if (!processSearch) return true;
    const q = processSearch.toLowerCase();
    return (
      (p.name && p.name.toLowerCase().includes(q)) ||
      (p.pid !== undefined && String(p.pid).includes(q)) ||
      (p.username && p.username.toLowerCase().includes(q)) ||
      (p.exe && p.exe.toLowerCase().includes(q))
    );
  });

  const networkList = investigationData?.collected_data?.network?.connections || [];
  const filteredNetwork = networkList.filter((conn) => {
    // Protocol / Status chips filter
    if (networkProtoFilter === 'TCP' && conn.protocol !== 'TCP') return false;
    if (networkProtoFilter === 'UDP' && conn.protocol !== 'UDP') return false;
    if (networkProtoFilter === 'LISTEN' && conn.status !== 'LISTEN') return false;
    if (networkProtoFilter === 'ESTABLISHED' && conn.status !== 'ESTABLISHED') return false;

    if (!networkSearch) return true;
    const q = networkSearch.toLowerCase();
    return (
      (conn.local_address && conn.local_address.toLowerCase().includes(q)) ||
      (conn.local_port !== undefined && String(conn.local_port).includes(q)) ||
      (conn.remote_address && conn.remote_address.toLowerCase().includes(q)) ||
      (conn.remote_port !== undefined && String(conn.remote_port).includes(q)) ||
      (conn.status && conn.status.toLowerCase().includes(q)) ||
      (conn.pid !== undefined && String(conn.pid).includes(q))
    );
  });

  const systemInfo = investigationData?.collected_data?.system || {};
  const networkInfo = investigationData?.collected_data?.network || {};
  const processCount = investigationData?.collected_data?.processes?.count || 0;
  const networkCount = networkInfo.count || 0;
  const listenCount = networkList.filter((c) => c.status === 'LISTEN').length;
  const establishedCount = networkList.filter((c) => c.status === 'ESTABLISHED').length;

  const TAB_LABELS = {
    overview: 'Overview & Analysis',
    support: 'Cybersecurity Support',
    correlation: 'Correlation Graph',
    timeline: 'Forensic Timeline',
    system: 'System Telemetry',
    processes: 'Active Processes',
    network: 'Network Sockets',
    files: 'Files & Binaries',
    users: 'Users & Sessions',
    windows: platformInfo?.is_linux ? 'Linux Persistence' : 'Windows Persistence',
    evidence: 'Evidence Vault',
    reports: 'Forensic Reports',
    execute: 'Execution Engine',
    script: 'JOCKY Script Editor',
    commands: 'Command Search',
  };
  const activeTabLabel = TAB_LABELS[activeTab] || 'Overview & Analysis';

  if (!session) {
    return <Login onLoginSuccess={handleLoginSuccess} />;
  }

  return (
    <div style={{ minHeight: '100vh', display: 'flex', backgroundColor: 'var(--bg-primary)' }}>
      {/* ChatGPT-style Left Sidebar */}
      <Sidebar
        activeTab={activeTab}
        onSelectTab={navigateToTab}
        collapsed={sidebarCollapsed}
        onToggleCollapse={handleToggleSidebar}
        mobileOpen={mobileOpen}
        onCloseMobile={() => setMobileOpen(false)}
        platformInfo={platformInfo}
        session={session}
        onOpenLogout={() => setIsLogoutModalOpen(true)}
        analystStatus={analystStatus}
        counts={{
          correlation: correlationData?.summary?.correlated_chains_count ?? null,
          timeline: timelineData?.length ?? null,
          processes: processCount || null,
          network: networkCount || null,
          evidence: vaultAudit?.total_artifacts ?? null,
        }}
      />

      {/* Main Content Layout Container */}
      <div
        className="main-content-layout"
        style={{
          marginLeft: isMobile ? 0 : (sidebarCollapsed ? '68px' : '260px'),
          width: isMobile ? '100%' : `calc(100% - ${sidebarCollapsed ? '68px' : '260px'})`,
          minHeight: '100vh',
          display: 'flex',
          flexDirection: 'column',
          transition: 'all 0.24s cubic-bezier(0.4, 0, 0.2, 1)',
        }}
      >
        {/* Top SOC Navbar */}
        <header style={{
          borderBottom: '1px solid var(--border-color)',
          backdropFilter: 'blur(16px)',
          backgroundColor: 'rgba(6, 9, 15, 0.85)',
          position: 'sticky',
          top: 0,
          zIndex: 50,
          padding: '0.75rem 2rem',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          flexWrap: 'wrap',
          gap: '1rem',
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.85rem' }}>
            <button
              onClick={() => (isMobile ? setMobileOpen(!mobileOpen) : handleToggleSidebar())}
              title={isMobile ? 'Toggle Navigation Menu' : (sidebarCollapsed ? 'Expand Sidebar' : 'Collapse Sidebar')}
              aria-label="Toggle Navigation Menu"
              style={{
                background: 'rgba(255, 255, 255, 0.04)',
                border: '1px solid var(--border-color)',
                borderRadius: '8px',
                color: 'var(--accent-cyan)',
                width: '36px',
                height: '36px',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                cursor: 'pointer',
                fontSize: '1.1rem',
                flexShrink: 0,
              }}
            >
              ☰
            </button>

            <div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flexWrap: 'wrap' }}>
                <h1 style={{ fontSize: '1.1rem', fontWeight: 800, letterSpacing: '-0.02em', color: '#fff' }}>
                  JOCKY FORENSICS
                </h1>
                <span style={{
                  fontSize: '0.65rem',
                  fontWeight: 700,
                  color: 'var(--accent-cyan)',
                  background: 'rgba(56, 189, 248, 0.1)',
                  border: '1px solid rgba(56, 189, 248, 0.25)',
                  padding: '0.15rem 0.4rem',
                  borderRadius: '4px',
                  letterSpacing: '0.05em',
                }}>
                  SIH26148 PROTOTYPE
                </span>
                <span style={{ color: 'var(--border-accent)', fontSize: '0.75rem' }}>•</span>
                <span style={{ fontSize: '0.82rem', color: 'var(--accent-cyan)', fontWeight: 600 }}>
                  {activeTabLabel}
                </span>
              </div>
              <p style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>
                Domain-Specific Scripting &amp; Authorized Read-Only Forensic Architecture
              </p>
            </div>
          </div>

        {/* Global Security & Status Pills */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', flexWrap: 'wrap' }}>
          <div style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: '0.4rem',
            padding: '0.3rem 0.75rem',
            borderRadius: '9999px',
            fontSize: '0.75rem',
            fontWeight: 600,
            background: 'rgba(16, 185, 129, 0.1)',
            color: 'var(--accent-emerald)',
            border: '1px solid rgba(16, 185, 129, 0.25)',
          }}>
            <span style={{ width: '6px', height: '6px', borderRadius: '50%', backgroundColor: 'var(--accent-emerald)' }} />
            STRICTLY READ-ONLY
          </div>

          <div style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: '0.4rem',
            padding: '0.3rem 0.75rem',
            borderRadius: '9999px',
            fontSize: '0.75rem',
            fontWeight: 600,
            background: 'var(--bg-surface)',
            border: '1px solid var(--border-color)',
          }}>
            <span style={{
              width: '6px',
              height: '6px',
              borderRadius: '50%',
              backgroundColor: backendHealth.status === 'online' ? 'var(--accent-emerald)' : 'var(--accent-amber)',
            }} className="pulse-dot" />
            BACKEND: <span style={{ color: backendHealth.status === 'online' ? 'var(--accent-emerald)' : 'var(--text-secondary)' }}>{backendHealth.status.toUpperCase()}</span>
          </div>

          {platformInfo && (
            <div style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: '0.45rem',
              padding: '0.3rem 0.75rem',
              borderRadius: '9999px',
              fontSize: '0.75rem',
              fontWeight: 600,
              background: 'rgba(56, 189, 248, 0.08)',
              color: 'var(--accent-cyan)',
              border: '1px solid rgba(56, 189, 248, 0.25)',
            }}>
              <span>{platformInfo.is_windows ? '🪟' : '🐧'}</span>
              <span>{platformInfo.platform?.toUpperCase()}</span>
              <span style={{ color: 'var(--text-muted)', fontSize: '0.68rem', fontFamily: 'monospace' }}>
                {platformInfo.architecture}
              </span>
            </div>
          )}

          <button
            onClick={handleExportJSON}
            disabled={!investigationData}
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: '0.4rem',
              padding: '0.4rem 0.9rem',
              borderRadius: '6px',
              fontSize: '0.8rem',
              fontWeight: 600,
              background: investigationData ? 'rgba(56, 189, 248, 0.1)' : 'rgba(255,255,255,0.03)',
              color: investigationData ? 'var(--accent-cyan)' : 'var(--text-muted)',
              border: '1px solid var(--border-color)',
              cursor: investigationData ? 'pointer' : 'not-allowed',
            }}
          >
            ⬇ Export JSON
          </button>

          <button
            onClick={() => {
              setIsLogoutWorkflow(false);
              setIsReportModalOpen(true);
            }}
            title="Generate & Send Forensic Report"
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: '0.4rem',
              padding: '0.4rem 0.9rem',
              borderRadius: '6px',
              fontSize: '0.8rem',
              fontWeight: 600,
              background: 'linear-gradient(135deg, rgba(14, 165, 233, 0.2), rgba(99, 102, 241, 0.2))',
              color: '#fff',
              border: '1px solid rgba(56, 189, 248, 0.35)',
              cursor: 'pointer',
            }}
          >
            📄 Generate &amp; Send Report
          </button>

          <button
            onClick={() => setIsLogoutModalOpen(true)}
            title="End Investigation Session"
            style={{
              display: 'inline-flex',
              alignItems: 'center',
              gap: '0.4rem',
              padding: '0.4rem 0.85rem',
              borderRadius: '6px',
              fontSize: '0.8rem',
              fontWeight: 600,
              background: 'rgba(244, 63, 94, 0.08)',
              color: '#fda4af',
              border: '1px solid rgba(244, 63, 94, 0.3)',
              cursor: 'pointer',
            }}
          >
            <span>⎋</span> Logout
          </button>
        </div>
      </header>

      {/* Main Workspace Layout */}
      <main style={{ maxWidth: '1400px', margin: '0 auto', padding: '1.5rem 2rem', flex: 1, width: '100%' }}>
        {/* Error Notification Banner */}
        {apiError && (
          <div style={{
            background: 'rgba(244, 63, 94, 0.1)',
            border: '1px solid rgba(244, 63, 94, 0.3)',
            borderRadius: '8px',
            padding: '1rem 1.25rem',
            marginBottom: '1.5rem',
            display: 'flex',
            alignItems: 'flex-start',
            gap: '0.85rem',
          }}>
            <div style={{ fontSize: '1.2rem', color: 'var(--accent-rose)' }}>⚠</div>
            <div style={{ flex: 1 }}>
              <div style={{ fontWeight: 700, color: 'var(--accent-rose)', fontSize: '0.9rem' }}>
                {apiError.error_type} {apiError.line ? `(Line ${apiError.line}, Col ${apiError.column})` : ''}
              </div>
              <div style={{ fontSize: '0.85rem', color: '#fda4af', marginTop: '0.2rem' }}>
                {apiError.message}
              </div>
            </div>
            <button
              onClick={() => setApiError(null)}
              style={{ background: 'transparent', border: 'none', color: '#fda4af', fontSize: '1rem', cursor: 'pointer' }}
            >
              ✕
            </button>
          </div>
        )}

        {/* Executive Case & Action Bar */}
        <section style={{
          background: 'linear-gradient(180deg, rgba(15, 23, 42, 0.8) 0%, rgba(12, 17, 29, 0.8) 100%)',
          borderRadius: '12px',
          border: '1px solid var(--border-color)',
          padding: '1.25rem 1.5rem',
          marginBottom: '1.5rem',
          boxShadow: '0 10px 30px rgba(0,0,0,0.3)',
        }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '1rem' }}>
            <div>
              <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                Current Active Investigation
              </div>
              <div style={{ display: 'flex', alignItems: 'baseline', gap: '0.75rem', marginTop: '0.2rem' }}>
                <h2 style={{ fontSize: '1.5rem', fontWeight: 800, color: 'var(--text-primary)', letterSpacing: '-0.02em' }}>
                  {investigationData?.case_id || 'LAB-2026-001'}
                </h2>
                <span style={{ fontSize: '0.9rem', color: 'var(--accent-cyan)', fontWeight: 600 }}>
                  Target: {investigationData?.target || 'LAB-PC'}
                </span>
              </div>
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: '0.85rem' }}>
              <div style={{
                padding: '0.4rem 0.8rem',
                borderRadius: '6px',
                background: 'rgba(255,255,255,0.03)',
                border: '1px solid var(--border-subtle)',
                fontSize: '0.78rem',
              }}>
                <span style={{ color: 'var(--text-muted)' }}>Status: </span>
                <span style={{ fontWeight: 700, color: investigationData?.status === 'COMPLETED' ? 'var(--accent-emerald)' : 'var(--accent-amber)' }}>
                  {loading ? 'RUNNING...' : (investigationData?.status || 'READY')}
                </span>
              </div>

              <button
                id="btn-run-investigation"
                onClick={() => handleExecuteScript()}
                disabled={loading || executeLoading}
                style={{
                  background: (loading || executeLoading) ? 'rgba(14, 165, 233, 0.4)' : 'linear-gradient(135deg, #0ea5e9, #6366f1)',
                  color: '#fff',
                  border: 'none',
                  borderRadius: '6px',
                  padding: '0.55rem 1.25rem',
                  fontSize: '0.85rem',
                  fontWeight: 700,
                  display: 'flex',
                  alignItems: 'center',
                  gap: '0.5rem',
                  boxShadow: '0 4px 15px rgba(14, 165, 233, 0.3)',
                  cursor: (loading || executeLoading) ? 'not-allowed' : 'pointer',
                }}
              >
                {(loading || executeLoading) ? 'Executing...' : '▶ Run Investigation'}
              </button>
            </div>
          </div>
        </section>

        {/* Real-time Collector Pipeline Execution UI */}
        {renderCollectorProgressUI()}


        {/* Metric KPI Cards */}
        <section style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '1rem', marginBottom: '1.5rem' }}>
          {/* System Card */}
          <div style={{ background: 'var(--bg-card)', borderRadius: '10px', border: '1px solid var(--border-color)', padding: '1rem' }}>
            <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600 }}>Operating System</div>
            <div style={{ fontSize: '1.15rem', fontWeight: 700, color: 'var(--text-primary)', marginTop: '0.3rem' }}>
              {systemInfo.os ? `${systemInfo.os} (${systemInfo.architecture || ''})` : 'Awaiting collection'}
            </div>
            <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', marginTop: '0.2rem' }}>
              Host: <span className="font-mono">{systemInfo.hostname || '...'}</span>
            </div>
          </div>

          {/* Processes Card */}
          <div style={{ background: 'var(--bg-card)', borderRadius: '10px', border: '1px solid var(--border-color)', padding: '1rem' }}>
            <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600 }}>Active Processes</div>
            <div style={{ fontSize: '1.5rem', fontWeight: 800, color: 'var(--accent-cyan)', marginTop: '0.2rem' }}>
              {processCount}
            </div>
            <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', marginTop: '0.2rem' }}>
              Safe read-only psutil inspection
            </div>
          </div>

          {/* Network Sockets Card */}
          <div style={{ background: 'var(--bg-card)', borderRadius: '10px', border: '1px solid var(--border-color)', padding: '1rem' }}>
            <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600 }}>Network Telemetry</div>
            <div style={{ fontSize: '1.5rem', fontWeight: 800, color: 'var(--accent-indigo)', marginTop: '0.2rem' }}>
              {networkCount}
            </div>
            <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', marginTop: '0.2rem' }}>
              <span style={{ color: 'var(--accent-emerald)' }}>{listenCount} Listen</span> • <span>{establishedCount} Est.</span>
            </div>
          </div>

          {/* Evidence Integrity Card */}
          <div style={{ background: 'var(--bg-card)', borderRadius: '10px', border: '1px solid var(--border-color)', padding: '1rem' }}>
            <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600 }}>Cryptographic Integrity</div>
            <div style={{ fontSize: '1.15rem', fontWeight: 700, color: 'var(--accent-emerald)', marginTop: '0.3rem', display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
              <span>✓</span> {investigationData?.integrity_status?.verified ? 'VERIFIED (3/3 Hashes)' : 'Pending Verification'}
            </div>
            <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', marginTop: '0.2rem' }}>
              Immutable SHA-256 Vault
            </div>
          </div>
        </section>



        {/* TAB: CYBERSECURITY SUPPORT */}
        {activeTab === 'support' && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
            <CriticalIncidentAlert
              incident={currentIncident}
              onViewIncident={() => {
                navigateToTab('timeline');
              }}
              onPreserveEvidence={async () => {
                try {
                  await handleVerifyVault();
                } catch (e) {
                  console.error(e);
                }
              }}
              onContactSecurity={() => {
                navigateToTab('support');
              }}
              onGenerateReport={() => {
                setIsLogoutWorkflow(false);
                setIsReportModalOpen(true);
              }}
            />
            <CyberSupport
              session={session}
              activeCaseId={investigationData?.case_id || 'LAB-2026-001'}
              currentIncident={currentIncident}
              onOpenReportModal={() => {
                setIsLogoutWorkflow(false);
                setIsReportModalOpen(true);
              }}
            />
          </div>
        )}

        {/* TAB: COMMAND SEARCH */}
        {activeTab === 'commands' && (
          <CommandSearch
            onInsertCommand={(cmdSyntax) => handleInsertCommand(cmdSyntax)}
          />
        )}

        {/* TAB 1: OVERVIEW & ANALYSIS */}
        {activeTab === 'overview' && (
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(400px, 1fr))', gap: '1.5rem' }}>
            {/* Forensic Indicators & Heuristic Analysis */}
            <div style={{ background: 'var(--bg-card)', borderRadius: '10px', border: '1px solid var(--border-color)', padding: '1.5rem' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
                <h3 style={{ fontSize: '1rem', fontWeight: 700, color: 'var(--text-primary)' }}>
                  Forensic Indicators &amp; Analysis
                </h3>
                <span style={{
                  fontSize: '0.7rem',
                  padding: '0.2rem 0.5rem',
                  borderRadius: '4px',
                  background: 'rgba(56, 189, 248, 0.1)',
                  color: 'var(--accent-cyan)',
                  fontWeight: 600,
                }}>
                  POTENTIAL FORENSIC INDICATORS
                </span>
              </div>
              <p style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', marginBottom: '1.2rem', lineHeight: 1.5 }}>
                *Note: These observations represent automated baseline forensic indicators and heuristic observations. They do not claim definitive malware categorization.
              </p>

              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                {investigationData?.analysis?.findings?.map((finding, idx) => (
                  <div key={idx} style={{
                    display: 'flex',
                    alignItems: 'flex-start',
                    gap: '0.75rem',
                    padding: '0.75rem 1rem',
                    borderRadius: '6px',
                    background: 'rgba(255,255,255,0.02)',
                    border: '1px solid var(--border-subtle)',
                  }}>
                    <span style={{ color: 'var(--accent-cyan)', fontSize: '0.9rem' }}>ℹ</span>
                    <span style={{ fontSize: '0.85rem', color: 'var(--text-primary)', lineHeight: 1.4 }}>{finding}</span>
                  </div>
                )) || (
                  <div style={{ color: 'var(--text-muted)', fontSize: '0.85rem' }}>Run investigation to view findings.</div>
                )}
              </div>
            </div>

            {/* Forensic Pipeline Timeline */}
            <div style={{ background: 'var(--bg-card)', borderRadius: '10px', border: '1px solid var(--border-color)', padding: '1.5rem' }}>
              <h3 style={{ fontSize: '1rem', fontWeight: 700, color: 'var(--text-primary)', marginBottom: '1.2rem' }}>
                Investigation Pipeline Timeline
              </h3>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem', position: 'relative', paddingLeft: '0.5rem' }}>
                {[
                  { step: '1. Script Parse & Policy Verification', status: 'Approved (Read-Only)', time: investigationData?.timestamps?.started_at },
                  { step: '2. System Telemetry Collection', status: systemInfo.hostname ? 'Acquired & Buffered' : 'Pending', time: systemInfo.timestamp_utc },
                  { step: '3. Process Enumeration', status: `${processCount} Processes Extracted`, time: investigationData?.collected_data?.processes?.timestamp_utc },
                  { step: '4. Network Connection Discovery', status: `${networkCount} Sockets Mapped`, time: networkInfo.timestamp_utc },
                  { step: '5. SHA-256 Hashes & Evidence Vault', status: 'Cryptographically Locked', time: investigationData?.timestamps?.completed_at },
                  { step: '6. Cryptographic Integrity Verification', status: '3 / 3 Verified Match', time: investigationData?.timestamps?.completed_at },
                  { step: '7. Investigation Report Generation', status: 'Report Compiled', time: investigationData?.report?.generated_at },
                ].map((item, idx) => (
                  <div key={idx} style={{ display: 'flex', alignItems: 'flex-start', gap: '1rem' }}>
                    <div style={{
                      width: '10px',
                      height: '10px',
                      borderRadius: '50%',
                      background: 'var(--accent-cyan)',
                      boxShadow: '0 0 8px var(--accent-cyan)',
                      marginTop: '4px',
                    }} />
                    <div style={{ flex: 1 }}>
                      <div style={{ fontSize: '0.85rem', fontWeight: 600, color: 'var(--text-primary)' }}>{item.step}</div>
                      <div style={{ fontSize: '0.75rem', color: 'var(--accent-emerald)', marginTop: '0.1rem' }}>{item.status}</div>
                      {item.time && (
                        <div className="font-mono" style={{ fontSize: '0.68rem', color: 'var(--text-muted)', marginTop: '0.1rem' }}>
                          {item.time}
                        </div>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* TAB 2: SYSTEM TELEMETRY */}
        {activeTab === 'system' && (
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(350px, 1fr))', gap: '1.5rem' }}>
            <div style={{ background: 'var(--bg-card)', borderRadius: '10px', border: '1px solid var(--border-color)', padding: '1.5rem' }}>
              <h3 style={{ fontSize: '1rem', fontWeight: 700, color: 'var(--accent-cyan)', marginBottom: '1.2rem' }}>
                Host Environment
              </h3>
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.8rem', fontSize: '0.85rem' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid var(--border-subtle)', paddingBottom: '0.4rem' }}>
                  <span style={{ color: 'var(--text-muted)' }}>Hostname:</span>
                  <span className="font-mono" style={{ color: 'var(--text-primary)', fontWeight: 600 }}>{systemInfo.hostname || '...'}</span>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid var(--border-subtle)', paddingBottom: '0.4rem' }}>
                  <span style={{ color: 'var(--text-muted)' }}>Operating System:</span>
                  <span style={{ color: 'var(--text-primary)' }}>{systemInfo.os || '...'}</span>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid var(--border-subtle)', paddingBottom: '0.4rem' }}>
                  <span style={{ color: 'var(--text-muted)' }}>OS Build / Version:</span>
                  <span style={{ color: 'var(--text-primary)' }}>{systemInfo.os_version || '...'}</span>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid var(--border-subtle)', paddingBottom: '0.4rem' }}>
                  <span style={{ color: 'var(--text-muted)' }}>Architecture:</span>
                  <span className="font-mono" style={{ color: 'var(--text-primary)' }}>{systemInfo.architecture || '...'}</span>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid var(--border-subtle)', paddingBottom: '0.4rem' }}>
                  <span style={{ color: 'var(--text-muted)' }}>Current User Context:</span>
                  <span className="font-mono" style={{ color: 'var(--accent-indigo)', fontWeight: 600 }}>{systemInfo.username || '...'}</span>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid var(--border-subtle)', paddingBottom: '0.4rem' }}>
                  <span style={{ color: 'var(--text-muted)' }}>System Boot Time:</span>
                  <span className="font-mono" style={{ color: 'var(--text-secondary)', fontSize: '0.75rem' }}>{systemInfo.boot_time || '...'}</span>
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                  <span style={{ color: 'var(--text-muted)' }}>Uptime:</span>
                  <span style={{ color: 'var(--accent-emerald)', fontWeight: 600 }}>
                    {systemInfo.uptime_seconds ? `${Math.floor(systemInfo.uptime_seconds / 60)} min (${systemInfo.uptime_seconds}s)` : '...'}
                  </span>
                </div>
              </div>
            </div>

            <div style={{ background: 'var(--bg-card)', borderRadius: '10px', border: '1px solid var(--border-color)', padding: '1.5rem' }}>
              <h3 style={{ fontSize: '1rem', fontWeight: 700, color: 'var(--accent-cyan)', marginBottom: '1.2rem' }}>
                Hardware &amp; Resource Allocation
              </h3>
              {/* CPU specs */}
              <div style={{ marginBottom: '1.25rem' }}>
                <div style={{ fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Processor Specs</div>
                <div style={{ fontSize: '0.85rem', color: 'var(--text-primary)', marginTop: '0.2rem' }}>
                  {systemInfo.cpu?.processor || 'Standard Processor'}
                </div>
                <div style={{ display: 'flex', gap: '1rem', marginTop: '0.5rem' }}>
                  <div style={{ background: 'rgba(255,255,255,0.03)', padding: '0.4rem 0.75rem', borderRadius: '4px', border: '1px solid var(--border-subtle)' }}>
                    <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>Logical Cores: </span>
                    <strong style={{ color: 'var(--accent-cyan)' }}>{systemInfo.cpu?.count_logical ?? 'N/A'}</strong>
                  </div>
                  <div style={{ background: 'rgba(255,255,255,0.03)', padding: '0.4rem 0.75rem', borderRadius: '4px', border: '1px solid var(--border-subtle)' }}>
                    <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>Physical Cores: </span>
                    <strong style={{ color: 'var(--accent-cyan)' }}>{systemInfo.cpu?.count_physical ?? 'N/A'}</strong>
                  </div>
                </div>
              </div>

              {/* Memory specs */}
              <div>
                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.75rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>
                  <span>Physical RAM Utilization</span>
                  <span>{systemInfo.memory?.percent_used ?? 0}%</span>
                </div>
                <div style={{
                  width: '100%',
                  height: '8px',
                  borderRadius: '4px',
                  background: 'rgba(255,255,255,0.08)',
                  overflow: 'hidden',
                  marginTop: '0.4rem',
                }}>
                  <div style={{
                    width: `${systemInfo.memory?.percent_used || 0}%`,
                    height: '100%',
                    background: 'linear-gradient(90deg, #0ea5e9, #6366f1)',
                    borderRadius: '4px',
                  }} />
                </div>
                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '0.75rem', color: 'var(--text-secondary)', marginTop: '0.5rem' }}>
                  <span>Total: <strong>{systemInfo.memory?.total_human || '...'}</strong></span>
                  <span>Available: <strong>{systemInfo.memory?.available_human || '...'}</strong></span>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* TAB 3: PROCESSES */}
        {activeTab === 'processes' && (
          <div style={{ background: 'var(--bg-card)', borderRadius: '10px', border: '1px solid var(--border-color)', padding: '1.25rem' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem', flexWrap: 'wrap', gap: '0.75rem' }}>
              <div>
                <h3 style={{ fontSize: '1rem', fontWeight: 700, color: 'var(--text-primary)' }}>
                  Process Forensic Ledger
                </h3>
                <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                  Showing {filteredProcesses.length} of {processCount} live enumerated processes
                </p>
              </div>

              {/* Search Bar */}
              <input
                type="text"
                placeholder="Search PID, name, user, or exe..."
                value={processSearch}
                onChange={(e) => setProcessSearch(e.target.value)}
                style={{
                  background: 'var(--bg-surface)',
                  border: '1px solid var(--border-color)',
                  borderRadius: '6px',
                  padding: '0.45rem 0.85rem',
                  fontSize: '0.82rem',
                  minWidth: '280px',
                }}
              />
            </div>

            <div className="table-container" style={{ maxHeight: '600px' }}>
              <table>
                <thead>
                  <tr>
                    <th>PID</th>
                    <th>Process Name</th>
                    <th>User Context</th>
                    <th>Status</th>
                    <th>CPU %</th>
                    <th>Memory %</th>
                    <th>Executable Path</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredProcesses.slice(0, 200).map((proc, idx) => (
                    <tr key={idx}>
                      <td className="font-mono" style={{ color: 'var(--accent-cyan)', fontWeight: 600 }}>{proc.pid}</td>
                      <td style={{ fontWeight: 600 }}>{proc.name}</td>
                      <td className="font-mono" style={{ fontSize: '0.75rem', color: 'var(--text-secondary)' }}>{proc.username || '—'}</td>
                      <td>
                        <span style={{
                          fontSize: '0.7rem',
                          padding: '0.15rem 0.4rem',
                          borderRadius: '4px',
                          background: proc.status === 'running' ? 'rgba(16, 185, 129, 0.1)' : 'rgba(255,255,255,0.05)',
                          color: proc.status === 'running' ? 'var(--accent-emerald)' : 'var(--text-muted)',
                        }}>
                          {proc.status}
                        </span>
                      </td>
                      <td className="font-mono">{proc.cpu_percent !== null ? `${proc.cpu_percent}%` : '—'}</td>
                      <td className="font-mono">{proc.memory_percent !== null ? `${proc.memory_percent}%` : '—'}</td>
                      <td className="font-mono" style={{ fontSize: '0.72rem', color: 'var(--text-muted)', maxWidth: '280px', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                        {proc.exe || '—'}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* TAB 4: NETWORK */}
        {activeTab === 'network' && (
          <div style={{ background: 'var(--bg-card)', borderRadius: '10px', border: '1px solid var(--border-color)', padding: '1.25rem' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem', flexWrap: 'wrap', gap: '0.75rem' }}>
              <div>
                <h3 style={{ fontSize: '1rem', fontWeight: 700, color: 'var(--text-primary)' }}>
                  Active Network Connections
                </h3>
                <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                  Showing {filteredNetwork.length} of {networkCount} active sockets
                </p>
              </div>

              {/* Protocol Filters & Search */}
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', flexWrap: 'wrap' }}>
                {['ALL', 'LISTEN', 'ESTABLISHED', 'TCP', 'UDP'].map((f) => (
                  <button
                    key={f}
                    onClick={() => setNetworkProtoFilter(f)}
                    style={{
                      padding: '0.3rem 0.6rem',
                      borderRadius: '4px',
                      fontSize: '0.72rem',
                      fontWeight: 600,
                      border: '1px solid var(--border-color)',
                      background: networkProtoFilter === f ? 'rgba(56, 189, 248, 0.2)' : 'var(--bg-surface)',
                      color: networkProtoFilter === f ? 'var(--accent-cyan)' : 'var(--text-secondary)',
                    }}
                  >
                    {f}
                  </button>
                ))}

                <input
                  type="text"
                  placeholder="Filter IP, port, or PID..."
                  value={networkSearch}
                  onChange={(e) => setNetworkSearch(e.target.value)}
                  style={{
                    background: 'var(--bg-surface)',
                    border: '1px solid var(--border-color)',
                    borderRadius: '6px',
                    padding: '0.4rem 0.75rem',
                    fontSize: '0.8rem',
                    minWidth: '220px',
                  }}
                />
              </div>
            </div>

            <div className="table-container" style={{ maxHeight: '600px' }}>
              <table>
                <thead>
                  <tr>
                    <th>Protocol</th>
                    <th>Local Address</th>
                    <th>Local Port</th>
                    <th>Remote Address</th>
                    <th>Remote Port</th>
                    <th>Connection State</th>
                    <th>PID</th>
                  </tr>
                </thead>
                <tbody>
                  {filteredNetwork.slice(0, 200).map((conn, idx) => (
                    <tr key={idx}>
                      <td>
                        <span style={{
                          fontSize: '0.7rem',
                          fontWeight: 700,
                          padding: '0.15rem 0.4rem',
                          borderRadius: '4px',
                          background: conn.protocol === 'TCP' ? 'rgba(99, 102, 241, 0.15)' : 'rgba(245, 158, 11, 0.15)',
                          color: conn.protocol === 'TCP' ? 'var(--accent-indigo)' : 'var(--accent-amber)',
                        }}>
                          {conn.protocol}
                        </span>
                      </td>
                      <td className="font-mono">{conn.local_address || '—'}</td>
                      <td className="font-mono" style={{ color: 'var(--accent-cyan)', fontWeight: 600 }}>{conn.local_port || '—'}</td>
                      <td className="font-mono">{conn.remote_address || '—'}</td>
                      <td className="font-mono">{conn.remote_port || '—'}</td>
                      <td>
                        <span style={{
                          fontSize: '0.7rem',
                          padding: '0.15rem 0.4rem',
                          borderRadius: '4px',
                          background: conn.status === 'LISTEN' ? 'rgba(16, 185, 129, 0.1)' : (conn.status === 'ESTABLISHED' ? 'rgba(14, 165, 233, 0.1)' : 'rgba(255,255,255,0.05)'),
                          color: conn.status === 'LISTEN' ? 'var(--accent-emerald)' : (conn.status === 'ESTABLISHED' ? 'var(--accent-cyan)' : 'var(--text-muted)'),
                        }}>
                          {conn.status}
                        </span>
                      </td>
                      <td className="font-mono" style={{ color: 'var(--text-muted)' }}>{conn.pid ?? '—'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* TAB: FILES & BINARIES (Phase 3) */}
        {activeTab === 'files' && (() => {
          const filesObj = filesData || executeData?.collected_data?.files || investigationData?.collected_data?.files;
          const filesList = filesObj?.files || [];
          const procBinaries = filesObj?.process_binaries || [];
          const filteredFiles = filesList.filter((f) =>
            !fileSearch ||
            f.filename?.toLowerCase().includes(fileSearch.toLowerCase()) ||
            f.path?.toLowerCase().includes(fileSearch.toLowerCase()) ||
            f.extension?.toLowerCase().includes(fileSearch.toLowerCase())
          );

          return (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
              <div style={{
                background: 'linear-gradient(135deg, rgba(14,165,233,0.08) 0%, rgba(99,102,241,0.08) 100%)',
                borderRadius: '10px',
                border: '1px solid rgba(14,165,233,0.25)',
                padding: '1.25rem 1.5rem',
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
                flexWrap: 'wrap',
                gap: '1rem',
              }}>
                <div>
                  <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                    Phase 3 — Real Windows Forensic Collection
                  </div>
                  <div style={{ fontSize: '1.15rem', fontWeight: 800, color: 'var(--text-primary)', marginTop: '0.2rem' }}>
                    File System Telemetry &amp; Process Binary Verification
                  </div>
                  <div style={{ fontSize: '0.78rem', color: 'var(--text-secondary)', marginTop: '0.2rem' }}>
                    Method: <span className="font-mono" style={{ color: 'var(--accent-cyan)' }}>{filesObj?.provenance?.method || 'filesystem_stat_and_sha256_bounded_scan'}</span>
                    {' '} • Host: <span className="font-mono">{filesObj?.provenance?.host || '...'}</span>
                    {' '} • Operator: <span className="font-mono">{filesObj?.provenance?.collected_by || '...'}</span>
                  </div>
                </div>
                <button
                  onClick={() => handleDirectCollect('files')}
                  disabled={directLoading.files}
                  style={{
                    background: directLoading.files ? 'rgba(14,165,233,0.3)' : 'linear-gradient(135deg, #0ea5e9, #6366f1)',
                    color: '#fff',
                    border: 'none',
                    borderRadius: '6px',
                    padding: '0.55rem 1.1rem',
                    fontSize: '0.82rem',
                    fontWeight: 700,
                    cursor: directLoading.files ? 'not-allowed' : 'pointer',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '0.4rem',
                  }}
                >
                  {directLoading.files ? 'Scanning Filesystem...' : '⚡ Collect Live Files'}
                </button>
              </div>

              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '1rem' }}>
                <div style={{ background: 'var(--bg-card)', borderRadius: '10px', border: '1px solid var(--border-color)', padding: '1rem' }}>
                  <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Files Inspected</div>
                  <div style={{ fontSize: '1.4rem', fontWeight: 800, color: 'var(--accent-cyan)', marginTop: '0.2rem' }}>{filesList.length}</div>
                </div>
                <div style={{ background: 'var(--bg-card)', borderRadius: '10px', border: '1px solid var(--border-color)', padding: '1rem' }}>
                  <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Process Binaries Verified</div>
                  <div style={{ fontSize: '1.4rem', fontWeight: 800, color: 'var(--accent-indigo)', marginTop: '0.2rem' }}>{procBinaries.length}</div>
                </div>
                <div style={{ background: 'var(--bg-card)', borderRadius: '10px', border: '1px solid var(--border-color)', padding: '1rem' }}>
                  <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Executables Detected</div>
                  <div style={{ fontSize: '1.4rem', fontWeight: 800, color: 'var(--accent-amber)', marginTop: '0.2rem' }}>{filesObj?.summary?.executables_count ?? 0}</div>
                </div>
                <div style={{ background: 'var(--bg-card)', borderRadius: '10px', border: '1px solid var(--border-color)', padding: '1rem' }}>
                  <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>Evidence ID</div>
                  <div style={{ fontSize: '0.75rem', fontWeight: 700, color: 'var(--accent-emerald)', marginTop: '0.4rem', fontFamily: 'JetBrains Mono, monospace', wordBreak: 'break-all' }}>
                    {filesObj?.evidence_id || 'Pending Acquisition'}
                  </div>
                </div>
              </div>

              <div style={{ background: 'var(--bg-card)', borderRadius: '10px', border: '1px solid var(--border-color)', padding: '1.25rem' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem', flexWrap: 'wrap', gap: '0.75rem' }}>
                  <h3 style={{ fontSize: '0.95rem', fontWeight: 700, color: 'var(--text-primary)' }}>
                    Forensic Files List ({filteredFiles.length})
                  </h3>
                  <input
                    type="text"
                    placeholder="Filter by name, path, extension..."
                    value={fileSearch}
                    onChange={(e) => setFileSearch(e.target.value)}
                    style={{
                      background: 'rgba(0,0,0,0.3)',
                      border: '1px solid var(--border-color)',
                      borderRadius: '6px',
                      padding: '0.4rem 0.8rem',
                      fontSize: '0.8rem',
                      color: 'var(--text-primary)',
                      width: '260px',
                    }}
                  />
                </div>
                <div style={{ overflowX: 'auto' }}>
                  <table className="data-table" style={{ width: '100%', fontSize: '0.8rem' }}>
                    <thead>
                      <tr>
                        <th>Filename</th>
                        <th>Path</th>
                        <th>Size</th>
                        <th>Modified (UTC)</th>
                        <th>SHA-256 Digest</th>
                        <th>Flags</th>
                      </tr>
                    </thead>
                    <tbody>
                      {filteredFiles.slice(0, 100).map((f, i) => (
                        <tr key={i}>
                          <td style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{f.filename}</td>
                          <td className="font-mono" style={{ fontSize: '0.72rem', maxWidth: '280px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={f.path}>
                            {f.path}
                          </td>
                          <td className="font-mono">{(f.size_bytes / 1024).toFixed(1)} KB</td>
                          <td className="font-mono" style={{ fontSize: '0.72rem' }}>{f.modified_time || '—'}</td>
                          <td className="font-mono" style={{ fontSize: '0.7rem' }}>
                            {f.sha256 ? (
                              <span
                                onClick={() => handleCopy(f.sha256)}
                                title="Click to copy full SHA-256"
                                style={{ cursor: 'pointer', color: 'var(--accent-cyan)' }}
                              >
                                {f.sha256.slice(0, 16)}… {copiedHash === f.sha256 ? '✓' : '📋'}
                              </span>
                            ) : '—'}
                          </td>
                          <td>
                            <div style={{ display: 'flex', gap: '0.3rem' }}>
                              {f.is_executable && (
                                <span style={{ fontSize: '0.65rem', padding: '0.1rem 0.3rem', borderRadius: '3px', background: 'rgba(245,158,11,0.15)', color: 'var(--accent-amber)', fontWeight: 700 }}>EXE</span>
                              )}
                              {f.is_hidden && (
                                <span style={{ fontSize: '0.65rem', padding: '0.1rem 0.3rem', borderRadius: '3px', background: 'rgba(244,63,94,0.15)', color: 'var(--accent-rose)', fontWeight: 700 }}>HIDDEN</span>
                              )}
                              <span style={{ fontSize: '0.65rem', padding: '0.1rem 0.3rem', borderRadius: '3px', background: 'rgba(255,255,255,0.05)', color: 'var(--text-muted)' }}>{f.permissions}</span>
                            </div>
                          </td>
                        </tr>
                      ))}
                      {filteredFiles.length === 0 && (
                        <tr><td colSpan={6} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: '2rem' }}>No file records available or collection not yet triggered.</td></tr>
                      )}
                    </tbody>
                  </table>
                </div>
              </div>

              {procBinaries.length > 0 && (
                <div style={{ background: 'var(--bg-card)', borderRadius: '10px', border: '1px solid var(--border-color)', padding: '1.25rem' }}>
                  <h3 style={{ fontSize: '0.95rem', fontWeight: 700, color: 'var(--text-primary)', marginBottom: '1rem' }}>
                    Process Executable Binaries on Disk ({procBinaries.length})
                  </h3>
                  <div style={{ overflowX: 'auto' }}>
                    <table className="data-table" style={{ width: '100%', fontSize: '0.8rem' }}>
                      <thead>
                        <tr>
                          <th>Process</th>
                          <th>PID</th>
                          <th>Executable Path</th>
                          <th>Size</th>
                          <th>Binary SHA-256 Digest</th>
                        </tr>
                      </thead>
                      <tbody>
                        {procBinaries.slice(0, 50).map((b, i) => (
                          <tr key={i}>
                            <td style={{ fontWeight: 600, color: 'var(--accent-cyan)' }}>{b.associated_process_name || b.filename}</td>
                            <td className="font-mono">{b.associated_pid ?? '—'}</td>
                            <td className="font-mono" style={{ fontSize: '0.72rem', maxWidth: '300px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={b.path}>{b.path}</td>
                            <td className="font-mono">{(b.size_bytes / 1024).toFixed(1)} KB</td>
                            <td className="font-mono" style={{ fontSize: '0.7rem' }}>
                              {b.sha256 ? (
                                <span onClick={() => handleCopy(b.sha256)} title="Click to copy full SHA-256" style={{ cursor: 'pointer', color: 'var(--accent-indigo)' }}>
                                  {b.sha256.slice(0, 20)}… {copiedHash === b.sha256 ? '✓' : '📋'}
                                </span>
                              ) : '—'}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}
            </div>
          );
        })()}

        {/* TAB: USERS & SESSIONS (Phase 3) */}
        {activeTab === 'users' && (() => {
          const usersObj = usersData || executeData?.collected_data?.users || investigationData?.collected_data?.users;
          const cu = usersObj?.current_user || {};
          const sessions = usersObj?.active_sessions || [];
          const profiles = usersObj?.user_profiles || [];

          return (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
              <div style={{
                background: 'linear-gradient(135deg, rgba(16,185,129,0.08) 0%, rgba(14,165,233,0.08) 100%)',
                borderRadius: '10px',
                border: '1px solid rgba(16,185,129,0.25)',
                padding: '1.25rem 1.5rem',
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
                flexWrap: 'wrap',
                gap: '1rem',
              }}>
                <div>
                  <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                    Phase 3 — Real Windows Forensic Collection
                  </div>
                  <div style={{ fontSize: '1.15rem', fontWeight: 800, color: 'var(--text-primary)', marginTop: '0.2rem' }}>
                    User Accounts, Security Context &amp; Logon Sessions
                  </div>
                  <div style={{ fontSize: '0.78rem', color: 'var(--text-secondary)', marginTop: '0.2rem' }}>
                    Method: <span className="font-mono" style={{ color: 'var(--accent-emerald)' }}>{usersObj?.provenance?.method || 'psutil_users_and_registry_profilelist'}</span>
                    {' '} • Host: <span className="font-mono">{usersObj?.provenance?.host || '...'}</span>
                    {' '} • Operator: <span className="font-mono">{usersObj?.provenance?.collected_by || '...'}</span>
                  </div>
                </div>
                <button
                  onClick={() => handleDirectCollect('users')}
                  disabled={directLoading.users}
                  style={{
                    background: directLoading.users ? 'rgba(16,185,129,0.3)' : 'linear-gradient(135deg, #10b981, #0ea5e9)',
                    color: '#fff',
                    border: 'none',
                    borderRadius: '6px',
                    padding: '0.55rem 1.1rem',
                    fontSize: '0.82rem',
                    fontWeight: 700,
                    cursor: directLoading.users ? 'not-allowed' : 'pointer',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '0.4rem',
                  }}
                >
                  {directLoading.users ? 'Querying Users...' : '⚡ Collect Live Users'}
                </button>
              </div>

              <div style={{ background: 'var(--bg-card)', borderRadius: '10px', border: '1px solid var(--border-color)', padding: '1.25rem' }}>
                <h3 style={{ fontSize: '0.95rem', fontWeight: 700, color: 'var(--text-primary)', marginBottom: '1rem' }}>
                  Current Execution Security Context
                </h3>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '1rem' }}>
                  <div style={{ padding: '0.75rem', borderRadius: '6px', background: 'rgba(255,255,255,0.02)', border: '1px solid var(--border-subtle)' }}>
                    <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>LOGON USERNAME</div>
                    <div style={{ fontSize: '1rem', fontWeight: 700, color: 'var(--accent-cyan)', marginTop: '0.2rem' }}>{cu.username || 'unknown'}</div>
                  </div>
                  <div style={{ padding: '0.75rem', borderRadius: '6px', background: 'rgba(255,255,255,0.02)', border: '1px solid var(--border-subtle)' }}>
                    <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>DOMAIN / WORKGROUP</div>
                    <div style={{ fontSize: '1rem', fontWeight: 700, color: 'var(--text-primary)', marginTop: '0.2rem' }}>{cu.domain || 'WORKGROUP'}</div>
                  </div>
                  <div style={{ padding: '0.75rem', borderRadius: '6px', background: 'rgba(255,255,255,0.02)', border: '1px solid var(--border-subtle)' }}>
                    <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>ADMIN PRIVILEGES</div>
                    <div style={{ fontSize: '1rem', fontWeight: 700, color: cu.is_admin ? 'var(--accent-emerald)' : 'var(--accent-amber)', marginTop: '0.2rem' }}>
                      {cu.is_admin ? '🛡️ Elevated (Admin)' : 'Standard User'}
                    </div>
                  </div>
                  <div style={{ padding: '0.75rem', borderRadius: '6px', background: 'rgba(255,255,255,0.02)', border: '1px solid var(--border-subtle)' }}>
                    <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>SESSION NAME</div>
                    <div style={{ fontSize: '1rem', fontWeight: 700, color: 'var(--accent-indigo)', marginTop: '0.2rem' }}>{cu.session_name || 'Console'}</div>
                  </div>
                  <div style={{ padding: '0.75rem', borderRadius: '6px', background: 'rgba(255,255,255,0.02)', border: '1px solid var(--border-subtle)' }}>
                    <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>USER PROFILE PATH</div>
                    <div className="font-mono" style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', marginTop: '0.2rem', wordBreak: 'break-all' }}>{cu.home_path || '—'}</div>
                  </div>
                </div>
              </div>

              <div style={{ background: 'var(--bg-card)', borderRadius: '10px', border: '1px solid var(--border-color)', padding: '1.25rem' }}>
                <h3 style={{ fontSize: '0.95rem', fontWeight: 700, color: 'var(--text-primary)', marginBottom: '1rem' }}>
                  Active Interactive &amp; Remote Sessions ({sessions.length})
                </h3>
                <table className="data-table" style={{ width: '100%', fontSize: '0.82rem' }}>
                  <thead>
                    <tr>
                      <th>User Account</th>
                      <th>Terminal</th>
                      <th>Originating Host</th>
                      <th>Logon Time (UTC)</th>
                      <th>Associated PID</th>
                    </tr>
                  </thead>
                  <tbody>
                    {sessions.map((s, i) => (
                      <tr key={i}>
                        <td style={{ fontWeight: 700, color: 'var(--accent-cyan)' }}>{s.username}</td>
                        <td className="font-mono">{s.terminal}</td>
                        <td className="font-mono">{s.host}</td>
                        <td className="font-mono">{s.started_time || '—'}</td>
                        <td className="font-mono">{s.pid ?? '—'}</td>
                      </tr>
                    ))}
                    {sessions.length === 0 && (
                      <tr><td colSpan={5} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: '1.5rem' }}>No active interactive sessions reported.</td></tr>
                    )}
                  </tbody>
                </table>
              </div>

              {profiles.length > 0 && (
                <div style={{ background: 'var(--bg-card)', borderRadius: '10px', border: '1px solid var(--border-color)', padding: '1.25rem' }}>
                  <h3 style={{ fontSize: '0.95rem', fontWeight: 700, color: 'var(--text-primary)', marginBottom: '1rem' }}>
                    Windows Registered User Profiles (Registry ProfileList) ({profiles.length})
                  </h3>
                  <table className="data-table" style={{ width: '100%', fontSize: '0.82rem' }}>
                    <thead>
                      <tr>
                        <th>Account Name</th>
                        <th>Security Identifier (SID)</th>
                        <th>Profile Image Path</th>
                        <th>Classification</th>
                      </tr>
                    </thead>
                    <tbody>
                      {profiles.map((p, i) => (
                        <tr key={i}>
                          <td style={{ fontWeight: 700, color: 'var(--text-primary)' }}>{p.account_name}</td>
                          <td className="font-mono" style={{ fontSize: '0.72rem', color: 'var(--accent-indigo)' }}>{p.sid}</td>
                          <td className="font-mono" style={{ fontSize: '0.75rem' }}>{p.profile_image_path || '—'}</td>
                          <td>
                            <span style={{
                              fontSize: '0.68rem',
                              padding: '0.15rem 0.4rem',
                              borderRadius: '4px',
                              background: p.is_system_sid ? 'rgba(255,255,255,0.06)' : 'rgba(14,165,233,0.15)',
                              color: p.is_system_sid ? 'var(--text-muted)' : 'var(--accent-cyan)',
                              fontWeight: 600,
                            }}>
                              {p.is_system_sid ? 'SYSTEM BUILT-IN' : 'USER ACCOUNT'}
                            </span>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          );
        })()}

        {/* TAB: WINDOWS PERSISTENCE & SERVICES (Phase 3) */}
        {activeTab === 'windows' && (() => {
          const winObj = windowsData || executeData?.collected_data?.windows_metadata || executeData?.collected_data?.registry || investigationData?.collected_data?.windows_metadata;
          const autoruns = winObj?.autoruns || [];
          const services = winObj?.services || [];
          const osMeta = winObj?.os_metadata || {};
          const filteredServices = services.filter((s) =>
            !serviceSearch ||
            s.name?.toLowerCase().includes(serviceSearch.toLowerCase()) ||
            s.display_name?.toLowerCase().includes(serviceSearch.toLowerCase()) ||
            s.binpath?.toLowerCase().includes(serviceSearch.toLowerCase())
          );

          return (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
              <div style={{
                background: 'linear-gradient(135deg, rgba(245,158,11,0.08) 0%, rgba(99,102,241,0.08) 100%)',
                borderRadius: '10px',
                border: '1px solid rgba(245,158,11,0.25)',
                padding: '1.25rem 1.5rem',
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
                flexWrap: 'wrap',
                gap: '1rem',
              }}>
                <div>
                  <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>
                    Phase 3 — Real Windows Forensic Collection
                  </div>
                  <div style={{ fontSize: '1.15rem', fontWeight: 800, color: 'var(--text-primary)', marginTop: '0.2rem' }}>
                    Windows Persistence (Autoruns), Services &amp; OS Build Metadata
                  </div>
                  <div style={{ fontSize: '0.78rem', color: 'var(--text-secondary)', marginTop: '0.2rem' }}>
                    Method: <span className="font-mono" style={{ color: 'var(--accent-amber)' }}>{winObj?.provenance?.method || 'winreg_autorun_and_psutil_services'}</span>
                    {' '} • Host: <span className="font-mono">{winObj?.provenance?.host || '...'}</span>
                  </div>
                </div>
                <button
                  onClick={() => handleDirectCollect('windows_metadata')}
                  disabled={directLoading.windows_metadata}
                  style={{
                    background: directLoading.windows_metadata ? 'rgba(245,158,11,0.3)' : 'linear-gradient(135deg, #f59e0b, #6366f1)',
                    color: '#fff',
                    border: 'none',
                    borderRadius: '6px',
                    padding: '0.55rem 1.1rem',
                    fontSize: '0.82rem',
                    fontWeight: 700,
                    cursor: directLoading.windows_metadata ? 'not-allowed' : 'pointer',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '0.4rem',
                  }}
                >
                  {directLoading.windows_metadata ? 'Querying Registry...' : '⚡ Collect Live Metadata'}
                </button>
              </div>

              <div style={{ background: 'var(--bg-card)', borderRadius: '10px', border: '1px solid var(--border-color)', padding: '1.25rem' }}>
                <h3 style={{ fontSize: '0.95rem', fontWeight: 700, color: 'var(--text-primary)', marginBottom: '1rem' }}>
                  Windows OS Installation &amp; Build Telemetry
                </h3>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '1rem' }}>
                  <div style={{ padding: '0.75rem', borderRadius: '6px', background: 'rgba(255,255,255,0.02)', border: '1px solid var(--border-subtle)' }}>
                    <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>PRODUCT NAME</div>
                    <div style={{ fontSize: '0.95rem', fontWeight: 700, color: 'var(--accent-cyan)', marginTop: '0.2rem' }}>{osMeta.product_name || osMeta.platform || 'Windows'}</div>
                  </div>
                  <div style={{ padding: '0.75rem', borderRadius: '6px', background: 'rgba(255,255,255,0.02)', border: '1px solid var(--border-subtle)' }}>
                    <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>BUILD NUMBER</div>
                    <div style={{ fontSize: '0.95rem', fontWeight: 700, color: 'var(--text-primary)', marginTop: '0.2rem' }}>{osMeta.build_number || osMeta.release || '—'}</div>
                  </div>
                  <div style={{ padding: '0.75rem', borderRadius: '6px', background: 'rgba(255,255,255,0.02)', border: '1px solid var(--border-subtle)' }}>
                    <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>DISPLAY VERSION</div>
                    <div style={{ fontSize: '0.95rem', fontWeight: 700, color: 'var(--accent-indigo)', marginTop: '0.2rem' }}>{osMeta.display_version || '—'}</div>
                  </div>
                  <div style={{ padding: '0.75rem', borderRadius: '6px', background: 'rgba(255,255,255,0.02)', border: '1px solid var(--border-subtle)' }}>
                    <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>EDITION ID</div>
                    <div style={{ fontSize: '0.95rem', fontWeight: 700, color: 'var(--accent-emerald)', marginTop: '0.2rem' }}>{osMeta.edition_id || '—'}</div>
                  </div>
                  <div style={{ padding: '0.75rem', borderRadius: '6px', background: 'rgba(255,255,255,0.02)', border: '1px solid var(--border-subtle)' }}>
                    <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>INSTALL DATE (UTC)</div>
                    <div className="font-mono" style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', marginTop: '0.2rem' }}>{osMeta.install_date || '—'}</div>
                  </div>
                </div>
              </div>

              <div style={{ background: 'var(--bg-card)', borderRadius: '10px', border: '1px solid var(--border-color)', padding: '1.25rem' }}>
                <h3 style={{ fontSize: '0.95rem', fontWeight: 700, color: 'var(--text-primary)', marginBottom: '1rem' }}>
                  Registry Run &amp; Persistence Keys (Autoruns) ({autoruns.length})
                </h3>
                <div style={{ overflowX: 'auto' }}>
                  <table className="data-table" style={{ width: '100%', fontSize: '0.82rem' }}>
                    <thead>
                      <tr>
                        <th>Hive</th>
                        <th>Entry Name</th>
                        <th>Startup Command</th>
                        <th>Registry Key Path</th>
                      </tr>
                    </thead>
                    <tbody>
                      {autoruns.map((a, i) => (
                        <tr key={i}>
                          <td>
                            <span style={{ fontSize: '0.7rem', fontWeight: 700, padding: '0.15rem 0.4rem', borderRadius: '4px', background: 'rgba(245,158,11,0.12)', color: 'var(--accent-amber)' }}>
                              {a.hive}
                            </span>
                          </td>
                          <td style={{ fontWeight: 700, color: 'var(--accent-cyan)' }}>{a.entry_name}</td>
                          <td className="font-mono" style={{ fontSize: '0.72rem', maxWidth: '340px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={a.command}>{a.command}</td>
                          <td className="font-mono" style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>{a.path}</td>
                        </tr>
                      ))}
                      {autoruns.length === 0 && (
                        <tr><td colSpan={4} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: '1.5rem' }}>No autorun keys found or registry query pending.</td></tr>
                      )}
                    </tbody>
                  </table>
                </div>
              </div>

              {services.length > 0 && (
                <div style={{ background: 'var(--bg-card)', borderRadius: '10px', border: '1px solid var(--border-color)', padding: '1.25rem' }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem', flexWrap: 'wrap', gap: '0.75rem' }}>
                    <h3 style={{ fontSize: '0.95rem', fontWeight: 700, color: 'var(--text-primary)' }}>
                      Windows Services ({filteredServices.length})
                    </h3>
                    <input
                      type="text"
                      placeholder="Search services by name or binary path..."
                      value={serviceSearch}
                      onChange={(e) => setServiceSearch(e.target.value)}
                      style={{
                        background: 'rgba(0,0,0,0.3)',
                        border: '1px solid var(--border-color)',
                        borderRadius: '6px',
                        padding: '0.4rem 0.8rem',
                        fontSize: '0.8rem',
                        color: 'var(--text-primary)',
                        width: '280px',
                      }}
                    />
                  </div>
                  <div style={{ overflowX: 'auto' }}>
                    <table className="data-table" style={{ width: '100%', fontSize: '0.8rem' }}>
                      <thead>
                        <tr>
                          <th>Service Name</th>
                          <th>Display Name</th>
                          <th>Status</th>
                          <th>Start Type</th>
                          <th>Binary Path</th>
                          <th>Account</th>
                        </tr>
                      </thead>
                      <tbody>
                        {filteredServices.slice(0, 100).map((s, i) => (
                          <tr key={i}>
                            <td style={{ fontWeight: 700, color: 'var(--accent-cyan)' }}>{s.name}</td>
                            <td style={{ color: 'var(--text-secondary)' }}>{s.display_name}</td>
                            <td>
                              <span style={{
                                fontSize: '0.68rem',
                                padding: '0.15rem 0.4rem',
                                borderRadius: '4px',
                                background: s.status === 'running' ? 'rgba(16,185,129,0.12)' : 'rgba(255,255,255,0.05)',
                                color: s.status === 'running' ? 'var(--accent-emerald)' : 'var(--text-muted)',
                                fontWeight: 700,
                              }}>
                                {(s.status || 'unknown').toUpperCase()}
                              </span>
                            </td>
                            <td className="font-mono" style={{ fontSize: '0.75rem' }}>{s.start_type}</td>
                            <td className="font-mono" style={{ fontSize: '0.7rem', maxWidth: '280px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={s.binpath}>{s.binpath || '—'}</td>
                            <td className="font-mono" style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>{s.username || 'LocalSystem'}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}
            </div>
          );
        })()}

        {/* TAB 5: EVIDENCE VAULT & CHAIN OF CUSTODY (PHASE 6 & 9) */}
        {activeTab === 'evidence' && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '1.25rem' }}>
            {/* Vault Action Header */}
            <div style={{
              background: 'linear-gradient(180deg, rgba(15, 23, 42, 0.9) 0%, rgba(12, 17, 29, 0.9) 100%)',
              borderRadius: '12px',
              border: '1px solid var(--border-color)',
              padding: '1.25rem 1.5rem',
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              flexWrap: 'wrap',
              gap: '1rem',
            }}>
              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
                  <span style={{ fontSize: '1.4rem' }}>🛡️</span>
                  <h2 style={{ fontSize: '1.2rem', fontWeight: 700, color: 'var(--text-primary)', margin: 0 }}>
                    Evidence Vault &amp; Chain of Custody
                  </h2>
                  <span style={{
                    fontSize: '0.72rem',
                    fontWeight: 700,
                    padding: '0.2rem 0.55rem',
                    borderRadius: '4px',
                    background: vaultAudit?.vault_status === 'COMPROMISED' ? 'rgba(239, 68, 68, 0.15)' : 'rgba(16, 185, 129, 0.15)',
                    color: vaultAudit?.vault_status === 'COMPROMISED' ? 'var(--accent-rose)' : 'var(--accent-emerald)',
                    border: `1px solid ${vaultAudit?.vault_status === 'COMPROMISED' ? 'rgba(239, 68, 68, 0.3)' : 'rgba(16, 185, 129, 0.3)'}`,
                  }}>
                    {vaultAudit?.vault_status === 'COMPROMISED' ? '⚠ VAULT COMPROMISED' : '✓ VAULT INTACT'}
                  </span>
                </div>
                <div style={{ fontSize: '0.78rem', color: 'var(--text-secondary)', marginTop: '0.35rem' }}>
                  {vaultAudit?.total_artifacts || 0} sealed artifacts • {vaultAudit?.valid_count || 0} verified • {vaultAudit?.tampered_count || 0} tampered
                </div>
              </div>

              <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem', flexWrap: 'wrap' }}>
                <button
                  onClick={() => setShowLedger(!showLedger)}
                  style={{
                    background: showLedger ? 'rgba(56, 189, 248, 0.15)' : 'var(--bg-surface)',
                    border: '1px solid var(--border-color)',
                    color: showLedger ? 'var(--accent-cyan)' : 'var(--text-primary)',
                    borderRadius: '6px',
                    padding: '0.45rem 0.85rem',
                    fontSize: '0.8rem',
                    fontWeight: 600,
                    cursor: 'pointer',
                  }}
                >
                  {showLedger ? '📦 View Artifacts' : '📜 View Custody Ledger'}
                </button>

                <button
                  onClick={handleAuditEntireVault}
                  disabled={vaultLoading}
                  style={{
                    background: 'rgba(16, 185, 129, 0.12)',
                    border: '1px solid rgba(16, 185, 129, 0.3)',
                    color: 'var(--accent-emerald)',
                    borderRadius: '6px',
                    padding: '0.45rem 0.9rem',
                    fontSize: '0.8rem',
                    fontWeight: 600,
                    cursor: vaultLoading ? 'not-allowed' : 'pointer',
                  }}
                >
                  {vaultLoading ? 'Auditing Vault...' : '🛡️ Audit Entire Vault'}
                </button>

                <button
                  onClick={() => handleExportBundle()}
                  style={{
                    background: 'rgba(99, 102, 241, 0.12)',
                    border: '1px solid rgba(99, 102, 241, 0.3)',
                    color: 'var(--accent-indigo)',
                    borderRadius: '6px',
                    padding: '0.45rem 0.9rem',
                    fontSize: '0.8rem',
                    fontWeight: 600,
                    cursor: 'pointer',
                  }}
                >
                  ⬇ Export Bundle
                </button>
              </div>
            </div>

            {/* Tamper Warning Banner */}
            {vaultAudit?.vault_status === 'COMPROMISED' && (
              <div style={{
                background: 'rgba(239, 68, 68, 0.1)',
                border: '1px solid rgba(239, 68, 68, 0.4)',
                borderRadius: '8px',
                padding: '1.25rem',
                boxShadow: '0 0 25px rgba(239, 68, 68, 0.15)',
              }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem', color: 'var(--accent-rose)', fontWeight: 800 }}>
                  <span style={{ fontSize: '1.3rem' }}>🚨</span>
                  <span>CRITICAL INTEGRITY FAILURE: EVIDENCE TAMPERING DETECTED</span>
                </div>
                <p style={{ fontSize: '0.84rem', color: '#fca5a5', marginTop: '0.4rem', lineHeight: 1.5 }}>
                  The cryptographic hash of one or more sealed artifacts does not match the on-disk payload.
                  This indicates unauthorized modification or disk corruption. Chain of custody is compromised.
                </p>
                {vaultAudit?.tampered_artifacts?.map((ta, i) => (
                  <div key={i} style={{
                    marginTop: '0.75rem',
                    background: 'rgba(0, 0, 0, 0.3)',
                    padding: '0.75rem',
                    borderRadius: '6px',
                    border: '1px solid rgba(239, 68, 68, 0.25)',
                    fontSize: '0.78rem',
                    fontFamily: 'monospace',
                  }}>
                    <div><strong>Evidence ID:</strong> {ta.evidence_id}</div>
                    <div style={{ color: 'var(--accent-emerald)', marginTop: '0.2rem' }}>Stored Hash: {ta.stored_hash}</div>
                    <div style={{ color: 'var(--accent-rose)', marginTop: '0.1rem' }}>Computed Hash: {ta.recomputed_hash}</div>
                  </div>
                ))}
              </div>
            )}

            {/* Tamper simulation info */}
            {vaultTamperMsg && (
              <div style={{
                background: 'rgba(245, 158, 11, 0.1)',
                border: '1px solid rgba(245, 158, 11, 0.3)',
                borderRadius: '6px',
                padding: '0.75rem 1rem',
                fontSize: '0.8rem',
                color: 'var(--accent-amber)',
                display: 'flex',
                justifyContent: 'space-between',
                alignItems: 'center',
              }}>
                <span>🧪 {vaultTamperMsg}</span>
                <button
                  onClick={() => setVaultTamperMsg(null)}
                  style={{ background: 'none', border: 'none', color: 'var(--accent-amber)', cursor: 'pointer' }}
                >
                  ✕
                </button>
              </div>
            )}

            {/* View Mode: Custody Ledger vs Sealed Artifacts */}
            {showLedger ? (
              /* Chronological Chain of Custody Ledger */
              <div style={{ background: 'var(--bg-card)', borderRadius: '10px', border: '1px solid var(--border-color)', padding: '1.25rem' }}>
                <h3 style={{ fontSize: '0.95rem', fontWeight: 700, color: 'var(--text-primary)', marginBottom: '0.75rem' }}>
                  Immutable Chain-of-Custody Ledger ({vaultLedger.length} events)
                </h3>
                <div style={{ overflowX: 'auto' }}>
                  <table className="data-table" style={{ width: '100%', fontSize: '0.8rem' }}>
                    <thead>
                      <tr>
                        <th>Timestamp (UTC)</th>
                        <th>Action</th>
                        <th>Evidence ID</th>
                        <th>Investigator / Actor</th>
                        <th>Reason / Activity</th>
                        <th>Integrity Snapshot</th>
                      </tr>
                    </thead>
                    <tbody>
                      {vaultLedger.map((evt, idx) => (
                        <tr key={idx}>
                          <td className="font-mono" style={{ fontSize: '0.74rem' }}>{evt.when}</td>
                          <td>
                            <span style={{
                              fontSize: '0.68rem',
                              padding: '0.15rem 0.45rem',
                              borderRadius: '4px',
                              fontWeight: 700,
                              background: evt.action === 'TAMPER_DETECTED'
                                ? 'rgba(239, 68, 68, 0.15)'
                                : evt.action === 'ACQUIRED'
                                ? 'rgba(56, 189, 248, 0.15)'
                                : 'rgba(16, 185, 129, 0.15)',
                              color: evt.action === 'TAMPER_DETECTED'
                                ? 'var(--accent-rose)'
                                : evt.action === 'ACQUIRED'
                                ? 'var(--accent-cyan)'
                                : 'var(--accent-emerald)',
                            }}>
                              {evt.action}
                            </span>
                          </td>
                          <td className="font-mono" style={{ fontSize: '0.74rem', color: 'var(--accent-cyan)' }}>
                            {evt.evidence_id}
                          </td>
                          <td style={{ fontWeight: 600 }}>{evt.who}</td>
                          <td style={{ color: 'var(--text-secondary)' }}>{evt.why || evt.what}</td>
                          <td className="font-mono" style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>
                            {evt.sha256 ? `${evt.sha256.slice(0, 16)}…` : '—'}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            ) : (
              /* Sealed Artifacts Grid */
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(360px, 1fr))', gap: '1rem' }}>
                {(vaultAudit?.artifacts_summary || []).length === 0 && (
                  <div style={{ textAlign: 'center', padding: '3rem', color: 'var(--text-muted)', gridColumn: '1 / -1' }}>
                    No artifacts currently sealed in the Evidence Vault. Execute a forensic investigation or IR script to seal artifacts.
                  </div>
                )}
                {(vaultAudit?.artifacts_summary || []).map((art) => (
                  <div key={art.evidence_id} style={{
                    background: 'var(--bg-card)',
                    borderRadius: '8px',
                    border: `1px solid ${art.valid ? 'var(--border-color)' : 'rgba(239, 68, 68, 0.4)'}`,
                    padding: '1.25rem',
                  }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.5rem' }}>
                      <span style={{
                        fontSize: '0.7rem',
                        fontWeight: 700,
                        textTransform: 'uppercase',
                        padding: '0.15rem 0.45rem',
                        borderRadius: '4px',
                        background: 'rgba(56, 189, 248, 0.1)',
                        color: 'var(--accent-cyan)',
                      }}>
                        {art.source}
                      </span>
                      <span style={{
                        fontSize: '0.7rem',
                        fontWeight: 700,
                        padding: '0.15rem 0.45rem',
                        borderRadius: '4px',
                        background: art.valid ? 'rgba(16, 185, 129, 0.12)' : 'rgba(239, 68, 68, 0.15)',
                        color: art.valid ? 'var(--accent-emerald)' : 'var(--accent-rose)',
                      }}>
                        {art.valid ? '✓ INTACT' : '✕ TAMPERED'}
                      </span>
                    </div>

                    <div className="font-mono" style={{ fontSize: '0.82rem', fontWeight: 700, color: 'var(--text-primary)', wordBreak: 'break-all' }}>
                      {art.evidence_id}
                    </div>

                    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '0.4rem', marginTop: '0.6rem', fontSize: '0.74rem' }}>
                      <div>
                        <span style={{ color: 'var(--text-muted)' }}>Case ID: </span>
                        <span className="font-mono" style={{ color: 'var(--accent-cyan)' }}>{art.case_id || investigationData?.case_id || 'LAB-2026-001'}</span>
                      </div>
                      <div>
                        <span style={{ color: 'var(--text-muted)' }}>Collector: </span>
                        <span style={{ color: 'var(--text-primary)' }}>{art.collector || art.source || 'Safe Forensics Collector'}</span>
                      </div>
                      <div>
                        <span style={{ color: 'var(--text-muted)' }}>Timestamp: </span>
                        <span className="font-mono" style={{ color: 'var(--text-secondary)' }}>{art.timestamp || art.sealed_at || 'Recorded in Vault'}</span>
                      </div>
                      <div>
                        <span style={{ color: 'var(--text-muted)' }}>Chain of Custody: </span>
                        <span style={{ color: 'var(--accent-emerald)', fontWeight: 600 }}>
                          {vaultLedger.filter((l) => l.evidence_id === art.evidence_id).length || 1} logged event(s)
                        </span>
                      </div>
                    </div>

                    {/* SHA-256 Hash with Copy */}
                    <div style={{ marginTop: '0.65rem', background: '#04070d', padding: '0.45rem 0.65rem', borderRadius: '6px', border: '1px solid var(--border-subtle)' }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.2rem' }}>
                        <span style={{ fontSize: '0.66rem', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 700 }}>
                          SHA-256 Digest
                        </span>
                        <button
                          onClick={() => handleCopy(art.stored_hash || art.sha256, `art-${art.evidence_id}`)}
                          style={{
                            background: 'transparent',
                            border: 'none',
                            color: copiedHash === `art-${art.evidence_id}` ? 'var(--accent-emerald)' : 'var(--accent-cyan)',
                            fontSize: '0.7rem',
                            cursor: 'pointer',
                          }}
                        >
                          {copiedHash === `art-${art.evidence_id}` ? '✓ Copied' : 'Copy Hash'}
                        </button>
                      </div>
                      <div className="font-mono" style={{ fontSize: '0.72rem', color: 'var(--accent-cyan)', wordBreak: 'break-all' }}>
                        {art.stored_hash || art.sha256 || 'SHA-256 Computed & Sealed'}
                      </div>
                    </div>

                    <div style={{ display: 'flex', gap: '0.5rem', marginTop: '1rem' }}>
                      <button
                        onClick={() => handleVerifyArtifact(art.evidence_id)}
                        style={{
                          flex: 1,
                          background: 'rgba(16, 185, 129, 0.1)',
                          border: '1px solid rgba(16, 185, 129, 0.25)',
                          color: 'var(--accent-emerald)',
                          borderRadius: '4px',
                          padding: '0.35rem 0.6rem',
                          fontSize: '0.75rem',
                          fontWeight: 600,
                          cursor: 'pointer',
                        }}
                      >
                        ✓ Verify
                      </button>
                      <button
                        onClick={() => handleSimulateTamper(art.evidence_id)}
                        style={{
                          background: 'rgba(239, 68, 68, 0.08)',
                          border: '1px solid rgba(239, 68, 68, 0.2)',
                          color: 'var(--accent-rose)',
                          borderRadius: '4px',
                          padding: '0.35rem 0.6rem',
                          fontSize: '0.75rem',
                          fontWeight: 600,
                          cursor: 'pointer',
                        }}
                        title="Simulate unauthorized mutation on disk"
                      >
                        🧪 Tamper Test
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* TAB: FORENSIC REPORT ENGINE */}
        {activeTab === 'reports' && (
          <ReportSection
            investigationData={investigationData}
            reportResult={reportResult}
            reportLoading={reportLoading}
            reportFormat={reportFormat}
            setReportFormat={setReportFormat}
            reportExaminer={reportExaminer}
            setReportExaminer={setReportExaminer}
            onGenerateReport={(fmt) => handleGenerateReport(fmt)}
            onDownloadReport={(fmt) => handleDownloadReport(fmt)}
          />
        )}

        {/* TAB 6: SCRIPT EDITOR & POLICY AUDIT */}
        {activeTab === 'script' && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
            {/* Top row: editor + execution plan */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(450px, 1fr))', gap: '1.5rem' }}>
              {/* Script Editor Panel */}
              <div style={{ background: 'var(--bg-card)', borderRadius: '10px', border: '1px solid var(--border-color)', padding: '1.25rem', display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '0.5rem' }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
                    <h3 style={{ fontSize: '0.95rem', fontWeight: 800, color: 'var(--text-primary)', margin: 0 }}>
                      JOCKY Forensic DSL Script
                    </h3>
                    {/* Execution status indicator badge */}
                    <span
                      style={{
                        fontSize: '0.7rem',
                        fontWeight: 700,
                        padding: '0.15rem 0.5rem',
                        borderRadius: '4px',
                        background: loading
                          ? 'rgba(245, 158, 11, 0.15)'
                          : compiling
                          ? 'rgba(99, 102, 241, 0.15)'
                          : apiError || (compilerResult && !compilerResult.success)
                          ? 'rgba(239, 68, 68, 0.15)'
                          : investigationData
                          ? 'rgba(16, 185, 129, 0.15)'
                          : 'rgba(56, 189, 248, 0.15)',
                        color: loading
                          ? 'var(--accent-amber)'
                          : compiling
                          ? 'var(--accent-indigo)'
                          : apiError || (compilerResult && !compilerResult.success)
                          ? 'var(--accent-rose)'
                          : investigationData
                          ? 'var(--accent-emerald)'
                          : 'var(--accent-cyan)',
                        border: `1px solid ${
                          loading
                            ? 'rgba(245, 158, 11, 0.3)'
                            : compiling
                            ? 'rgba(99, 102, 241, 0.3)'
                            : apiError || (compilerResult && !compilerResult.success)
                            ? 'rgba(239, 68, 68, 0.3)'
                            : investigationData
                            ? 'rgba(16, 185, 129, 0.3)'
                            : 'rgba(56, 189, 248, 0.3)'
                        }`,
                      }}
                    >
                      {loading
                        ? '● EXECUTING...'
                        : compiling
                        ? '● COMPILING...'
                        : apiError || (compilerResult && !compilerResult.success)
                        ? '● ERROR'
                        : investigationData
                        ? '● EXECUTION SUCCESS'
                        : '● READY'}
                    </span>
                  </div>
                  <span className="font-mono" style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>
                    UTF-8 • Policy Signed
                  </span>
                </div>

                {/* Editor Action Toolbar */}
                <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center', flexWrap: 'wrap', background: 'rgba(0, 0, 0, 0.25)', padding: '0.4rem 0.6rem', borderRadius: '6px', border: '1px solid var(--border-subtle)' }}>
                  <button
                    onClick={handleLoadExample}
                    title="Load incident example script (INCIDENT-2026-ALPHA)"
                    style={{
                      background: 'rgba(56, 189, 248, 0.12)',
                      border: '1px solid rgba(56, 189, 248, 0.25)',
                      color: 'var(--accent-cyan)',
                      borderRadius: '4px',
                      padding: '0.3rem 0.65rem',
                      fontSize: '0.76rem',
                      fontWeight: 700,
                      cursor: 'pointer',
                    }}
                  >
                    📂 Load Example
                  </button>

                  <button
                    onClick={handleClearScript}
                    title="Clear current script and reset to template"
                    style={{
                      background: 'rgba(255, 255, 255, 0.04)',
                      border: '1px solid var(--border-subtle)',
                      color: 'var(--text-secondary)',
                      borderRadius: '4px',
                      padding: '0.3rem 0.65rem',
                      fontSize: '0.76rem',
                      fontWeight: 600,
                      cursor: 'pointer',
                    }}
                  >
                    🗑 Clear Script
                  </button>

                  <button
                    onClick={() => setIsCommandModalOpen(true)}
                    title="Open Command Search palette"
                    style={{
                      background: 'rgba(99, 102, 241, 0.15)',
                      border: '1px solid rgba(99, 102, 241, 0.3)',
                      color: 'var(--accent-indigo)',
                      borderRadius: '4px',
                      padding: '0.3rem 0.65rem',
                      fontSize: '0.76rem',
                      fontWeight: 700,
                      cursor: 'pointer',
                      display: 'flex',
                      alignItems: 'center',
                      gap: '0.3rem',
                    }}
                  >
                    <span>🔎</span>
                    <span>Command Search</span>
                  </button>

                  {/* Insert Command Quick Dropdown */}
                  <div style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                    <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)', fontWeight: 600 }}>Insert:</span>
                    <select
                      value=""
                      onChange={(e) => {
                        const val = e.target.value;
                        if (val) {
                          const cmd = SUPPORTED_COMMANDS.find((c) => c.name === val);
                          if (cmd) handleInsertCommand(cmd.syntax);
                        }
                      }}
                      style={{
                        background: '#04070d',
                        border: '1px solid var(--border-color)',
                        borderRadius: '4px',
                        padding: '0.28rem 0.5rem',
                        color: 'var(--text-primary)',
                        fontSize: '0.74rem',
                        cursor: 'pointer',
                      }}
                    >
                      <option value="">-- Insert Command --</option>
                      {SUPPORTED_COMMANDS.map((cmd) => (
                        <option key={cmd.id} value={cmd.name}>
                          {cmd.name} ({cmd.category})
                        </option>
                      ))}
                    </select>
                  </div>
                </div>

                {/* Toast Notification */}
                {scriptToast && (
                  <div style={{
                    background: 'rgba(16, 185, 129, 0.12)',
                    border: '1px solid var(--accent-emerald)',
                    borderRadius: '4px',
                    padding: '0.35rem 0.75rem',
                    color: 'var(--accent-emerald)',
                    fontSize: '0.75rem',
                    fontWeight: 600,
                    display: 'flex',
                    alignItems: 'center',
                    gap: '0.4rem',
                  }}>
                    <span>✓</span> {scriptToast}
                  </div>
                )}

                <textarea
                  value={scriptText}
                  onChange={(e) => setScriptText(e.target.value)}
                  rows={14}
                  style={{
                    width: '100%',
                    background: '#04070d',
                    border: '1px solid var(--border-color)',
                    borderRadius: '6px',
                    padding: '1rem',
                    fontFamily: 'JetBrains Mono, monospace',
                    fontSize: '0.85rem',
                    lineHeight: 1.6,
                    color: '#38bdf8',
                    resize: 'vertical',
                  }}
                />

                {/* Detected Commands Visual Scope Indicator */}
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: '0.35rem', alignItems: 'center' }}>
                  <span style={{ fontSize: '0.68rem', color: 'var(--text-muted)', fontWeight: 700, textTransform: 'uppercase' }}>
                    Active Scope:
                  </span>
                  {SUPPORTED_COMMANDS.filter((cmd) => scriptText.toUpperCase().includes(cmd.name)).map((cmd) => (
                    <span
                      key={cmd.id}
                      style={{
                        fontSize: '0.66rem',
                        padding: '0.1rem 0.4rem',
                        borderRadius: '4px',
                        background: 'rgba(56, 189, 248, 0.08)',
                        color: 'var(--accent-cyan)',
                        border: '1px solid rgba(56, 189, 248, 0.2)',
                        fontFamily: 'JetBrains Mono, monospace',
                      }}
                    >
                      {cmd.name}
                    </span>
                  ))}
                </div>

                {/* Error Display Card */}
                {apiError && (
                  <div style={{
                    background: 'rgba(239, 68, 68, 0.1)',
                    border: '1px solid rgba(239, 68, 68, 0.35)',
                    borderRadius: '6px',
                    padding: '0.75rem 1rem',
                  }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', color: 'var(--accent-rose)', fontWeight: 800, fontSize: '0.82rem' }}>
                      <span>⚠️</span>
                      <span>{apiError.error_type || 'Execution Error'}</span>
                      {apiError.line && (
                        <span className="font-mono" style={{ fontSize: '0.72rem', background: 'rgba(0,0,0,0.3)', padding: '0.1rem 0.35rem', borderRadius: '3px' }}>
                          Line {apiError.line}{apiError.column ? `:${apiError.column}` : ''}
                        </span>
                      )}
                    </div>
                    <div style={{ color: '#fca5a5', fontSize: '0.78rem', marginTop: '0.3rem', lineHeight: 1.45 }}>
                      {apiError.message}
                    </div>
                  </div>
                )}

                <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '0.75rem', marginTop: '0.4rem' }}>
                  <button
                    id="btn-compile-jocky"
                    onClick={handleCompile}
                    disabled={compiling}
                    style={{
                      background: compiling ? 'rgba(99,102,241,0.3)' : 'linear-gradient(135deg, #6366f1, #8b5cf6)',
                      color: '#fff',
                      border: 'none',
                      borderRadius: '6px',
                      padding: '0.5rem 1.1rem',
                      fontSize: '0.85rem',
                      fontWeight: 700,
                      cursor: compiling ? 'not-allowed' : 'pointer',
                    }}
                  >
                    {compiling ? 'Compiling...' : '⚙ Compile / Validate'}
                  </button>
                  <button
                    id="btn-execute-script"
                    onClick={() => handleExecuteScript(scriptText)}
                    disabled={loading || executeLoading}
                    style={{
                      background: (loading || executeLoading) ? 'rgba(14, 165, 233, 0.4)' : 'linear-gradient(135deg, #0ea5e9, #6366f1)',
                      color: '#fff',
                      border: 'none',
                      borderRadius: '6px',
                      padding: '0.5rem 1.25rem',
                      fontSize: '0.85rem',
                      fontWeight: 700,
                      cursor: (loading || executeLoading) ? 'not-allowed' : 'pointer',
                      boxShadow: '0 4px 15px rgba(14, 165, 233, 0.3)',
                    }}
                  >
                    {(loading || executeLoading) ? 'Executing...' : '▶ Analyze and Execute Script'}
                  </button>
                </div>
              </div>

              {/* Real-time Collector Pipeline Execution UI */}
              {renderCollectorProgressUI()}


              {/* Execution Plan Audit */}
              <div style={{ background: 'var(--bg-card)', borderRadius: '10px', border: '1px solid var(--border-color)', padding: '1.25rem' }}>
                <h3 style={{ fontSize: '0.95rem', fontWeight: 700, color: 'var(--text-primary)', marginBottom: '0.75rem' }}>
                  Execution Plan &amp; Policy Ledger
                </h3>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem', maxHeight: '380px', overflowY: 'auto' }}>
                  {investigationData?.execution_plan?.tasks?.map((t, idx) => (
                    <div key={idx} style={{
                      padding: '0.6rem 0.85rem',
                      borderRadius: '6px',
                      background: 'rgba(255,255,255,0.02)',
                      border: '1px solid var(--border-subtle)',
                      display: 'flex',
                      justifyContent: 'space-between',
                      alignItems: 'center',
                    }}>
                      <div>
                        <span className="font-mono" style={{ fontSize: '0.8rem', color: 'var(--accent-cyan)', fontWeight: 600 }}>
                          Step {t.step}: {t.action} {t.category || t.target || ''}
                        </span>
                        <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>
                          {t.description || 'Forensic step'}
                        </div>
                      </div>
                      <span style={{ fontSize: '0.68rem', padding: '0.15rem 0.4rem', borderRadius: '4px', background: 'rgba(16, 185, 129, 0.1)', color: 'var(--accent-emerald)', fontWeight: 600 }}>
                        APPROVED (READ-ONLY)
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            {/* ── Phase 1 Compiler Output Panel ── */}
            {compilerResult && (
              <div id="jocky-compiler-output" style={{
                background: 'var(--bg-card)',
                borderRadius: '10px',
                border: `1px solid ${compilerResult.success ? 'rgba(99,102,241,0.4)' : 'rgba(244,63,94,0.4)'}`,
                padding: '1.5rem',
                boxShadow: compilerResult.success
                  ? '0 0 20px rgba(99,102,241,0.1)'
                  : '0 0 20px rgba(244,63,94,0.1)',
              }}>
                {/* Compiler header */}
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '1.25rem' }}>
                  <div style={{
                    fontFamily: 'JetBrains Mono, monospace',
                    fontSize: '0.72rem',
                    fontWeight: 700,
                    color: 'var(--text-muted)',
                    textTransform: 'uppercase',
                    letterSpacing: '0.1em',
                  }}>
                    JOCKY COMPILER
                  </div>
                  <div style={{
                    display: 'inline-flex',
                    alignItems: 'center',
                    gap: '0.4rem',
                    padding: '0.2rem 0.65rem',
                    borderRadius: '4px',
                    fontWeight: 700,
                    fontSize: '0.78rem',
                    background: compilerResult.success ? 'rgba(16,185,129,0.12)' : 'rgba(244,63,94,0.12)',
                    color: compilerResult.success ? 'var(--accent-emerald)' : 'var(--accent-rose)',
                    border: `1px solid ${compilerResult.success ? 'rgba(16,185,129,0.3)' : 'rgba(244,63,94,0.3)'}`,
                  }}>
                    {compilerResult.success ? '✓ SOURCE VALID' : '✕ COMPILATION ERROR'}
                  </div>
                </div>

                {/* ── Success view ── */}
                {compilerResult.success && (
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))', gap: '1.25rem' }}>

                    {/* Pipeline waterfall */}
                    <div>
                      <div style={{ fontSize: '0.75rem', color: 'var(--accent-indigo)', fontWeight: 700, marginBottom: '0.6rem', letterSpacing: '0.05em' }}>
                        COMPILATION PIPELINE
                      </div>
                      {['JOCKY SOURCE', 'LEXER', 'PARSER', 'AST', 'VALIDATION', 'JOCKY IR'].map((stage, i, arr) => (
                        <div key={stage}>
                          <div style={{
                            fontFamily: 'JetBrains Mono, monospace',
                            fontSize: '0.82rem',
                            fontWeight: 700,
                            color: stage === 'JOCKY IR' ? 'var(--accent-indigo)' : 'var(--accent-emerald)',
                            padding: '0.3rem 0.75rem',
                            background: stage === 'JOCKY IR' ? 'rgba(99,102,241,0.08)' : 'rgba(16,185,129,0.05)',
                            borderRadius: '4px',
                            border: stage === 'JOCKY IR' ? '1px solid rgba(99,102,241,0.25)' : '1px solid rgba(16,185,129,0.15)',
                          }}>
                            ✓ {stage}
                          </div>
                          {i < arr.length - 1 && (
                            <div style={{ fontFamily: 'monospace', color: 'var(--text-muted)', fontSize: '0.85rem', paddingLeft: '0.85rem', lineHeight: 1 }}>↓</div>
                          )}
                        </div>
                      ))}
                      <div style={{ marginTop: '0.75rem', fontSize: '0.78rem', color: 'var(--text-secondary)' }}>
                        Compilation successful — {compilerResult.tokens_count} tokens processed
                      </div>
                    </div>

                    {/* AST tree */}
                    <div>
                      <div style={{ fontSize: '0.75rem', color: 'var(--accent-cyan)', fontWeight: 700, marginBottom: '0.6rem', letterSpacing: '0.05em' }}>
                        AST ▼
                      </div>
                      <div style={{
                        background: '#04070d',
                        borderRadius: '6px',
                        border: '1px solid var(--border-subtle)',
                        padding: '0.85rem 1rem',
                        fontFamily: 'JetBrains Mono, monospace',
                        fontSize: '0.78rem',
                        lineHeight: 1.7,
                        color: 'var(--text-secondary)',
                      }}>
                        <div style={{ color: 'var(--accent-cyan)', fontWeight: 700 }}>Program</div>
                        {compilerResult.ast?.statements?.map((stmt, i, arr) => {
                          const isLast = i === arr.length - 1;
                          const prefix = isLast ? ' └── ' : ' ├── ';
                          const label = stmt.type === 'CaseNode' ? `Case: "${stmt.case_id}"`
                            : stmt.type === 'TargetNode' ? `Target: "${stmt.target}"`
                            : stmt.type === 'CollectNode'
                              ? `Collect ${stmt.category}${stmt.filters?.length ? ` (WHERE ${stmt.filters.map(f => `${f.field}${f.operator}${f.value}`).join(', ')})` : ''}`
                            : stmt.type === 'AnalyzeNode' ? `Analyze${stmt.analysis_target ? ` ${stmt.analysis_target}` : ''}`
                            : stmt.type === 'VerifyNode' ? `Verify ${stmt.verify_target}`
                            : stmt.type === 'ReportNode' ? `Report${stmt.format ? ` FORMAT ${stmt.format}` : ''}`
                            : stmt.type;
                          return (
                            <div key={i} style={{ color: stmt.type === 'CaseNode' || stmt.type === 'TargetNode' ? 'var(--accent-amber)' : 'var(--text-primary)' }}>
                              {prefix}{label}
                            </div>
                          );
                        })}
                      </div>
                    </div>

                    {/* JOCKY IR */}
                    <div>
                      <div style={{ fontSize: '0.75rem', color: 'var(--accent-indigo)', fontWeight: 700, marginBottom: '0.6rem', letterSpacing: '0.05em' }}>
                        JOCKY IR v{compilerResult.ir?.version} ▼
                      </div>
                      <div style={{ fontSize: '0.78rem', color: 'var(--text-secondary)', marginBottom: '0.5rem' }}>
                        Case: <span style={{ color: 'var(--accent-amber)', fontWeight: 600 }}>{compilerResult.ir?.case_id}</span>
                        {' '} · Target: <span style={{ color: 'var(--accent-amber)', fontWeight: 600 }}>{compilerResult.ir?.target}</span>
                        {' '} · <span style={{ color: 'var(--accent-indigo)' }}>{compilerResult.summary?.operation_count} operations</span>
                      </div>
                      <div style={{ display: 'flex', flexDirection: 'column', gap: '0.35rem' }}>
                        {compilerResult.ir?.operations?.map((op, i) => (
                          <div key={i} style={{
                            background: 'rgba(99,102,241,0.06)',
                            border: '1px solid rgba(99,102,241,0.2)',
                            borderRadius: '4px',
                            padding: '0.4rem 0.75rem',
                            fontFamily: 'JetBrains Mono, monospace',
                            fontSize: '0.78rem',
                          }}>
                            <span style={{ color: 'var(--accent-indigo)', fontWeight: 700 }}>{op.type}</span>
                            {op.target && <span style={{ color: 'var(--accent-cyan)' }}> {op.target}</span>}
                            {op.format && <span style={{ color: 'var(--accent-cyan)' }}> FORMAT {op.format}</span>}
                            {op.filters?.map((f, fi) => (
                              <div key={fi} style={{ paddingLeft: '1rem', color: 'var(--text-muted)', fontSize: '0.74rem' }}>
                                WHERE {f.field} {f.operator} {f.value}
                              </div>
                            ))}
                          </div>
                        ))}
                      </div>
                    </div>
                  </div>
                )}

                {/* ── Error view ── */}
                {!compilerResult.success && (
                  <div style={{
                    background: 'rgba(244,63,94,0.06)',
                    border: '1px solid rgba(244,63,94,0.25)',
                    borderRadius: '6px',
                    padding: '1rem 1.25rem',
                    fontFamily: 'JetBrains Mono, monospace',
                  }}>
                    <div style={{ fontSize: '0.8rem', color: 'var(--accent-rose)', fontWeight: 700, marginBottom: '0.4rem' }}>
                      {compilerResult.error_type || 'JockyError'}
                      {compilerResult.line != null && (
                        <span style={{ fontWeight: 400, color: '#fda4af', marginLeft: '0.5rem' }}>
                          — Line {compilerResult.line}{compilerResult.column != null ? `, Column ${compilerResult.column}` : ''}
                        </span>
                      )}
                    </div>
                    <div style={{ fontSize: '0.82rem', color: '#fda4af', whiteSpace: 'pre-wrap', lineHeight: 1.6 }}>
                      {compilerResult.message}
                    </div>
                  </div>
                )}
              </div>
            )}
          </div>
        )}

        {/* TAB 7: EXECUTION ENGINE (Phase 2) */}
        {activeTab === 'execute' && (
          <div>
            {/* Action bar */}
            <div style={{
              background: 'linear-gradient(135deg, rgba(99,102,241,0.08) 0%, rgba(14,165,233,0.08) 100%)',
              border: '1px solid rgba(99,102,241,0.25)',
              borderRadius: '10px',
              padding: '1.25rem 1.5rem',
              marginBottom: '1.5rem',
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              flexWrap: 'wrap',
              gap: '1rem',
            }}>
              <div>
                <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.05em' }}>Phase 2 — JOCKY IR Execution Engine</div>
                <div style={{ fontSize: '1.1rem', fontWeight: 800, color: 'var(--text-primary)', marginTop: '0.2rem' }}>
                  IR → Policy → Collectors → Receipt
                </div>
                <div style={{ fontSize: '0.78rem', color: 'var(--text-secondary)', marginTop: '0.15rem' }}>
                  Runs the current script through <span style={{ color: 'var(--accent-indigo)', fontWeight: 600 }}>POST /api/jocky/execute</span> — IR-native pipeline, distinct from legacy /investigate
                </div>
              </div>
              <button
                id="btn-run-ir-execute"
                onClick={() => handleRunExecute()}
                disabled={executeLoading}
                style={{
                  background: executeLoading
                    ? 'rgba(99,102,241,0.3)'
                    : 'linear-gradient(135deg, #6366f1, #0ea5e9)',
                  color: '#fff',
                  border: 'none',
                  borderRadius: '7px',
                  padding: '0.6rem 1.4rem',
                  fontSize: '0.88rem',
                  fontWeight: 700,
                  cursor: executeLoading ? 'not-allowed' : 'pointer',
                  boxShadow: '0 4px 18px rgba(99,102,241,0.35)',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '0.5rem',
                  whiteSpace: 'nowrap',
                }}
              >
                {executeLoading ? '⚡ Executing...' : '⚡ Run IR Execute'}
              </button>
            </div>

            {/* Real-time Collector Pipeline Execution UI */}
            {renderCollectorProgressUI()}


            {/* Execute Error Banner */}
            {executeError && (
              <div style={{
                background: 'rgba(244,63,94,0.08)',
                border: '1px solid rgba(244,63,94,0.3)',
                borderRadius: '8px',
                padding: '1rem 1.25rem',
                marginBottom: '1.5rem',
              }}>
                <div style={{ fontWeight: 700, color: 'var(--accent-rose)', fontSize: '0.9rem' }}>
                  {executeError.error_type || 'ExecuteError'}
                  {executeError.line ? ` (Line ${executeError.line}, Col ${executeError.column})` : ''}
                </div>
                <div style={{ fontSize: '0.84rem', color: '#fda4af', marginTop: '0.3rem' }}>
                  {executeError.message}
                </div>
                {/* Policy denial detail */}
                {executeError.policy_result && (
                  <div style={{ marginTop: '0.75rem', fontSize: '0.8rem', color: 'var(--text-secondary)' }}>
                    <strong style={{ color: 'var(--accent-amber)' }}>Policy Denial Trail:</strong>
                    {executeError.policy_result.denied_operations?.map((op, i) => (
                      <div key={i} style={{
                        marginTop: '0.35rem',
                        paddingLeft: '0.75rem',
                        borderLeft: '2px solid rgba(244,63,94,0.4)',
                      }}>
                        <span style={{ color: 'var(--accent-rose)', fontWeight: 600 }}>[{op.index}] {op.type} {op.target || ''}</span>
                        {' — '}{op.reason}
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )}

            {executeData && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>

                {/* Summary KPIs */}
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: '1rem' }}>
                  {[
                    {
                      label: 'Pipeline Status',
                      value: executeData.success ? 'SUCCESS' : 'FAILED',
                      color: executeData.success ? 'var(--accent-emerald)' : 'var(--accent-rose)',
                    },
                    {
                      label: 'Operations Executed',
                      value: executeData.receipts?.length ?? 0,
                      color: 'var(--accent-cyan)',
                    },
                    {
                      label: 'Evidence Artifacts',
                      value: Object.keys(executeData.evidence_ids || {}).length,
                      color: 'var(--accent-indigo)',
                    },
                    {
                      label: 'Integrity',
                      value: executeData.integrity_status?.verified ? 'VERIFIED' : 'PENDING',
                      color: executeData.integrity_status?.verified ? 'var(--accent-emerald)' : 'var(--accent-amber)',
                    },
                  ].map((kpi) => (
                    <div key={kpi.label} style={{
                      background: 'var(--bg-card)',
                      borderRadius: '9px',
                      border: '1px solid var(--border-color)',
                      padding: '1rem',
                    }}>
                      <div style={{ fontSize: '0.7rem', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600 }}>{kpi.label}</div>
                      <div style={{ fontSize: '1.4rem', fontWeight: 800, color: kpi.color, marginTop: '0.25rem' }}>{kpi.value}</div>
                    </div>
                  ))}
                </div>

                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(420px, 1fr))', gap: '1.5rem' }}>

                  {/* Policy Decision Panel */}
                  <div style={{
                    background: 'var(--bg-card)',
                    borderRadius: '10px',
                    border: '1px solid var(--border-color)',
                    padding: '1.5rem',
                  }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem' }}>
                      <h3 style={{ fontSize: '0.95rem', fontWeight: 700, color: 'var(--text-primary)' }}>Policy Decision</h3>
                      <span style={{
                        fontSize: '0.72rem',
                        padding: '0.2rem 0.55rem',
                        borderRadius: '5px',
                        fontWeight: 700,
                        background: executeData.policy_result?.allowed ? 'rgba(16,185,129,0.1)' : 'rgba(244,63,94,0.1)',
                        color: executeData.policy_result?.allowed ? 'var(--accent-emerald)' : 'var(--accent-rose)',
                        border: `1px solid ${executeData.policy_result?.allowed ? 'rgba(16,185,129,0.3)' : 'rgba(244,63,94,0.3)'}`,
                      }}>
                        {executeData.policy_result?.allowed ? '✓ ALL AUTHORIZED' : '✗ POLICY DENIED'}
                      </span>
                    </div>
                    <div style={{ fontSize: '0.78rem', color: 'var(--text-secondary)', marginBottom: '1rem', lineHeight: 1.5 }}>
                      {executeData.policy_result?.reason}
                    </div>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                      {[
                        ...(executeData.policy_result?.approved_operations || []).map(op => ({ ...op, _allowed: true })),
                        ...(executeData.policy_result?.denied_operations || []).map(op => ({ ...op, _allowed: false })),
                      ].sort((a, b) => a.index - b.index).map((op, i) => (
                        <div key={i} style={{
                          display: 'flex',
                          alignItems: 'center',
                          gap: '0.75rem',
                          padding: '0.55rem 0.85rem',
                          borderRadius: '6px',
                          background: op._allowed ? 'rgba(16,185,129,0.04)' : 'rgba(244,63,94,0.04)',
                          border: `1px solid ${op._allowed ? 'rgba(16,185,129,0.2)' : 'rgba(244,63,94,0.2)'}`,
                        }}>
                          <span style={{
                            fontSize: '0.68rem',
                            fontWeight: 700,
                            padding: '0.15rem 0.4rem',
                            borderRadius: '4px',
                            background: op._allowed ? 'rgba(16,185,129,0.15)' : 'rgba(244,63,94,0.15)',
                            color: op._allowed ? 'var(--accent-emerald)' : 'var(--accent-rose)',
                            letterSpacing: '0.04em',
                            whiteSpace: 'nowrap',
                          }}>
                            {op._allowed ? 'ALLOWED' : 'DENIED'}
                          </span>
                          <div style={{ flex: 1, minWidth: 0 }}>
                            <div style={{ fontSize: '0.82rem', fontWeight: 600, color: 'var(--text-primary)', fontFamily: 'JetBrains Mono, monospace' }}>
                              {op.type}{op.target ? ` ${op.target}` : ''}
                            </div>
                            <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', marginTop: '0.1rem' }}>
                              {op.capability}
                            </div>
                          </div>
                          <span style={{
                            fontSize: '0.68rem',
                            color: op._allowed ? 'var(--accent-emerald)' : 'var(--text-muted)',
                            fontWeight: 600,
                          }}>
                            #{op.index}
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>

                  {/* Execution Receipt Panel */}
                  <div style={{
                    background: 'var(--bg-card)',
                    borderRadius: '10px',
                    border: '1px solid var(--border-color)',
                    padding: '1.5rem',
                  }}>
                    <h3 style={{ fontSize: '0.95rem', fontWeight: 700, color: 'var(--text-primary)', marginBottom: '1rem' }}>
                      Execution Receipts
                      <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)', fontWeight: 400, marginLeft: '0.5rem' }}>
                        — {executeData.receipts?.length} operations
                      </span>
                    </h3>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.6rem' }}>
                      {executeData.receipts?.map((r, i) => {
                        const statusColor = r.status === 'COMPLETED'
                          ? 'var(--accent-emerald)'
                          : r.status === 'ERROR'
                            ? 'var(--accent-rose)'
                            : 'var(--text-muted)';
                        return (
                          <div key={i} style={{
                            padding: '0.75rem 1rem',
                            borderRadius: '7px',
                            background: 'rgba(255,255,255,0.02)',
                            border: '1px solid var(--border-subtle)',
                          }}>
                            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.4rem' }}>
                              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                                <span style={{
                                  fontSize: '0.68rem',
                                  fontWeight: 700,
                                  padding: '0.15rem 0.4rem',
                                  borderRadius: '4px',
                                  background: r.status === 'COMPLETED' ? 'rgba(16,185,129,0.12)' : 'rgba(244,63,94,0.12)',
                                  color: statusColor,
                                  letterSpacing: '0.04em',
                                }}>{r.status}</span>
                                <span style={{ fontSize: '0.82rem', fontWeight: 600, color: 'var(--text-primary)', fontFamily: 'JetBrains Mono, monospace' }}>
                                  {r.capability}
                                </span>
                              </div>
                              <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>#{r.index}</span>
                            </div>
                            {r.evidence_id && (
                              <div style={{ fontSize: '0.72rem', color: 'var(--text-secondary)', marginTop: '0.2rem' }}>
                                Evidence: <span style={{ fontFamily: 'JetBrains Mono, monospace', color: 'var(--accent-cyan)' }}>{r.evidence_id}</span>
                              </div>
                            )}
                            {r.sha256 && (
                              <div style={{ fontSize: '0.68rem', color: 'var(--text-muted)', fontFamily: 'JetBrains Mono, monospace', marginTop: '0.15rem', wordBreak: 'break-all' }}>
                                SHA-256: {r.sha256.slice(0, 24)}…
                              </div>
                            )}
                            {r.record_count != null && (
                              <div style={{ fontSize: '0.72rem', color: 'var(--text-secondary)', marginTop: '0.15rem' }}>
                                Records: <span style={{ fontWeight: 600, color: 'var(--accent-cyan)' }}>{r.record_count}</span>
                                {r.filter_matched_count != null && r.filter_matched_count !== r.record_count && (
                                  <span style={{ color: 'var(--text-muted)' }}> (filtered)</span>
                                )}
                              </div>
                            )}
                            {r.started_at && (
                              <div style={{ fontSize: '0.67rem', color: 'var(--text-muted)', marginTop: '0.15rem', fontFamily: 'JetBrains Mono, monospace' }}>
                                {r.started_at.slice(0, 19).replace('T', ' ')} → {r.completed_at?.slice(0, 19).replace('T', ' ')}
                              </div>
                            )}
                          </div>
                        );
                      })}
                    </div>
                  </div>
                </div>

                {/* IR Operations + Evidence IDs strip */}
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(340px, 1fr))', gap: '1.5rem' }}>

                  {/* IR Operations */}
                  <div style={{
                    background: 'var(--bg-card)',
                    borderRadius: '10px',
                    border: '1px solid var(--border-color)',
                    padding: '1.5rem',
                  }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '1rem' }}>
                      <h3 style={{ fontSize: '0.95rem', fontWeight: 700, color: 'var(--text-primary)' }}>JOCKY IR</h3>
                      <span style={{
                        fontSize: '0.65rem',
                        padding: '0.15rem 0.4rem',
                        borderRadius: '4px',
                        background: 'rgba(99,102,241,0.1)',
                        color: 'var(--accent-indigo)',
                        fontWeight: 700,
                      }}>v{executeData.ir_version}</span>
                    </div>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.4rem' }}>
                      {executeData.policy_result?.approved_operations?.map((op, i) => (
                        <div key={i} style={{
                          padding: '0.5rem 0.85rem',
                          borderRadius: '5px',
                          background: 'rgba(99,102,241,0.05)',
                          border: '1px solid rgba(99,102,241,0.2)',
                          fontFamily: 'JetBrains Mono, monospace',
                          fontSize: '0.8rem',
                        }}>
                          <span style={{ color: 'var(--accent-indigo)', fontWeight: 700 }}>{op.type}</span>
                          {op.target && <span style={{ color: 'var(--accent-cyan)' }}> {op.target}</span>}
                          {op.format && <span style={{ color: 'var(--accent-amber)' }}> FORMAT {op.format}</span>}
                          {op.filters?.map((f, fi) => (
                            <div key={fi} style={{ paddingLeft: '1rem', color: 'var(--text-muted)', fontSize: '0.74rem' }}>
                              WHERE {f.field} {f.operator} {f.value}
                            </div>
                          ))}
                        </div>
                      ))}
                    </div>
                  </div>

                  {/* Evidence IDs + SHA-256 */}
                  <div style={{
                    background: 'var(--bg-card)',
                    borderRadius: '10px',
                    border: '1px solid var(--border-color)',
                    padding: '1.5rem',
                  }}>
                    <h3 style={{ fontSize: '0.95rem', fontWeight: 700, color: 'var(--text-primary)', marginBottom: '1rem' }}>Evidence Vault</h3>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                      {Object.entries(executeData.evidence_ids || {}).map(([src, eid]) => (
                        <div key={src} style={{
                          padding: '0.75rem 1rem',
                          borderRadius: '7px',
                          background: 'rgba(16,185,129,0.04)',
                          border: '1px solid rgba(16,185,129,0.2)',
                        }}>
                          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                            <span style={{ fontSize: '0.72rem', fontWeight: 700, color: 'var(--accent-emerald)', textTransform: 'uppercase' }}>{src}</span>
                            <span style={{
                              fontSize: '0.65rem',
                              padding: '0.1rem 0.35rem',
                              borderRadius: '3px',
                              background: 'rgba(16,185,129,0.15)',
                              color: 'var(--accent-emerald)',
                              fontWeight: 600,
                            }}>✓ HASHED</span>
                          </div>
                          <div style={{ fontSize: '0.72rem', fontFamily: 'JetBrains Mono, monospace', color: 'var(--accent-cyan)', marginTop: '0.3rem', wordBreak: 'break-all' }}>
                            {eid}
                          </div>
                          {executeData.sha256_hashes?.[src] && (
                            <div style={{ fontSize: '0.67rem', fontFamily: 'JetBrains Mono, monospace', color: 'var(--text-muted)', marginTop: '0.2rem', wordBreak: 'break-all' }}>
                              SHA-256: {executeData.sha256_hashes[src].slice(0, 32)}…
                            </div>
                          )}
                        </div>
                      ))}
                      {Object.keys(executeData.evidence_ids || {}).length === 0 && (
                        <div style={{ color: 'var(--text-muted)', fontSize: '0.85rem' }}>No evidence artifacts collected.</div>
                      )}
                    </div>
                  </div>
                </div>

                {/* Analysis Findings (if present) */}
                {executeData.analysis?.findings?.length > 0 && (
                  <div style={{
                    background: 'var(--bg-card)',
                    borderRadius: '10px',
                    border: '1px solid var(--border-color)',
                    padding: '1.5rem',
                  }}>
                    <h3 style={{ fontSize: '0.95rem', fontWeight: 700, color: 'var(--text-primary)', marginBottom: '1rem' }}>Analysis Findings</h3>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: '0.6rem' }}>
                      {executeData.analysis.findings.map((finding, i) => (
                        <div key={i} style={{
                          display: 'flex',
                          gap: '0.75rem',
                          padding: '0.65rem 1rem',
                          borderRadius: '6px',
                          background: 'rgba(56,189,248,0.04)',
                          border: '1px solid rgba(56,189,248,0.15)',
                        }}>
                          <span style={{ color: 'var(--accent-cyan)', flexShrink: 0 }}>ℹ</span>
                          <span style={{ fontSize: '0.84rem', color: 'var(--text-primary)', lineHeight: 1.5 }}>{finding}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

              </div>
            )}

            {/* Empty state */}
            {!executeData && !executeError && !executeLoading && (
              <div style={{
                textAlign: 'center',
                padding: '4rem 2rem',
                color: 'var(--text-muted)',
              }}>
                <div style={{ fontSize: '3rem', marginBottom: '1rem', opacity: 0.4 }}>⚡</div>
                <div style={{ fontSize: '1rem', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '0.5rem' }}>No Execution Run Yet</div>
                <div style={{ fontSize: '0.85rem' }}>Click <strong style={{ color: 'var(--accent-indigo)' }}>Run IR Execute</strong> to dispatch the current script through the Phase 2 IR execution pipeline.</div>
              </div>
            )}
          </div>
        )}

        {/* ============================================================== */}
        {/* TAB: CORRELATION GRAPH (PHASE 4)                               */}
        {/* ============================================================== */}
        {activeTab === 'correlation' && (
          <div>
            {/* Header Action Bar */}
            <div style={{
              background: 'linear-gradient(180deg, rgba(15, 23, 42, 0.9) 0%, rgba(12, 17, 29, 0.9) 100%)',
              borderRadius: '12px',
              border: '1px solid var(--border-color)',
              padding: '1.25rem 1.5rem',
              marginBottom: '1.5rem',
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              flexWrap: 'wrap',
              gap: '1rem',
            }}>
              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
                  <span style={{ fontSize: '1.4rem' }}>🕸️</span>
                  <h2 style={{ fontSize: '1.2rem', fontWeight: 700, color: 'var(--text-primary)', margin: 0 }}>
                    Forensic Correlation Graph
                  </h2>
                  <span style={{
                    fontSize: '0.7rem',
                    padding: '0.2rem 0.6rem',
                    borderRadius: '4px',
                    background: 'rgba(56, 189, 248, 0.1)',
                    color: 'var(--accent-cyan)',
                    fontWeight: 700,
                  }}>
                    PHASE 4
                  </span>
                </div>
                <p style={{ fontSize: '0.82rem', color: 'var(--text-secondary)', marginTop: '0.25rem', marginBottom: 0 }}>
                  Unified graph linkage connecting Processes ↔ Executables ↔ Network Sockets ↔ PPID Hierarchy
                </p>
              </div>

              <button
                id="btn-correlate-evidence"
                onClick={() => handleAnalyzeEvidenceCorrelate()}
                disabled={correlationLoading}
                style={{
                  background: 'linear-gradient(135deg, #0ea5e9 0%, #0284c7 100%)',
                  color: '#fff',
                  border: 'none',
                  borderRadius: '6px',
                  padding: '0.6rem 1.2rem',
                  fontSize: '0.85rem',
                  fontWeight: 700,
                  display: 'flex',
                  alignItems: 'center',
                  gap: '0.5rem',
                  cursor: correlationLoading ? 'not-allowed' : 'pointer',
                  boxShadow: '0 4px 15px rgba(14, 165, 233, 0.3)',
                }}
              >
                {correlationLoading ? 'Re-Correlating...' : '🔄 Run Live Correlation'}
              </button>
            </div>

            {/* KPI Metrics */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '1rem', marginBottom: '1.5rem' }}>
              <div style={{ background: 'var(--bg-card)', borderRadius: '10px', border: '1px solid var(--border-color)', padding: '1rem' }}>
                <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600 }}>Total Entities</div>
                <div style={{ fontSize: '1.4rem', fontWeight: 700, color: 'var(--accent-cyan)', marginTop: '0.2rem' }}>
                  {correlationData?.summary?.total_entities || 0}
                </div>
                <div style={{ fontSize: '0.72rem', color: 'var(--text-secondary)' }}>Registered Nodes</div>
              </div>

              <div style={{ background: 'var(--bg-card)', borderRadius: '10px', border: '1px solid var(--border-color)', padding: '1rem' }}>
                <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600 }}>Graph Edges</div>
                <div style={{ fontSize: '1.4rem', fontWeight: 700, color: 'var(--accent-indigo)', marginTop: '0.2rem' }}>
                  {correlationData?.summary?.total_relationships || 0}
                </div>
                <div style={{ fontSize: '0.72rem', color: 'var(--text-secondary)' }}>Cross-Artifact Links</div>
              </div>

              <div style={{ background: 'var(--bg-card)', borderRadius: '10px', border: '1px solid var(--border-color)', padding: '1rem' }}>
                <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600 }}>Processes</div>
                <div style={{ fontSize: '1.4rem', fontWeight: 700, color: 'var(--text-primary)', marginTop: '0.2rem' }}>
                  {correlationData?.summary?.process_count || 0}
                </div>
                <div style={{ fontSize: '0.72rem', color: 'var(--text-secondary)' }}>Active Process Nodes</div>
              </div>

              <div style={{ background: 'var(--bg-card)', borderRadius: '10px', border: '1px solid var(--border-color)', padding: '1rem' }}>
                <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600 }}>Network Sockets</div>
                <div style={{ fontSize: '1.4rem', fontWeight: 700, color: 'var(--accent-amber)', marginTop: '0.2rem' }}>
                  {correlationData?.summary?.network_count || 0}
                </div>
                <div style={{ fontSize: '0.72rem', color: 'var(--text-secondary)' }}>Correlated Endpoints</div>
              </div>

              <div style={{ background: 'var(--bg-card)', borderRadius: '10px', border: '1px solid var(--border-color)', padding: '1rem' }}>
                <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600 }}>Process Chains</div>
                <div style={{ fontSize: '1.4rem', fontWeight: 700, color: 'var(--accent-emerald)', marginTop: '0.2rem' }}>
                  {correlationData?.summary?.correlated_chains_count || 0}
                </div>
                <div style={{ fontSize: '0.72rem', color: 'var(--text-secondary)' }}>Full Provenance Paths</div>
              </div>
            </div>

            {/* Sub-Tabs: Chains, Tree, Entities */}
            <div style={{ display: 'flex', gap: '0.5rem', marginBottom: '1.25rem', borderBottom: '1px solid var(--border-color)', paddingBottom: '0.5rem' }}>
              {[
                { id: 'chains', label: `🔗 Correlated Chains (${correlationData?.correlated_chains?.length || 0})` },
                { id: 'tree', label: `🌳 Process Hierarchy Tree (${correlationData?.process_tree?.length || 0} Roots)` },
                { id: 'entities', label: `📋 Entity Registry (${correlationData?.summary?.total_entities || 0})` },
              ].map((st) => (
                <button
                  key={st.id}
                  onClick={() => setCorrelationSubTab(st.id)}
                  style={{
                    padding: '0.45rem 0.9rem',
                    borderRadius: '6px',
                    fontSize: '0.8rem',
                    fontWeight: 600,
                    border: 'none',
                    background: correlationSubTab === st.id ? 'rgba(56, 189, 248, 0.15)' : 'transparent',
                    color: correlationSubTab === st.id ? 'var(--accent-cyan)' : 'var(--text-secondary)',
                    cursor: 'pointer',
                  }}
                >
                  {st.label}
                </button>
              ))}
            </div>

            {/* Sub-Tab 1: Correlated Chains */}
            {correlationSubTab === 'chains' && (
              <div>
                <div style={{ marginBottom: '1rem' }}>
                  <input
                    type="text"
                    placeholder="Search chains by process name, PID, or Entity ID..."
                    value={correlationSearch}
                    onChange={(e) => setCorrelationSearch(e.target.value)}
                    style={{
                      width: '100%',
                      padding: '0.6rem 1rem',
                      borderRadius: '8px',
                      background: 'rgba(15, 23, 42, 0.6)',
                      border: '1px solid var(--border-color)',
                      color: 'var(--text-primary)',
                      fontSize: '0.85rem',
                      outline: 'none',
                    }}
                  />
                </div>

                <div style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
                  {(correlationData?.correlated_chains || [])
                    .filter((chain) => {
                      if (!correlationSearch) return true;
                      const q = correlationSearch.toLowerCase();
                      return (
                        chain.process_name?.toLowerCase().includes(q) ||
                        String(chain.pid).includes(q) ||
                        chain.entity_id?.toLowerCase().includes(q) ||
                        chain.executable?.path?.toLowerCase().includes(q)
                      );
                    })
                    .map((chain) => (
                      <div
                        key={chain.entity_id}
                        style={{
                          background: 'var(--bg-card)',
                          borderRadius: '10px',
                          border: '1px solid var(--border-color)',
                          padding: '1.25rem',
                        }}
                      >
                        {/* Chain Header */}
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '0.5rem', marginBottom: '1rem', borderBottom: '1px solid rgba(255,255,255,0.05)', paddingBottom: '0.75rem' }}>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
                            <span style={{ fontSize: '1.1rem' }}>⚙️</span>
                            <span style={{ fontWeight: 700, fontSize: '1rem', color: 'var(--text-primary)' }}>
                              {chain.process_name}
                            </span>
                            <span style={{
                              fontFamily: 'monospace',
                              fontSize: '0.75rem',
                              padding: '0.15rem 0.5rem',
                              borderRadius: '4px',
                              background: 'rgba(56, 189, 248, 0.1)',
                              color: 'var(--accent-cyan)',
                            }}>
                              PID: {chain.pid}
                            </span>
                            <button
                              onClick={() => handleCopy(chain.entity_id)}
                              style={{
                                fontFamily: 'monospace',
                                fontSize: '0.7rem',
                                padding: '0.15rem 0.45rem',
                                borderRadius: '4px',
                                background: 'rgba(99, 102, 241, 0.15)',
                                color: 'var(--accent-indigo)',
                                border: '1px solid rgba(99, 102, 241, 0.3)',
                                cursor: 'pointer',
                              }}
                              title="Click to copy Entity ID"
                            >
                              {copiedHash === chain.entity_id ? '✓ Copied' : chain.entity_id}
                            </button>
                          </div>

                          <div style={{ display: 'flex', gap: '0.5rem', alignItems: 'center' }}>
                            {chain.username && (
                              <span style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
                                User: <strong style={{ color: 'var(--text-secondary)' }}>{chain.username}</strong>
                              </span>
                            )}
                            {chain.create_time && (
                              <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)', fontFamily: 'monospace' }}>
                                {chain.create_time.split('T')[1]?.slice(0, 8) || chain.create_time}
                              </span>
                            )}
                          </div>
                        </div>

                        {/* Tri-Fold Columns */}
                        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '1rem' }}>
                          {/* Col 1: Parent Process */}
                          <div style={{ background: 'rgba(15, 23, 42, 0.5)', padding: '0.85rem', borderRadius: '8px', border: '1px solid var(--border-color)' }}>
                            <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600, marginBottom: '0.4rem' }}>
                              ↳ Parent Process (PPID)
                            </div>
                            {chain.parent ? (
                              <div>
                                <div style={{ fontWeight: 600, color: 'var(--text-primary)', fontSize: '0.85rem' }}>
                                  {chain.parent.name}
                                </div>
                                <div style={{ fontSize: '0.75rem', color: 'var(--accent-cyan)', fontFamily: 'monospace', marginTop: '0.2rem' }}>
                                  PID: {chain.parent.pid} • {chain.parent.entity_id}
                                </div>
                                <span style={{
                                  display: 'inline-block',
                                  fontSize: '0.65rem',
                                  padding: '0.1rem 0.4rem',
                                  borderRadius: '3px',
                                  background: 'rgba(56, 189, 248, 0.1)',
                                  color: 'var(--accent-cyan)',
                                  marginTop: '0.4rem',
                                }}>
                                  SPAWNED_CHILD
                                </span>
                              </div>
                            ) : (
                              <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)', fontStyle: 'italic' }}>
                                Root / System Service (No active parent)
                              </div>
                            )}
                          </div>

                          {/* Col 2: Binary Executable */}
                          <div style={{ background: 'rgba(15, 23, 42, 0.5)', padding: '0.85rem', borderRadius: '8px', border: '1px solid var(--border-color)' }}>
                            <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600, marginBottom: '0.4rem' }}>
                              📁 Binary Executable (EXECUTED_FROM)
                            </div>
                            {chain.executable ? (
                              <div>
                                <div style={{ fontSize: '0.8rem', color: 'var(--text-primary)', wordBreak: 'break-all', fontFamily: 'monospace' }}>
                                  {chain.executable.path}
                                </div>
                                <div style={{ marginTop: '0.4rem', display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                                  <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>SHA-256:</span>
                                  {chain.executable.sha256 ? (
                                    <button
                                      onClick={() => handleCopy(chain.executable.sha256)}
                                      style={{
                                        fontFamily: 'monospace',
                                        fontSize: '0.7rem',
                                        padding: '0.1rem 0.35rem',
                                        borderRadius: '3px',
                                        background: 'rgba(16, 185, 129, 0.1)',
                                        color: 'var(--accent-emerald)',
                                        border: '1px solid rgba(16, 185, 129, 0.25)',
                                        cursor: 'pointer',
                                      }}
                                    >
                                      {copiedHash === chain.executable.sha256 ? '✓ Copied' : `${chain.executable.sha256.slice(0, 16)}...`}
                                    </button>
                                  ) : (
                                    <span style={{ fontSize: '0.7rem', color: 'var(--text-muted)' }}>Unhashed</span>
                                  )}
                                </div>
                              </div>
                            ) : (
                              <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)', fontStyle: 'italic' }}>
                                Unmapped / In-Memory / Protected
                              </div>
                            )}
                          </div>

                          {/* Col 3: Active Sockets */}
                          <div style={{ background: 'rgba(15, 23, 42, 0.5)', padding: '0.85rem', borderRadius: '8px', border: '1px solid var(--border-color)' }}>
                            <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600, marginBottom: '0.4rem' }}>
                              🌐 Network Sockets (OPENED_SOCKET)
                            </div>
                            {chain.network_connections && chain.network_connections.length > 0 ? (
                              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.35rem' }}>
                                {chain.network_connections.map((conn, idx) => (
                                  <div key={idx} style={{ fontSize: '0.75rem', fontFamily: 'monospace', display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                                    <span style={{
                                      padding: '0.1rem 0.3rem',
                                      borderRadius: '3px',
                                      background: conn.status === 'ESTABLISHED' ? 'rgba(16, 185, 129, 0.15)' : 'rgba(56, 189, 248, 0.15)',
                                      color: conn.status === 'ESTABLISHED' ? 'var(--accent-emerald)' : 'var(--accent-cyan)',
                                      fontSize: '0.65rem',
                                    }}>
                                      {conn.protocol} {conn.status}
                                    </span>
                                    <span style={{ color: 'var(--text-primary)' }}>
                                      {conn.laddr?.ip}:{conn.laddr?.port} → {conn.raddr?.ip ? `${conn.raddr.ip}:${conn.raddr.port}` : 'LISTEN'}
                                    </span>
                                  </div>
                                ))}
                              </div>
                            ) : (
                              <div style={{ fontSize: '0.8rem', color: 'var(--text-muted)', fontStyle: 'italic' }}>
                                No active network sockets
                              </div>
                            )}
                          </div>
                        </div>

                        {/* Children List */}
                        {chain.children && chain.children.length > 0 && (
                          <div style={{ marginTop: '0.85rem', paddingTop: '0.6rem', borderTop: '1px dashed rgba(255,255,255,0.06)', display: 'flex', alignItems: 'center', gap: '0.5rem', flexWrap: 'wrap' }}>
                            <span style={{ fontSize: '0.72rem', color: 'var(--text-muted)', fontWeight: 600 }}>Spawned Children:</span>
                            {chain.children.map((child, idx) => (
                              <span
                                key={idx}
                                style={{
                                  fontSize: '0.72rem',
                                  padding: '0.15rem 0.5rem',
                                  borderRadius: '4px',
                                  background: 'rgba(99, 102, 241, 0.1)',
                                  color: 'var(--accent-indigo)',
                                  border: '1px solid rgba(99, 102, 241, 0.2)',
                                }}
                              >
                                {child.name} (PID: {child.pid})
                              </span>
                            ))}
                          </div>
                        )}
                      </div>
                    ))}
                </div>
              </div>
            )}

            {/* Sub-Tab 2: Process Hierarchy Tree */}
            {correlationSubTab === 'tree' && (
              <div style={{ background: 'var(--bg-card)', borderRadius: '10px', border: '1px solid var(--border-color)', padding: '1.5rem' }}>
                <div style={{ marginBottom: '1rem' }}>
                  <h3 style={{ fontSize: '0.95rem', fontWeight: 700, color: 'var(--text-primary)', margin: 0 }}>
                    Process Parent-Child Hierarchy (PPID Trees)
                  </h3>
                  <p style={{ fontSize: '0.78rem', color: 'var(--text-secondary)', marginTop: '0.2rem' }}>
                    Click arrow to expand/collapse child process subtrees. Reconstructed from live PPID links.
                  </p>
                </div>

                <div style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                  {(correlationData?.process_tree || []).map((rootNode) => (
                    <ProcessTreeNode key={rootNode.pid} node={rootNode} depth={0} />
                  ))}
                  {(!correlationData?.process_tree || correlationData.process_tree.length === 0) && (
                    <div style={{ textAlign: 'center', color: 'var(--text-muted)', padding: '2rem' }}>
                      No process tree data available. Click "Run Live Correlation".
                    </div>
                  )}
                </div>
              </div>
            )}

            {/* Sub-Tab 3: Entity Registry */}
            {correlationSubTab === 'entities' && (
              <div style={{ background: 'var(--bg-card)', borderRadius: '10px', border: '1px solid var(--border-color)', padding: '1.5rem', overflowX: 'auto' }}>
                <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left', fontSize: '0.8rem' }}>
                  <thead>
                    <tr style={{ borderBottom: '1px solid var(--border-color)', color: 'var(--text-muted)' }}>
                      <th style={{ padding: '0.6rem' }}>Entity ID</th>
                      <th style={{ padding: '0.6rem' }}>Type</th>
                      <th style={{ padding: '0.6rem' }}>Identifier / Path</th>
                      <th style={{ padding: '0.6rem' }}>Security Context / Status</th>
                    </tr>
                  </thead>
                  <tbody>
                    {(correlationData?.entities?.processes || []).map((p) => (
                      <tr key={p.entity_id} style={{ borderBottom: '1px solid rgba(255,255,255,0.03)' }}>
                        <td style={{ padding: '0.6rem', fontFamily: 'monospace', color: 'var(--accent-cyan)' }}>{p.entity_id}</td>
                        <td style={{ padding: '0.6rem' }}><span style={{ padding: '0.1rem 0.4rem', borderRadius: '3px', background: 'rgba(56, 189, 248, 0.1)', color: 'var(--accent-cyan)', fontSize: '0.7rem' }}>PROCESS</span></td>
                        <td style={{ padding: '0.6rem', fontWeight: 600, color: 'var(--text-primary)' }}>{p.name} (PID: {p.pid})</td>
                        <td style={{ padding: '0.6rem', color: 'var(--text-muted)' }}>{p.username || 'N/A'}</td>
                      </tr>
                    ))}
                    {(correlationData?.entities?.network || []).map((n) => (
                      <tr key={n.entity_id} style={{ borderBottom: '1px solid rgba(255,255,255,0.03)' }}>
                        <td style={{ padding: '0.6rem', fontFamily: 'monospace', color: 'var(--accent-amber)' }}>{n.entity_id}</td>
                        <td style={{ padding: '0.6rem' }}><span style={{ padding: '0.1rem 0.4rem', borderRadius: '3px', background: 'rgba(245, 158, 11, 0.1)', color: 'var(--accent-amber)', fontSize: '0.7rem' }}>SOCKET</span></td>
                        <td style={{ padding: '0.6rem', fontFamily: 'monospace', color: 'var(--text-primary)' }}>{n.protocol} {n.laddr?.ip}:{n.laddr?.port} → {n.raddr?.ip ? `${n.raddr.ip}:${n.raddr.port}` : 'LISTEN'}</td>
                        <td style={{ padding: '0.6rem', color: 'var(--text-muted)' }}>Status: {n.status}</td>
                      </tr>
                    ))}
                    {(correlationData?.entities?.files || []).map((f) => (
                      <tr key={f.entity_id} style={{ borderBottom: '1px solid rgba(255,255,255,0.03)' }}>
                        <td style={{ padding: '0.6rem', fontFamily: 'monospace', color: 'var(--accent-emerald)' }}>{f.entity_id}</td>
                        <td style={{ padding: '0.6rem' }}><span style={{ padding: '0.1rem 0.4rem', borderRadius: '3px', background: 'rgba(16, 185, 129, 0.1)', color: 'var(--accent-emerald)', fontSize: '0.7rem' }}>FILE</span></td>
                        <td style={{ padding: '0.6rem', fontFamily: 'monospace', color: 'var(--text-primary)', wordBreak: 'break-all' }}>{f.path}</td>
                        <td style={{ padding: '0.6rem', color: 'var(--text-muted)', fontFamily: 'monospace', fontSize: '0.7rem' }}>{f.sha256 ? `${f.sha256.slice(0, 16)}...` : 'Unhashed'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        )}

        {/* ============================================================== */}
        {/* TAB: FORENSIC TIMELINE & ANALYSIS (PHASE 5)                   */}
        {/* ============================================================== */}
        {activeTab === 'timeline' && (
          <div>
            {/* Header Action Bar */}
            <div style={{
              background: 'linear-gradient(180deg, rgba(15, 23, 42, 0.9) 0%, rgba(12, 17, 29, 0.9) 100%)',
              borderRadius: '12px',
              border: '1px solid var(--border-color)',
              padding: '1.25rem 1.5rem',
              marginBottom: '1.5rem',
              display: 'flex',
              justifyContent: 'space-between',
              alignItems: 'center',
              flexWrap: 'wrap',
              gap: '1rem',
            }}>
              <div>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
                  <span style={{ fontSize: '1.4rem' }}>⏱️</span>
                  <h2 style={{ fontSize: '1.2rem', fontWeight: 700, color: 'var(--text-primary)', margin: 0 }}>
                    Forensic Timeline &amp; Automated Analysis
                  </h2>
                  <span style={{
                    fontSize: '0.7rem',
                    padding: '0.2rem 0.6rem',
                    borderRadius: '4px',
                    background: 'rgba(16, 185, 129, 0.1)',
                    color: 'var(--accent-emerald)',
                    fontWeight: 700,
                  }}>
                    PHASE 5
                  </span>
                </div>
                <p style={{ fontSize: '0.82rem', color: 'var(--text-secondary)', marginTop: '0.25rem', marginBottom: 0 }}>
                  Chronological multi-source forensic reconstruction &amp; explainable deterministic anomaly indicators
                </p>
              </div>

              <button
                onClick={handleFetchTimeline}
                disabled={timelineLoading}
                style={{
                  background: 'linear-gradient(135deg, #10b981 0%, #059669 100%)',
                  color: '#fff',
                  border: 'none',
                  borderRadius: '6px',
                  padding: '0.6rem 1.2rem',
                  fontSize: '0.85rem',
                  fontWeight: 700,
                  display: 'flex',
                  alignItems: 'center',
                  gap: '0.5rem',
                  cursor: timelineLoading ? 'not-allowed' : 'pointer',
                  boxShadow: '0 4px 15px rgba(16, 185, 129, 0.3)',
                }}
              >
                {timelineLoading ? 'Scanning...' : '🔄 Re-Scan Timeline & Analysis'}
              </button>
            </div>

            {/* KPI Cards */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(180px, 1fr))', gap: '1rem', marginBottom: '1.5rem' }}>
              <div style={{ background: 'var(--bg-card)', borderRadius: '10px', border: '1px solid var(--border-color)', padding: '1rem' }}>
                <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600 }}>Total Events</div>
                <div style={{ fontSize: '1.4rem', fontWeight: 700, color: 'var(--text-primary)', marginTop: '0.2rem' }}>
                  {timelineData?.length || 0}
                </div>
                <div style={{ fontSize: '0.72rem', color: 'var(--text-secondary)' }}>Normalized Chronological Events</div>
              </div>

              <div style={{ background: 'var(--bg-card)', borderRadius: '10px', border: '1px solid var(--border-color)', padding: '1rem' }}>
                <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600 }}>High Alerts</div>
                <div style={{ fontSize: '1.4rem', fontWeight: 700, color: 'var(--accent-rose)', marginTop: '0.2rem' }}>
                  {analysisData?.severity_counts?.high || 0}
                </div>
                <div style={{ fontSize: '0.72rem', color: 'var(--text-secondary)' }}>Critical Suspicious Patterns</div>
              </div>

              <div style={{ background: 'var(--bg-card)', borderRadius: '10px', border: '1px solid var(--border-color)', padding: '1rem' }}>
                <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600 }}>Medium Alerts</div>
                <div style={{ fontSize: '1.4rem', fontWeight: 700, color: 'var(--accent-amber)', marginTop: '0.2rem' }}>
                  {analysisData?.severity_counts?.medium || 0}
                </div>
                <div style={{ fontSize: '0.72rem', color: 'var(--text-secondary)' }}>Anomalous Sockets / Autoruns</div>
              </div>

              <div style={{ background: 'var(--bg-card)', borderRadius: '10px', border: '1px solid var(--border-color)', padding: '1rem' }}>
                <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 600 }}>Low / Info Alerts</div>
                <div style={{ fontSize: '1.4rem', fontWeight: 700, color: 'var(--accent-cyan)', marginTop: '0.2rem' }}>
                  {analysisData?.severity_counts?.low || 0}
                </div>
                <div style={{ fontSize: '0.72rem', color: 'var(--text-secondary)' }}>Unmapped Executables</div>
              </div>
            </div>

            {/* SECTION A: HEURISTIC ANOMALY DETECTIONS */}
            <div style={{ background: 'var(--bg-card)', borderRadius: '10px', border: '1px solid var(--border-color)', padding: '1.5rem', marginBottom: '1.5rem' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1rem', flexWrap: 'wrap', gap: '0.5rem' }}>
                <div>
                  <h3 style={{ fontSize: '1rem', fontWeight: 700, color: 'var(--text-primary)', margin: 0 }}>
                    🚨 Rule-Based Heuristic Detections
                  </h3>
                  <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', marginTop: '0.2rem' }}>
                    100% deterministic rules (RULE-001 through RULE-005) • Explainable digital forensic rationale
                  </div>
                </div>

                <div style={{ display: 'flex', gap: '0.4rem' }}>
                  {['ALL', 'HIGH', 'MEDIUM', 'LOW'].map((sev) => (
                    <button
                      key={sev}
                      onClick={() => setRuleSeverityFilter(sev)}
                      style={{
                        padding: '0.25rem 0.6rem',
                        borderRadius: '4px',
                        fontSize: '0.75rem',
                        fontWeight: 600,
                        border: 'none',
                        background: ruleSeverityFilter === sev ? 'rgba(56, 189, 248, 0.2)' : 'rgba(255,255,255,0.04)',
                        color: ruleSeverityFilter === sev ? 'var(--accent-cyan)' : 'var(--text-secondary)',
                        cursor: 'pointer',
                      }}
                    >
                      {sev}
                    </button>
                  ))}
                </div>
              </div>

              {/* Detections List */}
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                {(analysisData?.detections || [])
                  .filter((d) => ruleSeverityFilter === 'ALL' || d.severity === ruleSeverityFilter)
                  .map((det, idx) => {
                    const borderColor = det.severity === 'HIGH' ? 'var(--accent-rose)' : det.severity === 'MEDIUM' ? 'var(--accent-amber)' : 'var(--accent-cyan)';
                    return (
                      <div
                        key={idx}
                        style={{
                          background: 'rgba(15, 23, 42, 0.6)',
                          borderLeft: `4px solid ${borderColor}`,
                          borderRadius: '6px',
                          border: '1px solid rgba(255,255,255,0.06)',
                          padding: '1rem',
                        }}
                      >
                        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.4rem' }}>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                            <span style={{
                              fontFamily: 'monospace',
                              fontWeight: 700,
                              fontSize: '0.75rem',
                              color: borderColor,
                            }}>
                              [{det.rule_id}]
                            </span>
                            <span style={{ fontWeight: 700, fontSize: '0.9rem', color: 'var(--text-primary)' }}>
                              {det.name}
                            </span>
                          </div>
                          <div style={{ display: 'flex', gap: '0.4rem' }}>
                            <span style={{
                              fontSize: '0.68rem',
                              padding: '0.15rem 0.45rem',
                              borderRadius: '4px',
                              background: det.severity === 'HIGH' ? 'rgba(244, 63, 94, 0.15)' : 'rgba(245, 158, 11, 0.15)',
                              color: borderColor,
                              fontWeight: 700,
                            }}>
                              {det.severity}
                            </span>
                            <span style={{
                              fontFamily: 'monospace',
                              fontSize: '0.68rem',
                              padding: '0.15rem 0.45rem',
                              borderRadius: '4px',
                              background: 'rgba(56, 189, 248, 0.1)',
                              color: 'var(--accent-cyan)',
                            }}>
                              {det.entity}
                            </span>
                          </div>
                        </div>

                        <p style={{ fontSize: '0.82rem', color: 'var(--text-secondary)', lineHeight: 1.5, margin: '0.4rem 0' }}>
                          {det.description}
                        </p>

                        <div style={{ fontSize: '0.75rem', color: 'var(--accent-emerald)', marginTop: '0.5rem', display: 'flex', alignItems: 'center', gap: '0.35rem' }}>
                          <span>💡</span>
                          <strong>Recommended Read-Only Step:</strong> {det.recommendation}
                        </div>
                      </div>
                    );
                  })}

                {(!analysisData?.detections || analysisData.detections.length === 0) && (
                  <div style={{
                    padding: '1.5rem',
                    textAlign: 'center',
                    background: 'rgba(16, 185, 129, 0.05)',
                    border: '1px solid rgba(16, 185, 129, 0.2)',
                    borderRadius: '8px',
                    color: 'var(--accent-emerald)',
                    fontSize: '0.85rem',
                    fontWeight: 600,
                  }}>
                    ✓ Normal Baseline: No high or medium-severity suspicious patterns detected in current snapshot.
                  </div>
                )}
              </div>
            </div>

            {/* SECTION B: CHRONOLOGICAL TIMELINE STREAM */}
            <div style={{ background: 'var(--bg-card)', borderRadius: '10px', border: '1px solid var(--border-color)', padding: '1.5rem' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '1.25rem', flexWrap: 'wrap', gap: '0.75rem' }}>
                <div>
                  <h3 style={{ fontSize: '1rem', fontWeight: 700, color: 'var(--text-primary)', margin: 0 }}>
                    ⏱️ Chronological Forensic Event Stream
                  </h3>
                  <div style={{ fontSize: '0.75rem', color: 'var(--text-secondary)', marginTop: '0.2rem' }}>
                    Ordered chronologically across Boot, Processes, Sockets, Files, Users &amp; Autoruns
                  </div>
                </div>

                <div style={{ display: 'flex', gap: '0.4rem', flexWrap: 'wrap' }}>
                  {['ALL', 'PROCESS_SPAWN', 'NETWORK_SOCKET', 'FILE_INSPECTED', 'USER_SESSION', 'PERSISTENCE_ENTRY', 'SYSTEM_BOOT'].map((type) => (
                    <button
                      key={type}
                      onClick={() => setTimelineEventTypeFilter(type)}
                      style={{
                        padding: '0.25rem 0.55rem',
                        borderRadius: '4px',
                        fontSize: '0.7rem',
                        fontWeight: 600,
                        border: 'none',
                        background: timelineEventTypeFilter === type ? 'rgba(56, 189, 248, 0.2)' : 'rgba(255,255,255,0.04)',
                        color: timelineEventTypeFilter === type ? 'var(--accent-cyan)' : 'var(--text-secondary)',
                        cursor: 'pointer',
                      }}
                    >
                      {type}
                    </button>
                  ))}
                </div>
              </div>

              {/* Search */}
              <div style={{ marginBottom: '1rem' }}>
                <input
                  type="text"
                  placeholder="Search timeline events by description, entity, or source..."
                  value={timelineSearch}
                  onChange={(e) => setTimelineSearch(e.target.value)}
                  style={{
                    width: '100%',
                    padding: '0.6rem 1rem',
                    borderRadius: '8px',
                    background: 'rgba(15, 23, 42, 0.6)',
                    border: '1px solid var(--border-color)',
                    color: 'var(--text-primary)',
                    fontSize: '0.85rem',
                    outline: 'none',
                  }}
                />
              </div>

              {/* Timeline Feed */}
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
                {(timelineData || [])
                  .filter((evt) => {
                    if (timelineEventTypeFilter !== 'ALL' && evt.event_type !== timelineEventTypeFilter) return false;
                    if (!timelineSearch) return true;
                    const q = timelineSearch.toLowerCase();
                    return (
                      evt.description?.toLowerCase().includes(q) ||
                      evt.entity?.toLowerCase().includes(q) ||
                      evt.source?.toLowerCase().includes(q)
                    );
                  })
                  .slice(0, 100)
                  .map((evt, idx) => {
                    const dotColor =
                      evt.event_type === 'PROCESS_SPAWN' ? 'var(--accent-cyan)' :
                      evt.event_type === 'NETWORK_SOCKET' ? 'var(--accent-amber)' :
                      evt.event_type === 'FILE_INSPECTED' ? 'var(--accent-emerald)' :
                      evt.event_type === 'PERSISTENCE_ENTRY' ? 'var(--accent-rose)' :
                      evt.event_type === 'SYSTEM_BOOT' ? 'var(--accent-indigo)' : 'var(--text-secondary)';

                    return (
                      <div
                        key={idx}
                        style={{
                          display: 'flex',
                          alignItems: 'flex-start',
                          gap: '1rem',
                          padding: '0.75rem',
                          background: 'rgba(15, 23, 42, 0.5)',
                          borderRadius: '8px',
                          border: '1px solid var(--border-color)',
                        }}
                      >
                        {/* Timestamp */}
                        <div style={{ width: '170px', flexShrink: 0, fontFamily: 'monospace', fontSize: '0.72rem', color: 'var(--text-muted)' }}>
                          {evt.timestamp || 'Snapshot Telemetry'}
                        </div>

                        {/* Dot */}
                        <div style={{
                          width: '10px',
                          height: '10px',
                          borderRadius: '50%',
                          backgroundColor: dotColor,
                          marginTop: '0.25rem',
                          flexShrink: 0,
                          boxShadow: `0 0 8px ${dotColor}`,
                        }} />

                        {/* Event Content */}
                        <div style={{ flex: 1 }}>
                          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem', marginBottom: '0.25rem', flexWrap: 'wrap' }}>
                            <span style={{
                              fontSize: '0.65rem',
                              padding: '0.1rem 0.4rem',
                              borderRadius: '3px',
                              background: 'rgba(255,255,255,0.06)',
                              color: dotColor,
                              fontWeight: 700,
                            }}>
                              {evt.event_type}
                            </span>
                            <span style={{ fontSize: '0.65rem', color: 'var(--text-muted)', textTransform: 'uppercase' }}>
                              SRC: {evt.source}
                            </span>
                            <button
                              onClick={() => handleCopy(evt.entity)}
                              style={{
                                fontFamily: 'monospace',
                                fontSize: '0.65rem',
                                padding: '0.05rem 0.35rem',
                                borderRadius: '3px',
                                background: 'rgba(56, 189, 248, 0.1)',
                                color: 'var(--accent-cyan)',
                                border: '1px solid rgba(56, 189, 248, 0.2)',
                                cursor: 'pointer',
                              }}
                            >
                              {copiedHash === evt.entity ? '✓ Copied' : evt.entity}
                            </button>
                            <span style={{ fontSize: '0.65rem', color: 'var(--text-muted)', fontFamily: 'monospace' }}>
                              {evt.evidence_id}
                            </span>
                          </div>

                          <div style={{ fontSize: '0.82rem', color: 'var(--text-primary)', lineHeight: 1.4 }}>
                            {evt.description}
                          </div>
                        </div>
                      </div>
                    );
                  })}

                {(!timelineData || timelineData.length === 0) && (
                  <div style={{ textAlign: 'center', color: 'var(--text-muted)', padding: '2rem' }}>
                    No timeline events loaded yet. Click "Re-Scan Timeline &amp; Analysis".
                  </div>
                )}
              </div>
            </div>
          </div>
        )}

      </main>

      {/* Footer */}
      <footer style={{
        borderTop: '1px solid var(--border-color)',
        padding: '1rem 2rem',
        textAlign: 'center',
        fontSize: '0.75rem',
        color: 'var(--text-muted)',
      }}>
        JOCKY Forensic Analysis Framework • SIH 2026 Problem SIH26148 • Strictly Authorized Read-Only Architecture
      </footer>
      </div>

      {/* Generate & Send Report Modal */}
      <ReportModal
        isOpen={isReportModalOpen}
        onClose={() => {
          setIsReportModalOpen(false);
          setIsLogoutWorkflow(false);
        }}
        caseId={investigationData?.case_id || 'LAB-2026-001'}
        session={session}
        isLogoutWorkflow={isLogoutWorkflow}
        onLogoutAfterReport={handleLogoutAfterReport}
      />

      {/* Logout Confirmation Modal */}
      <LogoutModal
        isOpen={isLogoutModalOpen}
        onClose={() => setIsLogoutModalOpen(false)}
        onLogoutWithoutSending={handleLogoutWithoutSending}
        onGenerateAndSend={() => {
          setIsLogoutModalOpen(false);
          setIsLogoutWorkflow(true);
          setIsReportModalOpen(true);
        }}
      />

      {/* JOCKY Command Palette Modal */}
      {isCommandModalOpen && (
        <div style={{
          position: 'fixed',
          top: 0,
          left: 0,
          right: 0,
          bottom: 0,
          backgroundColor: 'rgba(0, 0, 0, 0.75)',
          backdropFilter: 'blur(4px)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          zIndex: 1000,
          padding: '1.25rem',
        }}>
          <div style={{
            width: '100%',
            maxWidth: '920px',
            maxHeight: '88vh',
            overflowY: 'auto',
            background: 'var(--bg-card)',
            borderRadius: '12px',
            border: '1px solid var(--border-color)',
            boxShadow: '0 20px 50px rgba(0, 0, 0, 0.7)',
            padding: '1.5rem',
          }}>
            <CommandSearch
              onInsertCommand={(cmdSyntax) => {
                handleInsertCommand(cmdSyntax);
                setIsCommandModalOpen(false);
              }}
              onCloseModal={() => setIsCommandModalOpen(false)}
            />
          </div>
        </div>
      )}
    </div>
  );
}
