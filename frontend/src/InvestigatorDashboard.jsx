import React from 'react';
import { getUniqueTargetDevices } from './deviceUtils.js';

export default function InvestigatorDashboard({
  investigationData,
  systemInfo = {},
  platformInfo,
  processesList = [],
  networkList = [],
  vaultAudit,
  correlationData,
  analysisData,
  timelineData,
  backendHealth,
  loading = false,
  onNavigateTab,
  onRunInvestigation,
  devices = [],
  selectedDeviceId = null,
  onSelectTarget = () => {},
  onOpenPairModal = () => {},
}) {
  // Safe extractions
  const caseId = investigationData?.case_id || 'N/A';
  const targetHost = investigationData?.target || systemInfo?.hostname || 'N/A';
  const selectedDevice = devices.find((d) => d.device_id === selectedDeviceId);
  const activeEndpoints = getUniqueTargetDevices(devices, selectedDeviceId);
  const onlineCount = activeEndpoints.filter((d) => Boolean(d.is_online)).length;
  const executionStatus = loading
    ? 'Running...'
    : investigationData?.status
    ? investigationData.status.toUpperCase()
    : backendHealth?.status === 'online'
    ? 'READY'
    : 'OFFLINE';

  // System
  const hostname = systemInfo?.hostname || 'N/A';
  const operatingSystem = systemInfo?.os || systemInfo?.operating_system || platformInfo?.os_name || 'N/A';
  const platform = platformInfo?.platform || systemInfo?.platform || (platformInfo?.is_linux ? 'Linux' : platformInfo?.is_windows ? 'Windows' : 'N/A');

  // Processes
  const totalProcesses = processesList.length > 0 ? processesList.length : 'No data collected';
  const runningProcessesCount = processesList.filter(
    (p) => String(p.status || '').toLowerCase() === 'running'
  ).length;
  const runningProcesses = processesList.length > 0 ? runningProcessesCount : 'No data collected';

  // Network
  const activeConnections = networkList.length > 0 ? networkList.length : 'No data collected';
  const establishedConnectionsCount = networkList.filter(
    (c) => String(c.status || '').toUpperCase() === 'ESTABLISHED'
  ).length;
  const establishedConnections = networkList.length > 0 ? establishedConnectionsCount : 'No data collected';

  // Evidence
  const evidenceItemsCount = vaultAudit?.total_artifacts ?? vaultAudit?.artifacts_summary?.length;
  const evidenceItems = evidenceItemsCount !== undefined ? evidenceItemsCount : 'No data collected';
  const integrityStatus = vaultAudit?.vault_status
    ? vaultAudit.vault_status === 'COMPROMISED'
      ? 'COMPROMISED (Tamper Detected)'
      : 'VERIFIED INTACT'
    : 'No data collected';

  // Analysis
  const correlationsCount = correlationData?.correlations?.length ?? correlationData?.edges?.length;
  const correlations = correlationsCount !== undefined ? correlationsCount : 'No data collected';

  const detectionsCount =
    analysisData?.detections?.length ??
    investigationData?.analysis?.findings?.length;
  const detections = detectionsCount !== undefined ? detectionsCount : 'No data collected';

  const timelineEventsCount = timelineData?.length ?? timelineData?.events?.length;
  const timelineEvents = timelineEventsCount !== undefined ? timelineEventsCount : 'No data collected';

  // Reports
  const availableReportFormats = ['HTML', 'JSON', 'MARKDOWN'];

  const cards = [
    {
      id: 'case',
      title: 'CASE',
      badge: caseId !== 'N/A' ? caseId : null,
      icon: '📁',
      color: 'var(--accent-cyan)',
      items: [
        { label: 'Case Identifier', value: caseId, isMono: true },
        { label: 'Target Endpoint', value: targetHost, isMono: true },
        {
          label: 'Execution Status',
          value: executionStatus,
          isBadge: true,
          badgeColor:
            executionStatus === 'SUCCESS' || executionStatus === 'COMPLETED' || executionStatus === 'READY'
              ? 'var(--accent-emerald)'
              : executionStatus === 'Running...'
              ? 'var(--accent-amber)'
              : 'var(--accent-rose)',
        },
      ],
      targetTab: 'script',
      actionLabel: 'Open Script',
    },
    {
      id: 'system',
      title: 'SYSTEM',
      icon: '💻',
      color: 'var(--accent-indigo)',
      items: [
        { label: 'Hostname', value: hostname, isMono: true },
        { label: 'Operating System', value: operatingSystem },
        { label: 'Platform Architecture', value: platform },
      ],
      targetTab: 'system',
      actionLabel: 'View Telemetry',
    },
    {
      id: 'processes',
      title: 'PROCESSES',
      icon: '⚙️',
      color: 'var(--accent-cyan)',
      items: [
        { label: 'Total Processes', value: totalProcesses },
        { label: 'Running Processes', value: runningProcesses },
      ],
      targetTab: 'processes',
      actionLabel: 'View Processes',
    },
    {
      id: 'network',
      title: 'NETWORK',
      icon: '🌐',
      color: 'var(--accent-indigo)',
      items: [
        { label: 'Active Connections', value: activeConnections },
        { label: 'Established Connections', value: establishedConnections },
      ],
      targetTab: 'network',
      actionLabel: 'View Sockets',
    },
    {
      id: 'evidence',
      title: 'EVIDENCE',
      icon: '🛡️',
      color: 'var(--accent-emerald)',
      items: [
        { label: 'Evidence Items', value: evidenceItems },
        {
          label: 'Integrity Status',
          value: integrityStatus,
          isBadge: integrityStatus !== 'No data collected',
          badgeColor:
            integrityStatus.includes('VERIFIED') || integrityStatus.includes('INTACT')
              ? 'var(--accent-emerald)'
              : 'var(--accent-rose)',
        },
      ],
      targetTab: 'evidence',
      actionLabel: 'Inspect Vault',
    },
    {
      id: 'analysis',
      title: 'ANALYSIS',
      icon: '🔬',
      color: 'var(--accent-amber)',
      items: [
        { label: 'Correlations', value: correlations },
        { label: 'Detections / Findings', value: detections },
        { label: 'Timeline Events', value: timelineEvents },
      ],
      targetTab: 'correlation',
      actionLabel: 'View Graphs',
    },
    {
      id: 'reports',
      title: 'REPORTS',
      icon: '📄',
      color: 'var(--accent-cyan)',
      items: [
        { label: 'Available Formats', value: availableReportFormats.join(' • '), isMono: true },
        {
          label: 'Report Generation',
          value: investigationData ? 'Ready to Export' : 'Awaiting Collection',
          isBadge: true,
          badgeColor: investigationData ? 'var(--accent-emerald)' : 'var(--text-muted)',
        },
      ],
      targetTab: 'reports',
      actionLabel: 'Manage Reports',
    },
    {
      id: 'endpoints',
      title: 'ENDPOINT DEVICES',
      badge: onlineCount > 0 ? `${onlineCount} ONLINE` : null,
      icon: '🛰️',
      color: 'var(--accent-cyan)',
      items: [
        {
          label: 'Target',
          value: selectedDevice ? (selectedDevice.hostname || selectedDevice.device_id) : 'Local Cloud Server',
          isMono: true,
        },
        {
          label: 'Enrolled Devices',
          value: `${activeEndpoints.length} Endpoint(s)`,
        },
        {
          label: 'Target Status',
          value: selectedDevice ? (selectedDevice.is_online ? 'ONLINE' : 'OFFLINE') : 'READY (Local)',
          isBadge: true,
          badgeColor: selectedDevice
            ? (selectedDevice.is_online ? 'var(--accent-emerald)' : 'var(--accent-rose)')
            : 'var(--accent-emerald)',
        },
      ],
      targetTab: 'endpoints',
      actionLabel: 'Manage Endpoints',
    },
  ];

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '1.5rem' }}>
      {/* Top Banner / Quick Controls */}
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
            <h1 style={{ fontSize: '1.25rem', fontWeight: 800, color: 'var(--color-lava)', margin: 0 }}>
              Forensic Investigator Overview
            </h1>
            <span
              style={{
                fontSize: '0.72rem',
                fontWeight: 700,
                padding: '0.2rem 0.6rem',
                borderRadius: '4px',
                background: 'rgba(92, 128, 43, 0.14)',
                color: 'var(--color-algae)',
                border: '1px solid rgba(92, 128, 43, 0.35)',
              }}
            >
              ● LIVE CONSOLE
            </span>
          </div>
          <p style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', marginTop: '0.25rem' }}>
            High-integrity digital forensic telemetry and incident response status across verified modules.
          </p>
        </div>

        <div style={{ display: 'flex', gap: '0.6rem', flexWrap: 'wrap', alignItems: 'center' }}>
          {/* Target Selector */}
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', background: 'var(--bg-surface)', padding: '0.35rem 0.75rem', borderRadius: '6px', border: '1px solid var(--border-color)' }}>
            <span style={{ fontSize: '0.75rem', fontWeight: 600, color: 'var(--color-lava)' }}>Target:</span>
            <select
              value={selectedDeviceId || ''}
              onChange={(e) => onSelectTarget && onSelectTarget(e.target.value || null)}
              style={{
                background: '#FFFFFF',
                border: '1px solid var(--border-color)',
                color: 'var(--color-lava)',
                fontWeight: 600,
                fontSize: '0.78rem',
                padding: '0.25rem 0.5rem',
                borderRadius: '4px',
                cursor: 'pointer',
                outline: 'none',
              }}
            >
              <option value="">💻 Local Machine</option>
              {activeEndpoints.map((d) => (
                <option key={d.device_id} value={d.device_id}>
                  🛰️ {d.hostname || d.device_id} ({d.is_online ? 'ONLINE' : 'OFFLINE'})
                </option>
              ))}
            </select>
          </div>

          <button
            onClick={() => onNavigateTab && onNavigateTab('endpoints')}
            style={{
              background: 'rgba(139, 212, 232, 0.25)',
              border: '1px solid rgba(139, 212, 232, 0.6)',
              color: 'var(--color-lava)',
              borderRadius: '6px',
              padding: '0.5rem 0.9rem',
              fontSize: '0.8rem',
              fontWeight: 700,
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: '0.4rem',
            }}
          >
            <span>🛰️</span>
            <span>Endpoint Devices</span>
          </button>
          <button
            onClick={() => onNavigateTab && onNavigateTab('commands')}
            style={{
              background: 'rgba(139, 212, 232, 0.25)',
              border: '1px solid rgba(139, 212, 232, 0.6)',
              color: 'var(--color-lava)',
              borderRadius: '6px',
              padding: '0.5rem 0.9rem',
              fontSize: '0.8rem',
              fontWeight: 700,
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: '0.4rem',
            }}
          >
            <span>🔎</span>
            <span>Command Search</span>
          </button>

          <button
            onClick={() => onNavigateTab && onNavigateTab('script')}
            style={{
              background: '#FFFFFF',
              border: '1px solid var(--border-color)',
              color: 'var(--color-lava)',
              borderRadius: '6px',
              padding: '0.5rem 0.9rem',
              fontSize: '0.8rem',
              fontWeight: 600,
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: '0.4rem',
            }}
          >
            <span>📝</span>
            <span>Edit DSL Script</span>
          </button>

          <button
            onClick={() => onRunInvestigation && onRunInvestigation()}
            disabled={loading}
            style={{
              background: 'var(--color-lagoon)',
              border: '1px solid #72c7dc',
              color: 'var(--color-lava)',
              borderRadius: '6px',
              padding: '0.5rem 1.1rem',
              fontSize: '0.8rem',
              fontWeight: 800,
              cursor: loading ? 'not-allowed' : 'pointer',
              boxShadow: '0 2px 8px rgba(139, 212, 232, 0.45)',
            }}
          >
            {loading ? 'Collecting Evidence...' : '▶ Run Investigation'}
          </button>
        </div>
      </div>

      {/* Cards Grid */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: 'repeat(auto-fit, minmax(320px, 1fr))',
          gap: '1.25rem',
        }}
      >
        {cards.map((card) => (
          <div
            key={card.id}
            style={{
              background: 'var(--bg-card)',
              borderRadius: '10px',
              border: '1px solid var(--border-color)',
              padding: '1.25rem',
              display: 'flex',
              flexDirection: 'column',
              gap: '1rem',
              position: 'relative',
              overflow: 'hidden',
            }}
          >
            {/* Card Header */}
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                <span style={{ fontSize: '1.1rem' }}>{card.icon}</span>
                <h3
                  style={{
                    fontSize: '0.9rem',
                    fontWeight: 800,
                    letterSpacing: '0.05em',
                    color: 'var(--text-primary)',
                    margin: 0,
                  }}
                >
                  {card.title}
                </h3>
              </div>
              {card.badge && (
                <span
                  className="font-mono"
                  style={{
                    fontSize: '0.72rem',
                    padding: '0.15rem 0.5rem',
                    borderRadius: '4px',
                    background: 'rgba(56, 189, 248, 0.1)',
                    color: 'var(--accent-cyan)',
                    border: '1px solid rgba(56, 189, 248, 0.25)',
                  }}
                >
                  {card.badge}
                </span>
              )}
            </div>

            {/* Key-Value Items */}
            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.65rem' }}>
              {card.items.map((item, idx) => (
                <div
                  key={idx}
                  style={{
                    display: 'flex',
                    justifyContent: 'space-between',
                    alignItems: 'center',
                    padding: '0.45rem 0.6rem',
                    background: 'var(--bg-surface)',
                    borderRadius: '6px',
                    border: '1px solid var(--border-subtle)',
                  }}
                >
                  <span style={{ fontSize: '0.78rem', color: 'var(--text-secondary)' }}>
                    {item.label}
                  </span>
                  {item.isBadge ? (
                    <span
                      style={{
                        fontSize: '0.72rem',
                        fontWeight: 700,
                        padding: '0.15rem 0.5rem',
                        borderRadius: '4px',
                        background: item.badgeColor === 'var(--accent-rose)' ? 'rgba(197, 48, 48, 0.12)' : 'rgba(92, 128, 43, 0.14)',
                        color: item.badgeColor === 'var(--accent-rose)' ? '#C53030' : 'var(--color-algae)',
                        border: `1px solid ${item.badgeColor === 'var(--accent-rose)' ? 'rgba(197, 48, 48, 0.3)' : 'rgba(92, 128, 43, 0.35)'}`,
                      }}
                    >
                      {item.value}
                    </span>
                  ) : (
                    <span
                      className={item.isMono ? 'font-mono' : ''}
                      style={{
                        fontSize: '0.8rem',
                        fontWeight: 600,
                        color:
                          item.value === 'N/A' || item.value === 'No data collected'
                            ? 'var(--text-muted)'
                            : 'var(--text-primary)',
                      }}
                    >
                      {item.value}
                    </span>
                  )}
                </div>
              ))}
            </div>

            {/* Quick Action Footer */}
            {card.targetTab && onNavigateTab && (
              <div style={{ marginTop: 'auto', paddingTop: '0.4rem', borderTop: '1px solid var(--border-subtle)' }}>
                <button
                  onClick={() => onNavigateTab(card.targetTab)}
                  style={{
                    width: '100%',
                    background: 'transparent',
                    border: 'none',
                    color: 'var(--accent-cyan)',
                    fontSize: '0.76rem',
                    fontWeight: 700,
                    padding: '0.3rem 0',
                    cursor: 'pointer',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                  }}
                >
                  <span>{card.actionLabel}</span>
                  <span>→</span>
                </button>
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}
