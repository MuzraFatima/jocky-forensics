import React, { useState } from 'react';

// Icons designed for JOCKY Forensics Navigation
function OverviewIcon({ size = 18 }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <rect x="3" y="3" width="7" height="9" rx="1" />
      <rect x="14" y="3" width="7" height="5" rx="1" />
      <rect x="14" y="12" width="7" height="9" rx="1" />
      <rect x="3" y="16" width="7" height="5" rx="1" />
    </svg>
  );
}

function SupportIcon({ size = 18 }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
      <path d="M9 12h6" />
      <path d="M12 9v6" />
    </svg>
  );
}

function CorrelationIcon({ size = 18 }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="18" cy="5" r="3" />
      <circle cx="6" cy="12" r="3" />
      <circle cx="18" cy="19" r="3" />
      <line x1="8.59" y1="13.51" x2="15.42" y2="17.49" />
      <line x1="15.41" y1="6.51" x2="8.59" y2="10.49" />
    </svg>
  );
}

function TimelineIcon({ size = 18 }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="12" cy="12" r="10" />
      <polyline points="12 6 12 12 16 14" />
    </svg>
  );
}

function SystemIcon({ size = 18 }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <rect x="2" y="2" width="20" height="8" rx="2" ry="2" />
      <rect x="2" y="14" width="20" height="8" rx="2" ry="2" />
      <line x1="6" y1="6" x2="6.01" y2="6"/>
      <line x1="6" y1="18" x2="6.01" y2="18"/>
    </svg>
  );
}

function ProcessesIcon({ size = 18 }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <rect x="4" y="4" width="16" height="16" rx="2" />
      <rect x="9" y="9" width="6" height="6" />
      <line x1="9" y1="1" x2="9" y2="4" />
      <line x1="15" y1="1" x2="15" y2="4" />
      <line x1="9" y1="20" x2="9" y2="23" />
      <line x1="15" y1="20" x2="15" y2="23" />
      <line x1="20" y1="9" x2="23" y2="9" />
      <line x1="20" y1="14" x2="23" y2="14" />
      <line x1="1" y1="9" x2="4" y2="9" />
      <line x1="1" y1="14" x2="4" y2="14" />
    </svg>
  );
}

function NetworkIcon({ size = 18 }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="12" cy="12" r="10" />
      <line x1="2" y1="12" x2="22" y2="12" />
      <path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z" />
    </svg>
  );
}

function FilesIcon({ size = 18 }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M22 19a2 2 0 0 1-2 2H4a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h5l2 3h9a2 2 0 0 1 2 2z" />
    </svg>
  );
}

function UsersIcon({ size = 18 }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2" />
      <circle cx="9" cy="7" r="4" />
      <path d="M23 21v-2a4 4 0 0 0-3-3.87" />
      <path d="M16 3.13a4 4 0 0 1 0 7.75" />
    </svg>
  );
}

function PersistenceIcon({ isLinux = false, size = 18 }) {
  if (isLinux) {
    return (
      <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
        <path d="M12 2a5 5 0 0 0-5 5v3a5 5 0 0 0 10 0V7a5 5 0 0 0-5-5z" />
        <path d="M7 13c-2 1-3 3-3 5a3 3 0 0 0 3 3h10a3 3 0 0 0 3-3c0-2-1-4-3-5" />
        <circle cx="10" cy="7" r="1" fill="currentColor" />
        <circle cx="14" cy="7" r="1" fill="currentColor" />
      </svg>
    );
  }
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M3 4l8-1v8H3V4z" />
      <path d="M13 2.8l8-1.2v9.4h-8V2.8z" />
      <path d="M3 13h8v8l-8-1v-7z" />
      <path d="M13 13h8v9.4l-8-1.2V13z" />
    </svg>
  );
}

function EvidenceIcon({ size = 18 }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <rect x="3" y="11" width="18" height="11" rx="2" ry="2" />
      <path d="M7 11V7a5 5 0 0 1 10 0v4" />
      <circle cx="12" cy="16" r="1" fill="currentColor" />
    </svg>
  );
}

function ReportsIcon({ size = 18 }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z" />
      <polyline points="14 2 14 8 20 8" />
      <line x1="16" y1="13" x2="8" y2="13" />
      <line x1="16" y1="17" x2="8" y2="17" />
      <polyline points="10 9 9 9 8 9" />
    </svg>
  );
}

function ExecuteIcon({ size = 18 }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <polygon points="13 2 3 14 12 14 11 22 21 10 12 10 13 2" />
    </svg>
  );
}

function ScriptIcon({ size = 18 }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <polyline points="16 18 22 12 16 6" />
      <polyline points="8 6 2 12 8 18" />
    </svg>
  );
}

function SearchIcon({ size = 18 }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <circle cx="11" cy="11" r="8" />
      <line x1="21" y1="21" x2="16.65" y2="16.65" />
    </svg>
  );
}

// Panel Collapse / Expand Icon
function PanelToggleIcon({ collapsed = false, size = 18 }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
      <rect x="3" y="3" width="18" height="18" rx="2" ry="2" />
      <line x1="9" y1="3" x2="9" y2="21" />
      {collapsed ? (
        <path d="m14 15 3-3-3-3" />
      ) : (
        <path d="m15 9-3 3 3 3" />
      )}
    </svg>
  );
}

export default function Sidebar({
  activeTab,
  onSelectTab,
  collapsed,
  onToggleCollapse,
  mobileOpen,
  onCloseMobile,
  platformInfo,
  counts = {},
  session,
  onOpenLogout,
  analystStatus = 'ONLINE',
}) {
  const [hoveredTab, setHoveredTab] = useState(null);
  const [tooltipPos, setTooltipPos] = useState({ top: 0, left: 0 });

  const navItems = [
    {
      id: 'overview',
      label: 'Overview & Analysis',
      icon: (props) => <OverviewIcon {...props} />,
    },
    {
      id: 'support',
      label: 'Cybersecurity Support',
      icon: (props) => <SupportIcon {...props} />,
      statusBadge: analystStatus === 'ONLINE' ? '● ON' : '○ OFF',
      accentColor: 'var(--accent-indigo)',
    },
    {
      id: 'correlation',
      label: 'Correlation Graph',
      icon: (props) => <CorrelationIcon {...props} />,
      count: counts.correlation,
    },
    {
      id: 'timeline',
      label: 'Forensic Timeline',
      icon: (props) => <TimelineIcon {...props} />,
      count: counts.timeline,
    },
    {
      id: 'system',
      label: 'System Telemetry',
      icon: (props) => <SystemIcon {...props} />,
    },
    {
      id: 'processes',
      label: 'Active Processes',
      icon: (props) => <ProcessesIcon {...props} />,
      count: counts.processes,
    },
    {
      id: 'network',
      label: 'Network Sockets',
      icon: (props) => <NetworkIcon {...props} />,
      count: counts.network,
    },
    {
      id: 'files',
      label: 'Files & Binaries',
      icon: (props) => <FilesIcon {...props} />,
      count: counts.files,
    },
    {
      id: 'users',
      label: 'Users & Sessions',
      icon: (props) => <UsersIcon {...props} />,
      count: counts.users,
    },
    {
      id: 'windows',
      label: platformInfo?.is_linux ? 'Linux Persistence' : 'Windows Persistence',
      icon: (props) => <PersistenceIcon isLinux={platformInfo?.is_linux} {...props} />,
    },
    {
      id: 'evidence',
      label: 'Evidence Vault',
      icon: (props) => <EvidenceIcon {...props} />,
      count: counts.evidence,
    },
    {
      id: 'reports',
      label: 'Forensic Reports',
      icon: (props) => <ReportsIcon {...props} />,
    },
    {
      id: 'execute',
      label: 'Execution Engine',
      icon: (props) => <ExecuteIcon {...props} />,
    },
    {
      id: 'script',
      label: 'JOCKY Script Editor',
      icon: (props) => <ScriptIcon {...props} />,
    },
    {
      id: 'commands',
      label: 'Command Search',
      icon: (props) => <SearchIcon {...props} />,
      statusBadge: 'DSL',
    },
  ];

  const handleMouseEnter = (e, item) => {
    if (collapsed) {
      const rect = e.currentTarget.getBoundingClientRect();
      setTooltipPos({
        top: rect.top + rect.height / 2,
        left: rect.right + 10,
      });
      setHoveredTab(item);
    }
  };

  const handleMouseLeave = () => {
    setHoveredTab(null);
  };

  return (
    <>
      {/* Mobile Backdrop */}
      {mobileOpen && (
        <div
          className="sidebar-backdrop"
          onClick={onCloseMobile}
          aria-label="Close sidebar"
        />
      )}

      {/* Fixed Left Sidebar Container */}
      <aside
        className={`sidebar-container ${collapsed ? 'sidebar-collapsed' : 'sidebar-expanded'} ${mobileOpen ? 'mobile-open' : ''}`}
        style={{
          width: collapsed ? '68px' : '260px',
        }}
        aria-label="Forensics navigation sidebar"
      >
        {/* Branding & Top Actions */}
        <div
          style={{
            padding: collapsed ? '1.1rem 0.6rem 0.9rem' : '1.1rem 1rem 0.9rem',
            borderBottom: '1px solid var(--border-color)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: collapsed ? 'center' : 'space-between',
            gap: '0.6rem',
            flexShrink: 0,
          }}
        >
          {/* Logo Badge & Title */}
          <div
            onClick={() => onSelectTab('overview')}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '0.75rem',
              cursor: 'pointer',
              minWidth: 0,
              textDecoration: 'none',
            }}
            title="JOCKY FORENSICS - Overview"
          >
            <div
              style={{
                width: '36px',
                height: '36px',
                minWidth: '36px',
                borderRadius: '9px',
                background: 'linear-gradient(135deg, #0ea5e9, #6366f1)',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                fontWeight: 800,
                fontSize: '18px',
                color: '#fff',
                boxShadow: '0 0 16px rgba(14, 165, 233, 0.4)',
              }}
            >
              J
            </div>

            {!collapsed && (
              <div style={{ overflow: 'hidden', whiteSpace: 'nowrap' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem' }}>
                  <span
                    style={{
                      fontSize: '0.98rem',
                      fontWeight: 800,
                      letterSpacing: '-0.02em',
                      color: '#fff',
                    }}
                  >
                    JOCKY
                  </span>
                  <span
                    style={{
                      fontSize: '0.6rem',
                      fontWeight: 700,
                      color: 'var(--accent-cyan)',
                      background: 'rgba(56, 189, 248, 0.1)',
                      border: '1px solid rgba(56, 189, 248, 0.25)',
                      padding: '0.1rem 0.35rem',
                      borderRadius: '4px',
                      letterSpacing: '0.04em',
                    }}
                  >
                    SIH26148
                  </span>
                </div>
                <div
                  style={{
                    fontSize: '0.68rem',
                    color: 'var(--text-muted)',
                    letterSpacing: '0.04em',
                    textTransform: 'uppercase',
                    fontWeight: 600,
                    marginTop: '0.1rem',
                  }}
                >
                  Forensics Suite
                </div>
              </div>
            )}
          </div>

          {/* Collapse/Expand Toggle Button */}
          {!collapsed && (
            <button
              onClick={onToggleCollapse}
              title="Collapse sidebar"
              aria-label="Collapse sidebar"
              style={{
                background: 'rgba(255, 255, 255, 0.03)',
                border: '1px solid var(--border-subtle)',
                borderRadius: '6px',
                color: 'var(--text-secondary)',
                width: '28px',
                height: '28px',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                padding: 0,
                cursor: 'pointer',
                flexShrink: 0,
              }}
              onMouseEnter={(e) => {
                e.currentTarget.style.color = '#fff';
                e.currentTarget.style.borderColor = 'var(--accent-cyan)';
              }}
              onMouseLeave={(e) => {
                e.currentTarget.style.color = 'var(--text-secondary)';
                e.currentTarget.style.borderColor = 'var(--border-subtle)';
              }}
            >
              <PanelToggleIcon collapsed={false} size={16} />
            </button>
          )}
        </div>

        {/* In Collapsed mode, render expand button right below logo */}
        {collapsed && (
          <div
            style={{
              display: 'flex',
              justifyContent: 'center',
              padding: '0.5rem 0',
              borderBottom: '1px solid var(--border-subtle)',
            }}
          >
            <button
              onClick={onToggleCollapse}
              title="Expand sidebar"
              aria-label="Expand sidebar"
              style={{
                background: 'rgba(255, 255, 255, 0.04)',
                border: '1px solid var(--border-subtle)',
                borderRadius: '6px',
                color: 'var(--text-secondary)',
                width: '32px',
                height: '32px',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
                cursor: 'pointer',
              }}
              onMouseEnter={(e) => {
                e.currentTarget.style.color = '#fff';
                e.currentTarget.style.borderColor = 'var(--accent-cyan)';
              }}
              onMouseLeave={(e) => {
                e.currentTarget.style.color = 'var(--text-secondary)';
                e.currentTarget.style.borderColor = 'var(--border-subtle)';
              }}
            >
              <PanelToggleIcon collapsed={true} size={16} />
            </button>
          </div>
        )}

        {/* Scrollable Navigation List */}
        <nav className="sidebar-scrollable" role="navigation">
          {!collapsed && (
            <div
              style={{
                fontSize: '0.65rem',
                fontWeight: 700,
                color: 'var(--text-muted)',
                textTransform: 'uppercase',
                letterSpacing: '0.08em',
                padding: '0.35rem 0.65rem',
              }}
            >
              Forensic Modules
            </div>
          )}

          {navItems.map((item) => {
            const isActive = activeTab === item.id;
            return (
              <button
                key={item.id}
                id={`sidebar-nav-${item.id}`}
                onClick={() => onSelectTab(item.id)}
                onMouseEnter={(e) => handleMouseEnter(e, item)}
                onMouseLeave={handleMouseLeave}
                className={`sidebar-nav-btn ${isActive ? 'active' : ''} ${collapsed ? 'collapsed' : ''}`}
                title={collapsed ? `${item.label}${item.count != null ? ` (${item.count})` : ''}` : undefined}
                aria-current={isActive ? 'page' : undefined}
                style={{
                  borderLeft: isActive ? (item.id === 'support' ? '3px solid var(--accent-indigo)' : '3px solid var(--accent-cyan)') : 'none',
                }}
              >
                {/* Icon */}
                <span
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    color: isActive ? (item.id === 'support' ? 'var(--accent-indigo)' : 'var(--accent-cyan)') : 'inherit',
                    minWidth: '20px',
                    transition: 'color 0.16s ease',
                  }}
                >
                  {item.icon({ size: 18 })}
                </span>

                {/* Text Label & Badge (when expanded) */}
                {!collapsed && (
                  <>
                    <span
                      style={{
                        whiteSpace: 'nowrap',
                        overflow: 'hidden',
                        textOverflow: 'ellipsis',
                        flex: 1,
                      }}
                    >
                      {item.label}
                    </span>

                    {item.statusBadge && (
                      <span
                        style={{
                          fontSize: '0.65rem',
                          fontWeight: 700,
                          padding: '0.1rem 0.4rem',
                          borderRadius: '4px',
                          background: item.statusBadge.includes('ON') ? 'rgba(16, 185, 129, 0.15)' : 'rgba(245, 158, 11, 0.15)',
                          color: item.statusBadge.includes('ON') ? 'var(--accent-emerald)' : 'var(--accent-amber)',
                          fontFamily: 'monospace',
                        }}
                      >
                        {item.statusBadge}
                      </span>
                    )}

                    {item.count != null && (
                      <span className={isActive ? 'sidebar-badge' : 'sidebar-badge-muted'}>
                        {item.count}
                      </span>
                    )}
                  </>
                )}
              </button>
            );
          })}
        </nav>

        {/* Bottom Sidebar Status / Investigator Session / Logout */}
        <div
          style={{
            padding: collapsed ? '0.75rem 0.4rem' : '0.85rem 1rem',
            borderTop: '1px solid var(--border-color)',
            background: 'rgba(6, 9, 15, 0.6)',
            flexShrink: 0,
            display: 'flex',
            flexDirection: 'column',
            gap: '0.6rem',
            alignItems: collapsed ? 'center' : 'stretch',
          }}
        >
          {!collapsed ? (
            <>
              {/* Investigator Identity Card */}
              {session && (
                <div style={{
                  display: 'flex',
                  alignItems: 'center',
                  gap: '0.5rem',
                  padding: '0.35rem 0.5rem',
                  background: 'rgba(255, 255, 255, 0.02)',
                  border: '1px solid var(--border-subtle)',
                  borderRadius: '6px',
                }}>
                  <div style={{
                    width: '24px',
                    height: '24px',
                    borderRadius: '50%',
                    background: 'rgba(56, 189, 248, 0.15)',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'center',
                    fontSize: '0.7rem',
                    color: 'var(--accent-cyan)',
                    fontWeight: 700,
                  }}>
                    👤
                  </div>
                  <div style={{ overflow: 'hidden', flex: 1 }}>
                    <div style={{ fontSize: '0.72rem', fontWeight: 600, color: '#fff', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                      {session.username?.split('@')[0] || 'Investigator'}
                    </div>
                    <div style={{ fontSize: '0.65rem', color: 'var(--text-muted)' }}>
                      {session.role || 'Forensic Examiner'}
                    </div>
                  </div>
                </div>
              )}

              {/* Status & Logout Button Row */}
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', fontSize: '0.7rem' }}>
                  <span
                    style={{
                      width: '6px',
                      height: '6px',
                      borderRadius: '50%',
                      backgroundColor: 'var(--accent-emerald)',
                    }}
                  />
                  <span style={{ fontWeight: 600, color: 'var(--accent-emerald)' }}>READ-ONLY</span>
                </div>

                {onOpenLogout && (
                  <button
                    type="button"
                    onClick={onOpenLogout}
                    title="End Investigation Session"
                    style={{
                      background: 'rgba(244, 63, 94, 0.08)',
                      border: '1px solid rgba(244, 63, 94, 0.25)',
                      borderRadius: '4px',
                      color: '#fda4af',
                      fontSize: '0.7rem',
                      fontWeight: 600,
                      padding: '0.2rem 0.55rem',
                      cursor: 'pointer',
                      display: 'flex',
                      alignItems: 'center',
                      gap: '0.3rem',
                    }}
                    onMouseEnter={(e) => {
                      e.currentTarget.style.background = 'rgba(244, 63, 94, 0.2)';
                    }}
                    onMouseLeave={(e) => {
                      e.currentTarget.style.background = 'rgba(244, 63, 94, 0.08)';
                    }}
                  >
                    <span>⎋</span> Logout
                  </button>
                )}
              </div>
            </>
          ) : (
            /* Collapsed mode logout icon */
            <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: '0.5rem' }}>
              <div
                title="Authorized Read-Only Mode"
                style={{
                  width: '8px',
                  height: '8px',
                  borderRadius: '50%',
                  backgroundColor: 'var(--accent-emerald)',
                  boxShadow: '0 0 8px rgba(16, 185, 129, 0.6)',
                }}
              />
              {onOpenLogout && (
                <button
                  type="button"
                  onClick={onOpenLogout}
                  title="Logout Session"
                  style={{
                    background: 'none',
                    border: 'none',
                    color: 'var(--accent-rose)',
                    fontSize: '1rem',
                    cursor: 'pointer',
                    padding: '0.2rem',
                  }}
                >
                  ⎋
                </button>
              )}
            </div>
          )}
        </div>
      </aside>

      {/* Floating Tooltip in Collapsed Mode */}
      {collapsed && hoveredTab && (
        <div
          className="sidebar-tooltip"
          style={{
            top: `${tooltipPos.top}px`,
            left: `${tooltipPos.left}px`,
          }}
          role="tooltip"
        >
          <span>{hoveredTab.label}</span>
          {hoveredTab.statusBadge && (
            <span
              style={{
                fontSize: '0.65rem',
                padding: '0.1rem 0.35rem',
                borderRadius: '4px',
                background: hoveredTab.statusBadge.includes('ON') ? 'rgba(16, 185, 129, 0.2)' : 'rgba(245, 158, 11, 0.2)',
                color: hoveredTab.statusBadge.includes('ON') ? 'var(--accent-emerald)' : 'var(--accent-amber)',
                fontWeight: 700,
              }}
            >
              {hoveredTab.statusBadge}
            </span>
          )}
          {hoveredTab.count != null && (
            <span
              style={{
                fontSize: '0.68rem',
                padding: '0.1rem 0.4rem',
                borderRadius: '999px',
                background: 'rgba(56, 189, 248, 0.2)',
                color: 'var(--accent-cyan)',
                fontFamily: 'monospace',
                fontWeight: 700,
              }}
            >
              {hoveredTab.count}
            </span>
          )}
        </div>
      )}
    </>
  );
}
