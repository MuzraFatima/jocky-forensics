import React, { useState, useMemo } from 'react';

// Exact 11 supported JOCKY DSL commands
export const SUPPORTED_COMMANDS = [
  {
    id: 'collect_system',
    name: 'COLLECT SYSTEM',
    category: 'Collection',
    description: 'Collect system and host information.',
    syntax: 'COLLECT SYSTEM',
  },
  {
    id: 'collect_processes',
    name: 'COLLECT PROCESSES',
    category: 'Collection',
    description: 'Collect process information from the target system.',
    syntax: 'COLLECT PROCESSES\n    WHERE status == RUNNING',
  },
  {
    id: 'collect_network',
    name: 'COLLECT NETWORK',
    category: 'Collection',
    description: 'Collect active network connection information.',
    syntax: 'COLLECT NETWORK\n    WHERE state == ESTABLISHED',
  },
  {
    id: 'collect_files',
    name: 'COLLECT FILES',
    category: 'Collection',
    description: 'Collect file evidence from the configured evidence location.',
    syntax: 'COLLECT FILES "evidence"',
  },
  {
    id: 'collect_users',
    name: 'COLLECT USERS',
    category: 'Collection',
    description: 'Collect local user information.',
    syntax: 'COLLECT USERS',
  },
  {
    id: 'collect_registry',
    name: 'COLLECT REGISTRY',
    category: 'Collection',
    description: 'Collect supported Windows registry metadata.',
    syntax: 'COLLECT REGISTRY',
  },
  {
    id: 'analyze_process_network',
    name: 'ANALYZE PROCESS_NETWORK',
    category: 'Analysis',
    description: 'Correlate process activity with network activity.',
    syntax: 'ANALYZE PROCESS_NETWORK',
  },
  {
    id: 'verify_integrity',
    name: 'VERIFY INTEGRITY',
    category: 'Integrity',
    description: 'Verify evidence integrity using cryptographic hashes.',
    syntax: 'VERIFY INTEGRITY',
  },
  {
    id: 'report_json',
    name: 'REPORT FORMAT JSON',
    category: 'Reporting',
    description: 'Generate a JSON forensic report.',
    syntax: 'REPORT FORMAT JSON',
  },
  {
    id: 'report_markdown',
    name: 'REPORT FORMAT MARKDOWN',
    category: 'Reporting',
    description: 'Generate a Markdown forensic report.',
    syntax: 'REPORT FORMAT MARKDOWN',
  },
  {
    id: 'report_html',
    name: 'REPORT FORMAT HTML',
    category: 'Reporting',
    description: 'Generate an HTML forensic report.',
    syntax: 'REPORT FORMAT HTML',
  },
];

export const CATEGORY_COLORS = {
  Collection: {
    bg: 'rgba(56, 189, 248, 0.12)',
    text: '#38bdf8',
    border: 'rgba(56, 189, 248, 0.3)',
  },
  Analysis: {
    bg: 'rgba(99, 102, 241, 0.12)',
    text: '#818cf8',
    border: 'rgba(99, 102, 241, 0.3)',
  },
  Integrity: {
    bg: 'rgba(16, 185, 129, 0.12)',
    text: '#34d399',
    border: 'rgba(16, 185, 129, 0.3)',
  },
  Reporting: {
    bg: 'rgba(245, 158, 11, 0.12)',
    text: '#fbbf24',
    border: 'rgba(245, 158, 11, 0.3)',
  },
};

export default function CommandSearch({ onInsertCommand, isCompact = false, onCloseModal = null }) {
  const [query, setQuery] = useState('');
  const [selectedCategory, setSelectedCategory] = useState('ALL');
  const [copiedId, setCopiedId] = useState(null);
  const [insertedId, setInsertedId] = useState(null);

  const categories = ['ALL', 'Collection', 'Analysis', 'Integrity', 'Reporting'];

  const filteredCommands = useMemo(() => {
    const q = query.trim().toLowerCase();
    return SUPPORTED_COMMANDS.filter((cmd) => {
      const matchCategory = selectedCategory === 'ALL' || cmd.category === selectedCategory;
      const matchQuery =
        !q ||
        cmd.name.toLowerCase().includes(q) ||
        cmd.description.toLowerCase().includes(q) ||
        cmd.syntax.toLowerCase().includes(q);
      return matchCategory && matchQuery;
    });
  }, [query, selectedCategory]);

  const handleCopy = (cmd) => {
    if (navigator?.clipboard?.writeText) {
      navigator.clipboard.writeText(cmd.syntax);
      setCopiedId(cmd.id);
      setTimeout(() => setCopiedId(null), 1800);
    }
  };

  const handleInsert = (cmd) => {
    if (onInsertCommand) {
      onInsertCommand(cmd.syntax);
      setInsertedId(cmd.id);
      setTimeout(() => setInsertedId(null), 1800);
      if (onCloseModal) {
        setTimeout(() => onCloseModal(), 400);
      }
    }
  };

  return (
    <div
      style={{
        display: 'flex',
        flexDirection: 'column',
        gap: '1.25rem',
        background: isCompact ? 'transparent' : 'var(--bg-card)',
        borderRadius: isCompact ? 0 : '12px',
        border: isCompact ? 'none' : '1px solid var(--border-color)',
        padding: isCompact ? '0.5rem 0' : '1.5rem',
      }}
    >
      {/* Header bar */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexWrap: 'wrap', gap: '0.75rem' }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.6rem' }}>
            <span style={{ fontSize: '1.2rem' }}>🔎</span>
            <h2 style={{ fontSize: isCompact ? '1.1rem' : '1.25rem', fontWeight: 800, color: 'var(--text-primary)', margin: 0 }}>
              JOCKY Command Search
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
              DSL Specification
            </span>
          </div>
          <p style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', marginTop: '0.25rem' }}>
            Browse and filter verified JOCKY forensic DSL commands. Insert directly into your investigation script.
          </p>
        </div>

        {onCloseModal && (
          <button
            onClick={onCloseModal}
            style={{
              background: 'rgba(255, 255, 255, 0.05)',
              border: '1px solid var(--border-subtle)',
              color: 'var(--text-secondary)',
              borderRadius: '6px',
              padding: '0.35rem 0.75rem',
              fontSize: '0.8rem',
              cursor: 'pointer',
            }}
          >
            ✕ Close
          </button>
        )}
      </div>

      {/* Search Input Bar */}
      <div style={{ display: 'flex', gap: '0.75rem', alignItems: 'center', flexWrap: 'wrap' }}>
        <div style={{ position: 'relative', flex: 1, minWidth: '260px' }}>
          <span
            style={{
              position: 'absolute',
              left: '0.9rem',
              top: '50%',
              transform: 'translateY(-50%)',
              color: 'var(--text-muted)',
              fontSize: '0.9rem',
              pointerEvents: 'none',
            }}
          >
            🔍
          </span>
          <input
            type="text"
            placeholder="Search JOCKY commands..."
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            style={{
              width: '100%',
              background: '#04070d',
              border: '1px solid var(--border-color)',
              borderRadius: '8px',
              padding: '0.65rem 1rem 0.65rem 2.4rem',
              color: 'var(--text-primary)',
              fontSize: '0.88rem',
              transition: 'border-color 0.2s',
            }}
          />
          {query && (
            <button
              onClick={() => setQuery('')}
              style={{
                position: 'absolute',
                right: '0.75rem',
                top: '50%',
                transform: 'translateY(-50%)',
                background: 'none',
                border: 'none',
                color: 'var(--text-muted)',
                cursor: 'pointer',
                fontSize: '0.85rem',
              }}
            >
              ✕
            </button>
          )}
        </div>

        {/* Category Pills */}
        <div style={{ display: 'flex', gap: '0.4rem', flexWrap: 'wrap' }}>
          {categories.map((cat) => {
            const isSel = selectedCategory === cat;
            const count =
              cat === 'ALL'
                ? SUPPORTED_COMMANDS.length
                : SUPPORTED_COMMANDS.filter((c) => c.category === cat).length;
            const styleConf = CATEGORY_COLORS[cat] || {
              bg: 'rgba(255, 255, 255, 0.05)',
              text: 'var(--text-secondary)',
              border: 'var(--border-subtle)',
            };

            return (
              <button
                key={cat}
                onClick={() => setSelectedCategory(cat)}
                style={{
                  background: isSel ? 'rgba(56, 189, 248, 0.2)' : 'rgba(15, 23, 42, 0.6)',
                  border: isSel ? '1px solid var(--accent-cyan)' : '1px solid var(--border-subtle)',
                  color: isSel ? 'var(--accent-cyan)' : 'var(--text-secondary)',
                  borderRadius: '6px',
                  padding: '0.4rem 0.75rem',
                  fontSize: '0.75rem',
                  fontWeight: 700,
                  cursor: 'pointer',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '0.35rem',
                }}
              >
                <span>{cat}</span>
                <span
                  style={{
                    fontSize: '0.68rem',
                    background: 'rgba(0, 0, 0, 0.3)',
                    padding: '0.1rem 0.35rem',
                    borderRadius: '4px',
                    color: isSel ? 'var(--accent-cyan)' : 'var(--text-muted)',
                  }}
                >
                  {count}
                </span>
              </button>
            );
          })}
        </div>
      </div>

      {/* Filter status / count */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: '0.75rem', color: 'var(--text-muted)' }}>
        <span>Showing {filteredCommands.length} of {SUPPORTED_COMMANDS.length} verified commands</span>
        {query && <span>Filtered by keyword &ldquo;{query}&rdquo;</span>}
      </div>

      {/* Commands Grid */}
      <div
        style={{
          display: 'grid',
          gridTemplateColumns: isCompact ? '1fr' : 'repeat(auto-fill, minmax(360px, 1fr))',
          gap: '1rem',
        }}
      >
        {filteredCommands.length === 0 ? (
          <div
            style={{
              gridColumn: '1 / -1',
              padding: '2.5rem',
              textAlign: 'center',
              background: 'rgba(10, 15, 26, 0.5)',
              borderRadius: '8px',
              border: '1px dashed var(--border-subtle)',
              color: 'var(--text-muted)',
            }}
          >
            No supported JOCKY commands match &ldquo;{query}&rdquo;.
            <div style={{ marginTop: '0.5rem', fontSize: '0.75rem' }}>
              Supported modules: SYSTEM, PROCESSES, NETWORK, FILES, USERS, REGISTRY, PROCESS_NETWORK, INTEGRITY, REPORT.
            </div>
          </div>
        ) : (
          filteredCommands.map((cmd) => {
            const catStyle = CATEGORY_COLORS[cmd.category] || {};
            const isCopied = copiedId === cmd.id;
            const isInserted = insertedId === cmd.id;

            return (
              <div
                key={cmd.id}
                style={{
                  background: 'rgba(10, 15, 26, 0.75)',
                  border: '1px solid var(--border-color)',
                  borderRadius: '10px',
                  padding: '1.1rem',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '0.75rem',
                  transition: 'border-color 0.2s, transform 0.15s',
                }}
              >
                {/* Card Header */}
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: '0.5rem' }}>
                  <div className="font-mono" style={{ fontSize: '0.92rem', fontWeight: 800, color: 'var(--text-primary)' }}>
                    {cmd.name}
                  </div>
                  <span
                    style={{
                      fontSize: '0.68rem',
                      fontWeight: 700,
                      padding: '0.15rem 0.5rem',
                      borderRadius: '4px',
                      background: catStyle.bg,
                      color: catStyle.text,
                      border: `1px solid ${catStyle.border}`,
                      textTransform: 'uppercase',
                      letterSpacing: '0.04em',
                      whiteSpace: 'nowrap',
                    }}
                  >
                    {cmd.category}
                  </span>
                </div>

                {/* Description */}
                <p style={{ fontSize: '0.8rem', color: 'var(--text-secondary)', margin: 0, lineHeight: 1.45, minHeight: '2.4rem' }}>
                  {cmd.description}
                </p>

                {/* Syntax Box */}
                <div>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '0.3rem' }}>
                    <span style={{ fontSize: '0.68rem', color: 'var(--text-muted)', textTransform: 'uppercase', fontWeight: 700 }}>
                      Example Syntax
                    </span>
                    <button
                      onClick={() => handleCopy(cmd)}
                      title="Copy syntax"
                      style={{
                        background: 'transparent',
                        border: 'none',
                        color: isCopied ? 'var(--accent-emerald)' : 'var(--text-muted)',
                        fontSize: '0.72rem',
                        cursor: 'pointer',
                        padding: '0 0.25rem',
                      }}
                    >
                      {isCopied ? '✓ Copied' : 'Copy'}
                    </button>
                  </div>
                  <pre
                    className="font-mono"
                    style={{
                      margin: 0,
                      padding: '0.55rem 0.75rem',
                      background: '#04070d',
                      border: '1px solid var(--border-subtle)',
                      borderRadius: '6px',
                      color: 'var(--accent-cyan)',
                      fontSize: '0.76rem',
                      lineHeight: 1.4,
                      overflowX: 'auto',
                      whiteSpace: 'pre-wrap',
                    }}
                  >
                    {cmd.syntax}
                  </pre>
                </div>

                {/* Actions */}
                <div style={{ marginTop: 'auto', paddingTop: '0.5rem', display: 'flex', gap: '0.5rem' }}>
                  <button
                    onClick={() => handleInsert(cmd)}
                    style={{
                      flex: 1,
                      background: isInserted
                        ? 'rgba(16, 185, 129, 0.2)'
                        : 'linear-gradient(135deg, rgba(14, 165, 233, 0.2), rgba(99, 102, 241, 0.2))',
                      border: isInserted ? '1px solid var(--accent-emerald)' : '1px solid rgba(56, 189, 248, 0.4)',
                      color: isInserted ? 'var(--accent-emerald)' : 'var(--text-primary)',
                      borderRadius: '6px',
                      padding: '0.45rem 0.8rem',
                      fontSize: '0.78rem',
                      fontWeight: 700,
                      cursor: 'pointer',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                      gap: '0.4rem',
                      transition: 'all 0.15s ease',
                    }}
                  >
                    <span>{isInserted ? '✓ Inserted' : '+ Insert into Script'}</span>
                  </button>
                </div>
              </div>
            );
          })
        )}
      </div>
    </div>
  );
}
