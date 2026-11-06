// JOCKY command catalogue shared by the editor and the command search screen.

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
