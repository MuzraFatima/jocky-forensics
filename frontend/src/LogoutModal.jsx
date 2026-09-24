import React from 'react';

export default function LogoutModal({
  isOpen,
  onClose,
  onLogoutWithoutSending,
  onGenerateAndSend,
}) {
  if (!isOpen) return null;

  return (
    <div style={{
      position: 'fixed',
      inset: 0,
      background: 'rgba(4, 7, 14, 0.85)',
      backdropFilter: 'blur(8px)',
      zIndex: 2000,
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      padding: '1.5rem',
    }}>
      <div style={{
        width: '100%',
        maxWidth: '480px',
        background: '#0d1322',
        border: '1px solid var(--border-color)',
        borderRadius: '14px',
        padding: '2rem',
        boxShadow: '0 25px 60px rgba(0, 0, 0, 0.8), 0 0 30px rgba(244, 63, 94, 0.15)',
      }}>
        {/* Header */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '1rem' }}>
          <div style={{
            width: '40px',
            height: '40px',
            borderRadius: '10px',
            background: 'rgba(244, 63, 94, 0.15)',
            border: '1px solid rgba(244, 63, 94, 0.35)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            fontSize: '1.2rem',
            color: 'var(--accent-rose)',
          }}>
            ⎋
          </div>
          <div>
            <h3 style={{ fontSize: '1.2rem', fontWeight: 800, color: '#fff', letterSpacing: '-0.01em' }}>
              End Investigation Session?
            </h3>
            <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)' }}>
              Authorized JOCKY Forensic Workspace
            </p>
          </div>
        </div>

        {/* Informational Body */}
        <p style={{
          fontSize: '0.82rem',
          color: 'var(--text-secondary)',
          lineHeight: 1.5,
          marginBottom: '1.5rem',
          background: 'rgba(255, 255, 255, 0.02)',
          padding: '0.85rem 1rem',
          borderRadius: '8px',
          border: '1px solid var(--border-subtle)',
        }}>
          Closing your session will revoke active authorization tokens. You can optionally seal and dispatch the current case evidence report to the centralized security incident queue before exiting.
        </p>

        {/* Buttons Stack */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: '0.75rem' }}>
          {/* Option 1: Generate & Send Report */}
          <button
            type="button"
            onClick={onGenerateAndSend}
            style={{
              padding: '0.75rem 1.25rem',
              borderRadius: '8px',
              border: 'none',
              background: 'linear-gradient(135deg, #0ea5e9, #6366f1)',
              color: '#fff',
              fontSize: '0.85rem',
              fontWeight: 700,
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              gap: '0.5rem',
              boxShadow: '0 4px 15px rgba(14, 165, 233, 0.3)',
            }}
          >
            📄 Generate &amp; Send Report (Recommended)
          </button>

          {/* Option 2: Logout Without Sending */}
          <button
            type="button"
            onClick={onLogoutWithoutSending}
            style={{
              padding: '0.7rem 1.25rem',
              borderRadius: '8px',
              border: '1px solid rgba(244, 63, 94, 0.4)',
              background: 'rgba(244, 63, 94, 0.08)',
              color: '#fda4af',
              fontSize: '0.82rem',
              fontWeight: 600,
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              gap: '0.5rem',
            }}
          >
            ⎋ Logout Without Sending
          </button>

          {/* Option 3: Cancel */}
          <button
            type="button"
            onClick={onClose}
            style={{
              padding: '0.65rem 1.25rem',
              borderRadius: '8px',
              border: '1px solid var(--border-subtle)',
              background: 'transparent',
              color: 'var(--text-secondary)',
              fontSize: '0.82rem',
              fontWeight: 600,
              cursor: 'pointer',
              textAlign: 'center',
            }}
          >
            Cancel (Stay in Application)
          </button>
        </div>
      </div>
    </div>
  );
}
