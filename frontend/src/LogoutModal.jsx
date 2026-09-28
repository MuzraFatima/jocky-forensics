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
      background: 'rgba(34, 36, 38, 0.45)',
      backdropFilter: 'blur(6px)',
      zIndex: 2000,
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      padding: '1.5rem',
    }}>
      <div style={{
        width: '100%',
        maxWidth: '480px',
        background: '#FFFFFF',
        border: '1px solid rgba(139, 212, 232, 0.6)',
        borderRadius: '14px',
        padding: '2rem',
        boxShadow: '0 20px 60px rgba(34, 36, 38, 0.15), 0 0 30px rgba(139, 212, 232, 0.2)',
      }}>
        {/* Header */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', marginBottom: '1rem' }}>
          <div style={{
            width: '40px',
            height: '40px',
            borderRadius: '10px',
            background: 'rgba(197, 48, 48, 0.12)',
            border: '1px solid rgba(197, 48, 48, 0.3)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            fontSize: '1.2rem',
            color: 'var(--accent-rose)',
          }}>
            ⎋
          </div>
          <div>
            <h3 style={{ fontSize: '1.2rem', fontWeight: 800, color: 'var(--text-primary)', letterSpacing: '-0.01em' }}>
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
          background: '#F4F7F9',
          padding: '0.85rem 1rem',
          borderRadius: '8px',
          border: '1px solid rgba(139, 212, 232, 0.35)',
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
              border: '1px solid #72c7dc',
              background: '#8BD4E8',
              color: '#222426',
              fontSize: '0.85rem',
              fontWeight: 800,
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              gap: '0.5rem',
              boxShadow: '0 4px 14px rgba(139, 212, 232, 0.4)',
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
              border: '1px solid rgba(197, 48, 48, 0.35)',
              background: 'rgba(197, 48, 48, 0.08)',
              color: '#C53030',
              fontSize: '0.82rem',
              fontWeight: 700,
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
              border: '1px solid var(--border-color)',
              background: '#FFFFFF',
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
