import React, { useState } from 'react';
import { API_BASE } from './config.js';

export default function Login({ onLoginSuccess }) {
  const [username, setUsername] = useState('investigator@jocky.local');
  const [password, setPassword] = useState('jocky-forensics-2026');
  const [caseId, setCaseId] = useState('LAB-2026-001');
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [errorMsg, setErrorMsg] = useState(null);

  const handleFillDemo = (type = 'investigator') => {
    if (type === 'admin') {
      setUsername('admin@jocky.local');
      setPassword('admin-forensics-2026');
    } else {
      setUsername('investigator@jocky.local');
      setPassword('jocky-forensics-2026');
    }
    setErrorMsg(null);
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setErrorMsg(null);

    try {
      const response = await fetch(`${API_BASE}/api/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          username: username.trim(),
          password: password,
          case_id: caseId.trim() || 'LAB-2026-001',
        }),
      });

      const data = await response.json();
      if (response.ok && data.success && data.session) {
        onLoginSuccess(data.session);
      } else {
        setErrorMsg(data.error || 'Authentication rejected. Verify your credentials.');
      }
    } catch (err) {
      setErrorMsg(`Failed to reach JOCKY backend: ${err.message}. Ensure backend is running.`);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{
      minHeight: '100vh',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      background: 'radial-gradient(circle at 50% 20%, rgba(14, 165, 233, 0.12) 0%, rgba(6, 9, 15, 0.98) 60%)',
      padding: '1.5rem',
      fontFamily: 'inherit',
    }}>
      <div style={{
        width: '100%',
        maxWidth: '460px',
        background: 'rgba(12, 17, 29, 0.92)',
        border: '1px solid var(--border-color)',
        borderRadius: '14px',
        padding: '2.25rem 2rem',
        boxShadow: '0 25px 60px rgba(0, 0, 0, 0.6), 0 0 30px rgba(14, 165, 233, 0.12)',
        backdropFilter: 'blur(20px)',
      }}>
        {/* Header Branding */}
        <div style={{ textAlign: 'center', marginBottom: '1.75rem' }}>
          <div style={{
            width: '46px',
            height: '46px',
            borderRadius: '12px',
            background: 'linear-gradient(135deg, #0ea5e9, #6366f1)',
            display: 'inline-flex',
            alignItems: 'center',
            justifyContent: 'center',
            fontWeight: 800,
            fontSize: '22px',
            color: '#fff',
            boxShadow: '0 0 24px rgba(14, 165, 233, 0.5)',
            marginBottom: '0.75rem',
          }}>
            J
          </div>

          <h1 style={{
            fontSize: '1.4rem',
            fontWeight: 800,
            letterSpacing: '-0.02em',
            color: '#fff',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            gap: '0.5rem',
          }}>
            JOCKY FORENSICS
            <span style={{
              fontSize: '0.62rem',
              fontWeight: 700,
              color: 'var(--accent-cyan)',
              background: 'rgba(56, 189, 248, 0.12)',
              border: '1px solid rgba(56, 189, 248, 0.25)',
              padding: '0.15rem 0.4rem',
              borderRadius: '4px',
            }}>
              SIH26148
            </span>
          </h1>

          <p style={{ fontSize: '0.78rem', color: 'var(--text-muted)', marginTop: '0.35rem' }}>
            Authorized Read-Only Forensic Architecture &amp; Incident Triage
          </p>
        </div>

        {/* Demo Mode Notice Banner */}
        <div style={{
          background: 'rgba(56, 189, 248, 0.06)',
          border: '1px solid rgba(56, 189, 248, 0.2)',
          borderRadius: '8px',
          padding: '0.75rem 0.9rem',
          marginBottom: '1.5rem',
          fontSize: '0.75rem',
          color: 'var(--text-secondary)',
          lineHeight: 1.45,
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', color: 'var(--accent-cyan)', fontWeight: 700, marginBottom: '0.2rem' }}>
            <span>🔒</span> DEMO / RESEARCH AUTHENTICATION
          </div>
          Active session access to JOCKY investigation workspace. Use demo investigator credentials to authenticate:
          <div style={{ marginTop: '0.5rem', display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
            <button
              type="button"
              onClick={() => handleFillDemo('investigator')}
              style={{
                background: 'rgba(56, 189, 248, 0.15)',
                border: '1px solid rgba(56, 189, 248, 0.3)',
                borderRadius: '4px',
                color: 'var(--accent-cyan)',
                fontSize: '0.7rem',
                padding: '0.2rem 0.5rem',
                fontWeight: 600,
                cursor: 'pointer',
              }}
            >
              Fill Investigator Demo
            </button>
            <button
              type="button"
              onClick={() => handleFillDemo('admin')}
              style={{
                background: 'rgba(99, 102, 241, 0.15)',
                border: '1px solid rgba(99, 102, 241, 0.3)',
                borderRadius: '4px',
                color: 'var(--accent-indigo)',
                fontSize: '0.7rem',
                padding: '0.2rem 0.5rem',
                fontWeight: 600,
                cursor: 'pointer',
              }}
            >
              Fill Admin Demo
            </button>
          </div>
        </div>

        {/* Error Notification Banner */}
        {errorMsg && (
          <div style={{
            background: 'rgba(244, 63, 94, 0.12)',
            border: '1px solid rgba(244, 63, 94, 0.3)',
            borderRadius: '8px',
            padding: '0.75rem 0.9rem',
            marginBottom: '1.25rem',
            color: '#fda4af',
            fontSize: '0.8rem',
            display: 'flex',
            alignItems: 'center',
            gap: '0.5rem',
          }}>
            <span>⚠</span>
            <span style={{ flex: 1 }}>{errorMsg}</span>
          </div>
        )}

        {/* Login Form */}
        <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '1rem' }}>
          <div>
            <label style={{ display: 'block', fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '0.35rem' }}>
              Investigator Username / Email
            </label>
            <input
              type="text"
              required
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder="e.g. investigator@jocky.local"
              style={{
                width: '100%',
                padding: '0.65rem 0.85rem',
                background: 'rgba(10, 15, 26, 0.8)',
                border: '1px solid var(--border-color)',
                borderRadius: '6px',
                fontSize: '0.85rem',
                color: '#fff',
              }}
            />
          </div>

          <div>
            <label style={{ display: 'block', fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '0.35rem' }}>
              Access Password
            </label>
            <div style={{ position: 'relative' }}>
              <input
                type={showPassword ? 'text' : 'password'}
                required
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="Enter password"
                style={{
                  width: '100%',
                  padding: '0.65rem 2.5rem 0.65rem 0.85rem',
                  background: 'rgba(10, 15, 26, 0.8)',
                  border: '1px solid var(--border-color)',
                  borderRadius: '6px',
                  fontSize: '0.85rem',
                  color: '#fff',
                }}
              />
              <button
                type="button"
                onClick={() => setShowPassword(!showPassword)}
                style={{
                  position: 'absolute',
                  right: '8px',
                  top: '50%',
                  transform: 'translateY(-50%)',
                  background: 'none',
                  border: 'none',
                  color: 'var(--text-muted)',
                  fontSize: '0.8rem',
                  cursor: 'pointer',
                  padding: '0.2rem',
                }}
              >
                {showPassword ? 'Hide' : 'Show'}
              </button>
            </div>
          </div>

          <div>
            <label style={{ display: 'block', fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-secondary)', marginBottom: '0.35rem' }}>
              Target Case Designation
            </label>
            <input
              type="text"
              value={caseId}
              onChange={(e) => setCaseId(e.target.value)}
              placeholder="LAB-2026-001"
              style={{
                width: '100%',
                padding: '0.65rem 0.85rem',
                background: 'rgba(10, 15, 26, 0.8)',
                border: '1px solid var(--border-color)',
                borderRadius: '6px',
                fontSize: '0.85rem',
                color: '#fff',
                fontFamily: 'monospace',
              }}
            />
          </div>

          <button
            type="submit"
            disabled={loading}
            style={{
              marginTop: '0.75rem',
              padding: '0.75rem 1rem',
              borderRadius: '8px',
              border: 'none',
              background: loading ? 'rgba(14, 165, 233, 0.4)' : 'linear-gradient(135deg, #0ea5e9, #6366f1)',
              color: '#fff',
              fontWeight: 700,
              fontSize: '0.9rem',
              cursor: loading ? 'not-allowed' : 'pointer',
              boxShadow: '0 4px 18px rgba(14, 165, 233, 0.35)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              gap: '0.5rem',
            }}
          >
            {loading ? 'Authenticating Investigator...' : '🔐 Authenticate & Enter Dashboard'}
          </button>
        </form>

        {/* Security Invariant Footer */}
        <div style={{
          marginTop: '1.75rem',
          paddingTop: '1rem',
          borderTop: '1px solid var(--border-subtle)',
          textAlign: 'center',
          fontSize: '0.7rem',
          color: 'var(--text-muted)',
        }}>
          Protected by SHA-256 Chain-of-Custody &bull; Read-Only Telemetry Guards
        </div>
      </div>
    </div>
  );
}
