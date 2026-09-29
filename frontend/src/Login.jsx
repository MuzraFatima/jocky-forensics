import React, { useState } from 'react';
import { api } from './api.js';

export default function Login({ onLoginSuccess }) {
  const [mode, setMode] = useState('login'); // 'login' or 'register'
  const [username, setUsername] = useState('investigator@jocky.local');
  const [password, setPassword] = useState('jocky-forensics-2026');
  const [confirmPassword, setConfirmPassword] = useState('');
  const [role, setRole] = useState('Lead Forensic Examiner');
  const [caseId, setCaseId] = useState('LAB-2026-001');
  const [showPassword, setShowPassword] = useState(false);
  const [loading, setLoading] = useState(false);
  const [errorMsg, setErrorMsg] = useState(null);
  const [successMsg, setSuccessMsg] = useState(null);

  const handleFillDemo = (type = 'investigator') => {
    if (type === 'admin') {
      setUsername('admin@jocky.local');
      setPassword('admin-forensics-2026');
    } else {
      setUsername('investigator@jocky.local');
      setPassword('jocky-forensics-2026');
    }
    setErrorMsg(null);
    setSuccessMsg(null);
  };

  const switchMode = (newMode) => {
    setMode(newMode);
    setErrorMsg(null);
    setSuccessMsg(null);
    if (newMode === 'register') {
      setUsername('');
      setPassword('');
      setConfirmPassword('');
    } else {
      setUsername('investigator@jocky.local');
      setPassword('jocky-forensics-2026');
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);
    setErrorMsg(null);
    setSuccessMsg(null);

    const cleanUser = username.trim();
    const cleanCase = caseId.trim() || 'LAB-2026-001';

    if (!cleanUser) {
      setErrorMsg('Please enter an email or investigator username.');
      setLoading(false);
      return;
    }

    if (mode === 'register') {
      if (password.length < 6) {
        setErrorMsg('Password must be at least 6 characters long.');
        setLoading(false);
        return;
      }
      if (password !== confirmPassword) {
        setErrorMsg('Passwords do not match. Please verify.');
        setLoading(false);
        return;
      }

      try {
        const res = await api.register({
          email: cleanUser,
          username: cleanUser,
          password: password,
          role: role,
          case_id: cleanCase,
        });

        if (res.ok && res.data.success && res.data.session) {
          setSuccessMsg('Account created successfully! Entering dashboard...');
          setTimeout(() => {
            onLoginSuccess(res.data.session);
          }, 400);
        } else {
          setErrorMsg(res.data.error || 'Registration failed. Please try a different email.');
        }
      } catch (err) {
        setErrorMsg(`Unable to connect to JOCKY backend: ${err.message}. Check network connection.`);
      } finally {
        setLoading(false);
      }
    } else {
      // Login mode
      try {
        const res = await api.login({
          username: cleanUser,
          password: password,
          case_id: cleanCase,
        });

        if (res.ok && res.data.success && res.data.session) {
          onLoginSuccess(res.data.session);
        } else {
          setErrorMsg(res.data.error || 'Authentication rejected. Verify your credentials.');
        }
      } catch (err) {
        setErrorMsg(`Unable to connect to JOCKY backend: ${err.message}. Check network connection.`);
      } finally {
        setLoading(false);
      }
    }
  };

  return (
    <div style={{
      minHeight: '100vh',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      background: 'var(--bg-primary, #F6F8F9)',
      padding: '1.5rem',
      fontFamily: 'inherit',
    }}>
      <div style={{
        width: '100%',
        maxWidth: '480px',
        background: '#FFFFFF',
        border: '1px solid var(--border-color, #D8DEE2)',
        borderRadius: '14px',
        padding: '2.25rem 2rem',
        boxShadow: '0 4px 20px rgba(0, 0, 0, 0.05)',
      }}>
        {/* Header Branding */}
        <div style={{ textAlign: 'center', marginBottom: '1.5rem' }}>
          <div style={{
            width: '46px',
            height: '46px',
            borderRadius: '12px',
            background: 'var(--accent-cyan-bg, #8BD4E8)',
            display: 'inline-flex',
            alignItems: 'center',
            justifyContent: 'center',
            fontWeight: 800,
            fontSize: '22px',
            color: '#222426',
            boxShadow: '0 2px 8px rgba(139, 212, 232, 0.4)',
            marginBottom: '0.75rem',
          }}>
            J
          </div>

          <h1 style={{
            fontSize: '1.35rem',
            fontWeight: 800,
            letterSpacing: '-0.02em',
            color: '#222426',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            gap: '0.5rem',
          }}>
            JOCKY FORENSICS
            <span style={{
              fontSize: '0.62rem',
              fontWeight: 700,
              color: '#0284c7',
              background: 'var(--accent-cyan-soft, #CFEFF5)',
              border: '1px solid #BAE6FD',
              padding: '0.15rem 0.4rem',
              borderRadius: '4px',
            }}>
              SIH26148
            </span>
          </h1>

          <p style={{ fontSize: '0.78rem', color: 'var(--text-muted, #667078)', marginTop: '0.35rem' }}>
            Authorized Read-Only Digital Forensics &amp; Incident Investigation
          </p>
        </div>

        {/* Tab Toggle: Sign In vs Create Account */}
        <div style={{
          display: 'grid',
          gridTemplateColumns: '1fr 1fr',
          background: 'var(--bg-primary, #F6F8F9)',
          padding: '0.25rem',
          borderRadius: '8px',
          border: '1px solid var(--border-color, #D8DEE2)',
          marginBottom: '1.25rem',
        }}>
          <button
            type="button"
            onClick={() => switchMode('login')}
            style={{
              padding: '0.55rem 0.5rem',
              borderRadius: '6px',
              border: 'none',
              background: mode === 'login' ? '#FFFFFF' : 'transparent',
              color: mode === 'login' ? '#222426' : 'var(--text-muted, #667078)',
              fontWeight: mode === 'login' ? 700 : 500,
              fontSize: '0.82rem',
              cursor: 'pointer',
              boxShadow: mode === 'login' ? '0 1px 3px rgba(0, 0, 0, 0.05)' : 'none',
              transition: 'all 0.2s',
            }}
          >
            🔐 Sign In
          </button>
          <button
            type="button"
            onClick={() => switchMode('register')}
            style={{
              padding: '0.55rem 0.5rem',
              borderRadius: '6px',
              border: 'none',
              background: mode === 'register' ? '#FFFFFF' : 'transparent',
              color: mode === 'register' ? '#222426' : 'var(--text-muted, #667078)',
              fontWeight: mode === 'register' ? 700 : 500,
              fontSize: '0.82rem',
              cursor: 'pointer',
              boxShadow: mode === 'register' ? '0 1px 3px rgba(0, 0, 0, 0.05)' : 'none',
              transition: 'all 0.2s',
            }}
          >
            📝 Create Account
          </button>
        </div>

        {/* Demo Fill Banner (Login Mode Only) */}
        {mode === 'login' && (
          <div style={{
            background: 'var(--accent-cyan-soft, #CFEFF5)',
            border: '1px solid #BAE6FD',
            borderRadius: '8px',
            padding: '0.7rem 0.85rem',
            marginBottom: '1.25rem',
            fontSize: '0.74rem',
            color: '#222426',
            lineHeight: 1.45,
          }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '0.4rem', color: '#0284c7', fontWeight: 700, marginBottom: '0.2rem' }}>
              <span>🔒</span> QUICK DEMO CREDENTIALS
            </div>
            Pre-configured accounts for SIH evaluation:
            <div style={{ marginTop: '0.45rem', display: 'flex', gap: '0.5rem', flexWrap: 'wrap' }}>
              <button
                type="button"
                onClick={() => handleFillDemo('investigator')}
                style={{
                  background: '#FFFFFF',
                  border: '1px solid #BAE6FD',
                  borderRadius: '4px',
                  color: '#0284c7',
                  fontSize: '0.7rem',
                  padding: '0.25rem 0.55rem',
                  fontWeight: 600,
                  cursor: 'pointer',
                  boxShadow: '0 1px 2px rgba(0,0,0,0.03)',
                }}
              >
                Fill Investigator Demo
              </button>
              <button
                type="button"
                onClick={() => handleFillDemo('admin')}
                style={{
                  background: '#FFFFFF',
                  border: '1px solid var(--border-color, #D8DEE2)',
                  borderRadius: '4px',
                  color: '#4f46e5',
                  fontSize: '0.7rem',
                  padding: '0.25rem 0.55rem',
                  fontWeight: 600,
                  cursor: 'pointer',
                  boxShadow: '0 1px 2px rgba(0,0,0,0.03)',
                }}
              >
                Fill Admin Demo
              </button>
            </div>
          </div>
        )}

        {/* Error Notification Banner */}
        {errorMsg && (
          <div style={{
            background: '#FFF1F2',
            border: '1px solid #FECDD3',
            borderRadius: '8px',
            padding: '0.7rem 0.85rem',
            marginBottom: '1.25rem',
            color: '#E11D48',
            fontSize: '0.8rem',
            display: 'flex',
            alignItems: 'center',
            gap: '0.5rem',
          }}>
            <span>⚠</span>
            <span style={{ flex: 1 }}>{errorMsg}</span>
          </div>
        )}

        {/* Success Notification Banner */}
        {successMsg && (
          <div style={{
            background: 'var(--accent-emerald-soft, #E8F1DE)',
            border: '1px solid #BBF7D0',
            borderRadius: '8px',
            padding: '0.7rem 0.85rem',
            marginBottom: '1.25rem',
            color: 'var(--accent-emerald, #5C802B)',
            fontSize: '0.8rem',
            display: 'flex',
            alignItems: 'center',
            gap: '0.5rem',
          }}>
            <span>✓</span>
            <span style={{ flex: 1 }}>{successMsg}</span>
          </div>
        )}

        {/* Form */}
        <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: '0.9rem' }}>
          <div>
            <label style={{ display: 'block', fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-secondary, #667078)', marginBottom: '0.35rem' }}>
              {mode === 'register' ? 'Email / Investigator Username' : 'Investigator Username / Email'}
            </label>
            <input
              type="text"
              required
              value={username}
              onChange={(e) => setUsername(e.target.value)}
              placeholder={mode === 'register' ? 'analyst@agency.gov or analyst' : 'investigator@jocky.local'}
              style={{
                width: '100%',
                padding: '0.65rem 0.85rem',
                background: '#FFFFFF',
                border: '1px solid var(--border-color, #D8DEE2)',
                borderRadius: '6px',
                fontSize: '0.85rem',
                color: '#222426',
              }}
            />
          </div>

          {mode === 'register' && (
            <div>
              <label style={{ display: 'block', fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-secondary, #667078)', marginBottom: '0.35rem' }}>
                Investigator Role &amp; Clearance
              </label>
              <select
                value={role}
                onChange={(e) => setRole(e.target.value)}
                style={{
                  width: '100%',
                  padding: '0.65rem 0.85rem',
                  background: '#FFFFFF',
                  border: '1px solid var(--border-color, #D8DEE2)',
                  borderRadius: '6px',
                  fontSize: '0.85rem',
                  color: '#222426',
                }}
              >
                <option value="Lead Forensic Examiner">Lead Forensic Examiner</option>
                <option value="Incident Responder">Incident Responder</option>
                <option value="SOC Incident Commander">SOC Incident Commander</option>
                <option value="Digital Evidence Auditor">Digital Evidence Auditor</option>
              </select>
            </div>
          )}

          <div>
            <label style={{ display: 'block', fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-secondary, #667078)', marginBottom: '0.35rem' }}>
              {mode === 'register' ? 'Create Password (min 6 characters)' : 'Access Password'}
            </label>
            <div style={{ position: 'relative' }}>
              <input
                type={showPassword ? 'text' : 'password'}
                required
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder={mode === 'register' ? 'Choose secure password' : 'Enter password'}
                style={{
                  width: '100%',
                  padding: '0.65rem 2.5rem 0.65rem 0.85rem',
                  background: '#FFFFFF',
                  border: '1px solid var(--border-color, #D8DEE2)',
                  borderRadius: '6px',
                  fontSize: '0.85rem',
                  color: '#222426',
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
                  color: 'var(--text-muted, #667078)',
                  fontSize: '0.8rem',
                  cursor: 'pointer',
                  padding: '0.2rem',
                }}
              >
                {showPassword ? 'Hide' : 'Show'}
              </button>
            </div>
          </div>

          {mode === 'register' && (
            <div>
              <label style={{ display: 'block', fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-secondary, #667078)', marginBottom: '0.35rem' }}>
                Confirm Password
              </label>
              <input
                type={showPassword ? 'text' : 'password'}
                required
                value={confirmPassword}
                onChange={(e) => setConfirmPassword(e.target.value)}
                placeholder="Re-enter password"
                style={{
                  width: '100%',
                  padding: '0.65rem 0.85rem',
                  background: '#FFFFFF',
                  border: '1px solid var(--border-color, #D8DEE2)',
                  borderRadius: '6px',
                  fontSize: '0.85rem',
                  color: '#222426',
                }}
              />
            </div>
          )}

          <div>
            <label style={{ display: 'block', fontSize: '0.75rem', fontWeight: 600, color: 'var(--text-secondary, #667078)', marginBottom: '0.35rem' }}>
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
                background: '#FFFFFF',
                border: '1px solid var(--border-color, #D8DEE2)',
                borderRadius: '6px',
                fontSize: '0.85rem',
                color: '#222426',
                fontFamily: 'monospace',
              }}
            />
          </div>

          <button
            type="submit"
            disabled={loading}
            style={{
              marginTop: '0.65rem',
              padding: '0.75rem 1rem',
              borderRadius: '8px',
              border: 'none',
              background: loading ? 'var(--accent-cyan-soft, #CFEFF5)' : 'var(--accent-cyan-bg, #8BD4E8)',
              color: '#222426',
              fontWeight: 700,
              fontSize: '0.9rem',
              cursor: loading ? 'not-allowed' : 'pointer',
              boxShadow: '0 1px 2px rgba(0, 0, 0, 0.05)',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              gap: '0.5rem',
            }}
          >
            {loading ? (
              mode === 'register' ? 'Registering Account...' : 'Authenticating Investigator...'
            ) : (
              mode === 'register' ? '📝 Create Account & Enter Workspace' : '🔐 Authenticate & Enter Dashboard'
            )}
          </button>
        </form>

        {/* Bottom Switch Link */}
        <div style={{ marginTop: '1.25rem', textAlign: 'center', fontSize: '0.78rem', color: 'var(--text-secondary, #667078)' }}>
          {mode === 'login' ? (
            <span>
              Need a custom account?{' '}
              <button
                type="button"
                onClick={() => switchMode('register')}
                style={{
                  background: 'none',
                  border: 'none',
                  color: '#0284c7',
                  cursor: 'pointer',
                  fontWeight: 600,
                  textDecoration: 'underline',
                  padding: 0,
                }}
              >
                Register here
              </button>
            </span>
          ) : (
            <span>
              Already have an account?{' '}
              <button
                type="button"
                onClick={() => switchMode('login')}
                style={{
                  background: 'none',
                  border: 'none',
                  color: '#0284c7',
                  cursor: 'pointer',
                  fontWeight: 600,
                  textDecoration: 'underline',
                  padding: 0,
                }}
              >
                Sign in
              </button>
            </span>
          )}
        </div>

        {/* Security Invariant Footer */}
        <div style={{
          marginTop: '1.5rem',
          paddingTop: '0.9rem',
          borderTop: '1px solid var(--border-color, #D8DEE2)',
          textAlign: 'center',
          fontSize: '0.7rem',
          color: 'var(--text-muted, #667078)',
        }}>
          Protected by SHA-256 Chain-of-Custody &bull; PBKDF2 Password Hashing &bull; Read-Only Telemetry Guards
        </div>
      </div>
    </div>
  );
}
