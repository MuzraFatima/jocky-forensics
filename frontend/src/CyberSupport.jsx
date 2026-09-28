import React, { useState, useEffect, useRef } from 'react';
import { API_BASE } from './config.js';

export default function CyberSupport({
  session,
  activeCaseId = 'LAB-2026-001',
  currentIncident,
  onOpenReportModal,
}) {
  const [analystData, setAnalystData] = useState({
    status: 'ONLINE',
    is_simulation: true,
    status_label: 'Security Analyst Online',
  });
  const [chatMode, setChatMode] = useState('auto'); // auto, analyst, ai
  const [messages, setMessages] = useState([
    {
      id: 'welcome-1',
      sender: 'system',
      timestamp: Date.now() / 1000 - 60,
      text: 'Session connected to JOCKY Security Incident & Escalation Channel (Demo SOC Simulation).',
    },
    {
      id: 'welcome-2',
      sender: 'analyst',
      senderName: 'Sarah Connor, CISSP (Demo Analyst)',
      timestamp: Date.now() / 1000 - 30,
      text: 'SOC Analyst standing by. I am monitoring your investigation session under authorized read-only protocol. How can I assist with triage?',
      role: 'analyst',
    },
  ]);
  const [inputText, setInputText] = useState('');
  const [sending, setSending] = useState(false);
  const [statusLoading, setStatusLoading] = useState(false);
  const chatBottomRef = useRef(null);

  // Auto-scroll chat to bottom
  useEffect(() => {
    chatBottomRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [messages]);

  // Fetch analyst status on mount
  const fetchAnalystStatus = async () => {
    try {
      const res = await fetch(`${API_BASE}/api/security/analyst/status`);
      if (res.ok) {
        const data = await res.json();
        setAnalystData(data);
      }
    } catch (e) {
      console.error('Failed to query analyst status:', e);
    }
  };

  useEffect(() => {
    fetchAnalystStatus();
    const interval = setInterval(fetchAnalystStatus, 15000);
    return () => clearInterval(interval);
  }, []);

  // Toggle analyst status for simulation testing
  const handleToggleAnalyst = async () => {
    setStatusLoading(true);
    const newStatus = analystData.status === 'ONLINE' ? 'OFFLINE' : 'ONLINE';
    try {
      const res = await fetch(`${API_BASE}/api/security/analyst/toggle`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status: newStatus }),
      });
      if (res.ok) {
        const data = await res.json();
        setAnalystData(data);
        if (newStatus === 'OFFLINE') {
          setMessages((prev) => [
            ...prev,
            {
              id: `sys-${Date.now()}`,
              sender: 'system',
              timestamp: Date.now() / 1000,
              text: 'Security analyst is currently unavailable. Switching to AI Forensic Assistant (Context-Constrained, No Groq).',
            },
          ]);
        } else {
          setMessages((prev) => [
            ...prev,
            {
              id: `sys-${Date.now()}`,
              sender: 'system',
              timestamp: Date.now() / 1000,
              text: 'Security Analyst Sarah Connor is back ONLINE. Channel restored to human analyst.',
            },
          ]);
        }
      }
    } catch (e) {
      console.error('Failed to toggle analyst status:', e);
    } finally {
      setStatusLoading(false);
    }
  };

  const handleSendMessage = async (textToSend = null) => {
    const query = (textToSend || inputText).trim();
    if (!query || sending) return;

    const userMsg = {
      id: `usr-${Date.now()}`,
      sender: 'user',
      senderName: session?.username || 'Investigator',
      timestamp: Date.now() / 1000,
      text: query,
      role: 'investigator',
    };

    setMessages((prev) => [...prev, userMsg]);
    setInputText('');
    setSending(true);

    try {
      const res = await fetch(`${API_BASE}/api/security/chat`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: session?.token ? `Bearer ${session.token}` : '',
        },
        body: JSON.stringify({
          message: query,
          mode: chatMode,
          case_id: activeCaseId,
          incident_id: currentIncident?.incident_id,
          context: {
            case_id: activeCaseId,
            target: currentIncident?.target || 'LAB-PC',
            detections_count: currentIncident?.detections?.length || 0,
            has_incident: currentIncident?.has_incident || false,
          },
        }),
      });

      const data = await res.json();
      if (res.ok && data.success) {
        if (data.channel === 'ai') {
          setMessages((prev) => [
            ...prev,
            {
              id: `ai-${Date.now()}`,
              sender: 'ai',
              senderName: `${data.provider || 'AI Forensic Assistant'}`,
              timestamp: data.timestamp || Date.now() / 1000,
              text: data.reply,
              role: 'ai',
            },
          ]);
        } else if (data.reply) {
          setMessages((prev) => [
            ...prev,
            {
              id: data.reply.id || `rep-${Date.now()}`,
              sender: 'analyst',
              senderName: data.reply.sender_name || 'Sarah Connor (Demo Analyst)',
              timestamp: data.reply.timestamp || Date.now() / 1000,
              text: data.reply.text,
              role: 'analyst',
            },
          ]);
        }
      } else {
        setMessages((prev) => [
          ...prev,
          {
            id: `err-${Date.now()}`,
            sender: 'system',
            timestamp: Date.now() / 1000,
            text: `Error communicating with security backend: ${data.error || 'Request failed.'}`,
          },
        ]);
      }
    } catch (err) {
      setMessages((prev) => [
        ...prev,
        {
          id: `err-${Date.now()}`,
          sender: 'system',
          timestamp: Date.now() / 1000,
          text: `Connection error: ${err.message}. Ensure JOCKY backend is running.`,
        },
      ]);
    } finally {
      setSending(false);
    }
  };

  const isAnalystOnline = analystData.status === 'ONLINE';

  return (
    <div style={{
      display: 'flex',
      flexDirection: 'column',
      height: 'calc(100vh - 180px)',
      minHeight: '620px',
      background: 'var(--bg-card)',
      borderRadius: '12px',
      border: '1px solid var(--border-color)',
      overflow: 'hidden',
    }}>
      {/* Panel Header */}
      <div style={{
        padding: '1.1rem 1.5rem',
        borderBottom: '1px solid var(--border-color)',
        background: 'rgba(10, 15, 26, 0.7)',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        flexWrap: 'wrap',
        gap: '1rem',
      }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.65rem' }}>
            <h2 style={{ fontSize: '1.2rem', fontWeight: 800, color: '#fff', letterSpacing: '-0.02em' }}>
              Cybersecurity Support
            </h2>
            <span style={{
              fontSize: '0.65rem',
              fontWeight: 700,
              color: 'var(--accent-indigo)',
              background: 'rgba(99, 102, 241, 0.12)',
              border: '1px solid rgba(99, 102, 241, 0.3)',
              padding: '0.15rem 0.45rem',
              borderRadius: '4px',
            }}>
              SOC ESCALATION
            </span>
          </div>
          <p style={{ fontSize: '0.75rem', color: 'var(--text-muted)', marginTop: '0.2rem' }}>
            Incident Advisory &amp; Guidance Channel &bull; Demo Security Analyst &bull; Strictly Read-Only
          </p>
        </div>

        {/* Status Pill & Simulation Controls */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '0.75rem', flexWrap: 'wrap' }}>
          <div style={{
            display: 'inline-flex',
            alignItems: 'center',
            gap: '0.5rem',
            padding: '0.4rem 0.85rem',
            borderRadius: '999px',
            background: isAnalystOnline ? 'rgba(16, 185, 129, 0.1)' : 'rgba(245, 158, 11, 0.1)',
            border: `1px solid ${isAnalystOnline ? 'rgba(16, 185, 129, 0.3)' : 'rgba(245, 158, 11, 0.3)'}`,
            fontSize: '0.78rem',
            fontWeight: 700,
            color: isAnalystOnline ? 'var(--accent-emerald)' : 'var(--accent-amber)',
          }}>
            <span
              style={{
                width: '8px',
                height: '8px',
                borderRadius: '50%',
                backgroundColor: isAnalystOnline ? 'var(--accent-emerald)' : 'var(--accent-amber)',
              }}
              className={isAnalystOnline ? 'pulse-dot' : ''}
            />
            {isAnalystOnline ? '● Security Analyst Online' : '○ Security Analyst Unavailable'}
          </div>

          {/* Simulation Toggle Button */}
          <button
            type="button"
            onClick={handleToggleAnalyst}
            disabled={statusLoading}
            title="Toggle analyst online/offline to test AI fallback workflow"
            style={{
              background: 'rgba(255, 255, 255, 0.04)',
              border: '1px solid var(--border-color)',
              color: 'var(--text-secondary)',
              borderRadius: '6px',
              padding: '0.4rem 0.75rem',
              fontSize: '0.72rem',
              fontWeight: 600,
              cursor: statusLoading ? 'not-allowed' : 'pointer',
            }}
          >
            {statusLoading ? 'Updating...' : `Simulation: Toggle ${isAnalystOnline ? 'Offline' : 'Online'}`}
          </button>
        </div>
      </div>

      {/* Offline AI Notification Banner */}
      {!isAnalystOnline && (
        <div style={{
          background: 'rgba(245, 158, 11, 0.08)',
          borderBottom: '1px solid rgba(245, 158, 11, 0.25)',
          padding: '0.75rem 1.5rem',
          fontSize: '0.8rem',
          color: '#fef3c7',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          flexWrap: 'wrap',
          gap: '0.5rem',
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
            <span style={{ fontSize: '1.1rem' }}>🤖</span>
            <div>
              <strong>Security analyst is currently unavailable.</strong>
              <div style={{ fontSize: '0.72rem', color: 'var(--text-muted)' }}>
                Switched to AI Forensic Assistant (Deterministic, read-only guidance, no external Groq).
              </div>
            </div>
          </div>
          <span style={{
            fontSize: '0.68rem',
            padding: '0.2rem 0.5rem',
            borderRadius: '4px',
            background: 'rgba(245, 158, 11, 0.2)',
            color: 'var(--accent-amber)',
            fontWeight: 700,
          }}>
            AI FALLBACK ACTIVE
          </span>
        </div>
      )}

      {/* Chat Messages Body */}
      <div style={{
        flex: 1,
        overflowY: 'auto',
        padding: '1.5rem',
        display: 'flex',
        flexDirection: 'column',
        gap: '1rem',
      }}>
        {messages.map((msg) => {
          const isUser = msg.sender === 'user';
          const isSystem = msg.sender === 'system';
          const isAI = msg.sender === 'ai';

          if (isSystem) {
            return (
              <div
                key={msg.id}
                style={{
                  alignSelf: 'center',
                  background: 'rgba(255, 255, 255, 0.03)',
                  border: '1px solid var(--border-subtle)',
                  borderRadius: '20px',
                  padding: '0.35rem 0.9rem',
                  fontSize: '0.72rem',
                  color: 'var(--text-muted)',
                  textAlign: 'center',
                  maxWidth: '85%',
                }}
              >
                ℹ {msg.text}
              </div>
            );
          }

          return (
            <div
              key={msg.id}
              style={{
                alignSelf: isUser ? 'flex-end' : 'flex-start',
                maxWidth: '75%',
                display: 'flex',
                flexDirection: 'column',
                alignItems: isUser ? 'flex-end' : 'flex-start',
              }}
            >
              {/* Sender Name & Timestamp */}
              <div style={{
                fontSize: '0.68rem',
                color: 'var(--text-muted)',
                marginBottom: '0.25rem',
                display: 'flex',
                alignItems: 'center',
                gap: '0.4rem',
              }}>
                <span style={{ fontWeight: 600, color: isUser ? 'var(--accent-cyan)' : (isAI ? 'var(--accent-amber)' : 'var(--accent-emerald)') }}>
                  {msg.senderName}
                </span>
                <span>&bull;</span>
                <span>{new Date(msg.timestamp * 1000).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</span>
              </div>

              {/* Message Bubble */}
              <div style={{
                padding: '0.75rem 1rem',
                borderRadius: isUser ? '12px 12px 2px 12px' : '12px 12px 12px 2px',
                background: isUser
                  ? 'linear-gradient(135deg, rgba(14, 165, 233, 0.25), rgba(99, 102, 241, 0.25))'
                  : (isAI ? 'rgba(245, 158, 11, 0.1)' : 'rgba(15, 23, 42, 0.85)'),
                border: `1px solid ${isUser ? 'rgba(56, 189, 248, 0.35)' : (isAI ? 'rgba(245, 158, 11, 0.3)' : 'var(--border-color)')}`,
                color: '#fff',
                fontSize: '0.84rem',
                lineHeight: 1.45,
                whiteSpace: 'pre-wrap',
                boxShadow: isUser ? '0 4px 15px rgba(14, 165, 233, 0.1)' : 'none',
              }}>
                {msg.text}
              </div>
            </div>
          );
        })}
        <div ref={chatBottomRef} />
      </div>

      {/* Suggested Quick Prompts */}
      <div style={{
        padding: '0.5rem 1.5rem',
        borderTop: '1px solid var(--border-subtle)',
        background: 'rgba(6, 9, 15, 0.4)',
        display: 'flex',
        gap: '0.5rem',
        overflowX: 'auto',
      }}>
        <button
          type="button"
          onClick={() => handleSendMessage('Attach active forensic findings and evaluate severity.')}
          style={{
            background: 'rgba(56, 189, 248, 0.08)',
            border: '1px solid rgba(56, 189, 248, 0.2)',
            borderRadius: '999px',
            color: 'var(--accent-cyan)',
            fontSize: '0.7rem',
            padding: '0.25rem 0.75rem',
            whiteSpace: 'nowrap',
            cursor: 'pointer',
          }}
        >
          📎 Attach Incident Telemetry
        </button>

        <button
          type="button"
          onClick={() => handleSendMessage('What heuristic detection rules were triggered?')}
          style={{
            background: 'rgba(255, 255, 255, 0.04)',
            border: '1px solid var(--border-subtle)',
            borderRadius: '999px',
            color: 'var(--text-secondary)',
            fontSize: '0.7rem',
            padding: '0.25rem 0.75rem',
            whiteSpace: 'nowrap',
            cursor: 'pointer',
          }}
        >
          🔍 Review Heuristic Rules
        </button>

        <button
          type="button"
          onClick={() => handleSendMessage('How is cryptographic evidence integrity attested?')}
          style={{
            background: 'rgba(255, 255, 255, 0.04)',
            border: '1px solid var(--border-subtle)',
            borderRadius: '999px',
            color: 'var(--text-secondary)',
            fontSize: '0.7rem',
            padding: '0.25rem 0.75rem',
            whiteSpace: 'nowrap',
            cursor: 'pointer',
          }}
        >
          🛡️ Evidence Vault Attestation
        </button>

        <button
          type="button"
          onClick={onOpenReportModal}
          style={{
            background: 'rgba(16, 185, 129, 0.1)',
            border: '1px solid rgba(16, 185, 129, 0.3)',
            borderRadius: '999px',
            color: 'var(--accent-emerald)',
            fontSize: '0.7rem',
            padding: '0.25rem 0.75rem',
            whiteSpace: 'nowrap',
            cursor: 'pointer',
            marginLeft: 'auto',
          }}
        >
          📄 Generate &amp; Send Report
        </button>
      </div>

      {/* Message Input Box */}
      <form
        onSubmit={(e) => {
          e.preventDefault();
          handleSendMessage();
        }}
        style={{
          padding: '1rem 1.5rem',
          borderTop: '1px solid var(--border-color)',
          background: 'rgba(10, 15, 26, 0.9)',
          display: 'flex',
          gap: '0.75rem',
          alignItems: 'center',
        }}
      >
        <input
          type="text"
          value={inputText}
          onChange={(e) => setInputText(e.target.value)}
          placeholder={
            isAnalystOnline
              ? "Message Human Security Analyst Sarah Connor..."
              : "Query AI Forensic Assistant..."
          }
          disabled={sending}
          style={{
            flex: 1,
            padding: '0.65rem 1rem',
            background: 'rgba(6, 9, 15, 0.8)',
            border: '1px solid var(--border-color)',
            borderRadius: '8px',
            fontSize: '0.85rem',
            color: '#fff',
          }}
        />

        <button
          type="submit"
          disabled={sending || !inputText.trim()}
          style={{
            background: sending || !inputText.trim() ? 'rgba(56, 189, 248, 0.2)' : 'linear-gradient(135deg, #0ea5e9, #6366f1)',
            color: '#fff',
            border: 'none',
            borderRadius: '8px',
            padding: '0.65rem 1.25rem',
            fontSize: '0.85rem',
            fontWeight: 700,
            cursor: sending || !inputText.trim() ? 'not-allowed' : 'pointer',
            display: 'flex',
            alignItems: 'center',
            gap: '0.4rem',
          }}
        >
          {sending ? 'Sending...' : 'Send ▶'}
        </button>
      </form>
    </div>
  );
}
