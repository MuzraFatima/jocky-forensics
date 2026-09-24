import React from 'react';
import ReactDOM from 'react-dom/client';
import App from './App.jsx';
import './index.css';

class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error) {
    return { hasError: true, error };
  }

  componentDidCatch(error, errorInfo) {
    console.error('JOCKY UI Error Boundary caught an error:', error, errorInfo);
  }

  render() {
    if (this.state.hasError) {
      return (
        <div style={{
          minHeight: '100vh',
          backgroundColor: '#06090f',
          color: '#f8fafc',
          padding: '2.5rem',
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          justifyContent: 'center',
          fontFamily: 'monospace',
        }}>
          <div style={{
            maxWidth: '680px',
            width: '100%',
            background: 'rgba(244, 63, 94, 0.08)',
            border: '1px solid #f43f5e',
            borderRadius: '12px',
            padding: '2rem',
            boxShadow: '0 20px 50px rgba(0,0,0,0.7)',
          }}>
            <h2 style={{ color: '#f43f5e', marginBottom: '1rem', fontSize: '1.25rem' }}>
              ⚠ JOCKY Interface Render Error
            </h2>
            <p style={{ color: '#fda4af', marginBottom: '1rem', fontSize: '0.85rem' }}>
              {this.state.error?.message || String(this.state.error)}
            </p>
            <button
              onClick={() => {
                sessionStorage.clear();
                window.location.reload();
              }}
              style={{
                padding: '0.6rem 1.2rem',
                background: '#0ea5e9',
                color: '#fff',
                border: 'none',
                borderRadius: '6px',
                cursor: 'pointer',
                fontWeight: 700,
                fontSize: '0.85rem',
              }}
            >
              Reset Session &amp; Reload Application
            </button>
          </div>
        </div>
      );
    }
    return this.props.children;
  }
}

ReactDOM.createRoot(document.getElementById('root')).render(
  <React.StrictMode>
    <ErrorBoundary>
      <App />
    </ErrorBoundary>
  </React.StrictMode>,
);


