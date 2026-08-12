import React from 'react';
import { Bell, User, Shield } from 'lucide-react';

export default function Header({ activeTab, setActiveTab }) {
  const navItems = [
    { id: 'dashboard', label: 'Dashboard' },
    { id: 'scanner', label: 'Scan Reports' },
    { id: 'pipeline', label: 'Vulnerability Feed' },
    { id: 'prover', label: 'System Status' },
    { id: 'settings', label: 'Settings' }
  ];

  return (
    <header style={{
      background: 'rgba(5, 8, 20, 0.95)',
      backdropFilter: 'blur(16px)',
      borderBottom: '1px solid rgba(53, 230, 200, 0.15)',
      position: 'sticky',
      top: 0,
      zIndex: 100,
      padding: '0 24px'
    }}>
      <div style={{
        maxWidth: '1380px',
        margin: '0 auto',
        height: '56px',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between'
      }}>
        {/* Brand Logo */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
          <Shield size={20} color="#35E6C8" />
          <div style={{
            fontSize: '18px',
            fontWeight: 800,
            letterSpacing: '-0.02em',
            color: '#35E6C8',
            fontFamily: 'var(--font-sans)',
            textShadow: '0 0 12px rgba(53, 230, 200, 0.4)'
          }}>
            AI Kavach CRS
          </div>
        </div>

        {/* Navigation Tabs */}
        <nav style={{ display: 'flex', gap: '24px' }}>
          {navItems.map((item) => {
            const isActive = activeTab === item.id;
            return (
              <button
                key={item.id}
                onClick={() => setActiveTab(item.id)}
                style={{
                  background: 'transparent',
                  border: 'none',
                  color: isActive ? '#35E6C8' : '#8E9BAE',
                  padding: '8px 0',
                  fontSize: '13px',
                  fontWeight: isActive ? 700 : 500,
                  cursor: 'pointer',
                  position: 'relative',
                  transition: 'color 0.2s ease',
                  fontFamily: 'var(--font-sans)'
                }}
              >
                {item.label}
                {isActive && (
                  <div style={{
                    position: 'absolute',
                    bottom: 0,
                    left: 0,
                    right: 0,
                    height: '2px',
                    background: '#35E6C8',
                    borderRadius: '2px',
                    boxShadow: '0 0 8px #35E6C8'
                  }} />
                )}
              </button>
            );
          })}
        </nav>

        {/* Right Action Icons: Notification Bell & Profile User */}
        <div style={{ display: 'flex', alignItems: 'center', gap: '14px' }}>
          {/* Notification Bell */}
          <button style={{
            background: 'rgba(255, 255, 255, 0.04)',
            border: '1px solid rgba(255, 255, 255, 0.08)',
            borderRadius: '8px',
            color: '#8E9BAE',
            cursor: 'pointer',
            padding: '6px 8px',
            position: 'relative',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center'
          }}>
            <Bell size={18} />
            <span style={{
              position: 'absolute',
              top: '4px',
              right: '4px',
              width: '6px',
              height: '6px',
              borderRadius: '50%',
              background: '#35E6C8',
              boxShadow: '0 0 6px #35E6C8'
            }} />
          </button>

          {/* User Profile Avatar */}
          <button style={{
            background: 'linear-gradient(135deg, rgba(53, 230, 200, 0.2) 0%, rgba(0, 229, 124, 0.1) 100%)',
            border: '1px solid rgba(53, 230, 200, 0.4)',
            borderRadius: '50%',
            color: '#35E6C8',
            cursor: 'pointer',
            width: '32px',
            height: '32px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center'
          }}>
            <User size={16} />
          </button>
        </div>
      </div>
    </header>
  );
}
