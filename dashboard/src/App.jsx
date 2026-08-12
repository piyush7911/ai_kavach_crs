import React, { useState } from 'react';
import Header from './components/Header';
import DashboardView from './views/DashboardView';
import ScannerView from './views/ScannerView';
import PipelineView from './views/PipelineView';
import ProverView from './views/ProverView';
import MemoryView from './views/MemoryView';
import ReportsView from './views/ReportsView';
import SettingsView from './views/SettingsView';

export default function App() {
  const [activeTab, setActiveTab] = useState('dashboard');

  return (
    <div style={{ height: '100vh', display: 'flex', flexDirection: 'column', background: 'var(--bg-dark)', overflow: 'hidden' }}>
      {/* Top Navigation Header */}
      <Header activeTab={activeTab} setActiveTab={setActiveTab} />

      {/* Viewport Container (Zero Scroll, 100% Height Fill) */}
      <main style={{
        flex: 1,
        maxWidth: '1400px',
        width: '100%',
        margin: '0 auto',
        padding: '16px 20px',
        display: 'flex',
        flexDirection: 'column',
        overflow: 'hidden'
      }}>
        {activeTab === 'dashboard' && <DashboardView onNavigate={setActiveTab} />}
        {activeTab === 'scanner' && <ScannerView onNavigate={setActiveTab} />}
        {activeTab === 'pipeline' && <PipelineView onNavigate={setActiveTab} />}
        {activeTab === 'prover' && <ProverView />}
        {activeTab === 'memory' && <MemoryView />}
        {activeTab === 'reports' && <ReportsView />}
        {activeTab === 'settings' && <SettingsView />}
      </main>

      {/* Footer Status Line */}
      <footer style={{
        borderTop: '1px solid rgba(255, 255, 255, 0.05)',
        padding: '6px 20px',
        textAlign: 'center',
        fontSize: '10px',
        color: 'var(--text-dim)',
        fontFamily: 'var(--font-mono)',
        letterSpacing: '0.05em'
      }}>
        AI KAVACH CRS
      </footer>
    </div>
  );
}
