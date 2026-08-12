import React, { useState } from 'react';
import { Cpu, Shield, Database, Save, CheckCircle2, RefreshCw, Sliders, CheckSquare, Zap, ShieldCheck } from 'lucide-react';

export default function SettingsView() {
  const [saved, setSaved] = useState(false);
  const [testingConnection, setTestingConnection] = useState(false);
  const [connectionStatus, setConnectionStatus] = useState(null);

  const [settings, setSettings] = useState({
    model: 'Ollama Llama-3 Security 70B (Air-Gapped)',
    endpoint: 'http://localhost:11434/v1',
    temperature: 0.1,
    maxTokens: 4096,
    clangPath: '/usr/bin/clang',
    cbmcPath: '/opt/homebrew/bin/cbmc',
    semgrepRules: 'p/security-audit',
    parallelAgents: 3,
    maxIterations: 8,
    stallThreshold: 4,
    enableFormal: true,
    enableHardening: true,
    enableMemory: true,
    enableASan: true
  });

  const handleTestConnection = () => {
    setTestingConnection(true);
    setTimeout(() => {
      setTestingConnection(false);
      setConnectionStatus('ONLINE — 12ms Latency (Local Host)');
    }, 1000);
  };

  const handleSave = () => {
    setSaved(true);
    setTimeout(() => setSaved(false), 2000);
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '14px', height: '100%' }}>
      
      {/* Header Bar */}
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <div>
          <div style={{
            fontSize: '11px',
            fontFamily: 'var(--font-mono)',
            color: 'var(--cyan-primary)',
            letterSpacing: '0.1em',
            display: 'flex',
            alignItems: 'center',
            gap: '6px'
          }}>
            <span style={{ width: '6px', height: '6px', borderRadius: '50%', background: 'var(--cyan-primary)' }} />
            SYSTEM CONFIGURATION // CONTROL CENTER
          </div>
          <h1 style={{ fontSize: '20px', fontWeight: 800, color: '#FFFFFF', letterSpacing: '-0.02em', marginTop: '2px' }}>
            System Settings & Toolchain Config
          </h1>
        </div>

        <button 
          onClick={handleSave}
          className="stat-card-sample" 
          style={{
            padding: '8px 20px',
            background: 'linear-gradient(135deg, #35E6C8 0%, #00E57C 100%)',
            border: 'none',
            color: '#040711',
            fontWeight: 800,
            fontSize: '12px',
            cursor: 'pointer',
            display: 'flex',
            alignItems: 'center',
            gap: '6px',
            boxShadow: '0 0 15px rgba(53, 230, 200, 0.3)'
          }}
        >
          {saved ? <CheckCircle2 size={14} /> : <Save size={14} />}
          {saved ? 'Configurations Saved!' : 'Save System Settings'}
        </button>
      </div>

      {/* Main Form Container: Compact 12px Gap (No Spaced-Out Black Void!) */}
      <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
        
        {/* CARD 1: AI Reasoning Model & Air-Gap API Endpoint */}
        <div className="stat-card-sample" style={{ padding: '16px 20px', display: 'flex', flexDirection: 'column', gap: '12px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid rgba(255, 255, 255, 0.08)', paddingBottom: '8px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <Cpu size={18} color="var(--cyan-primary)" />
              <div style={{ fontSize: '13.5px', fontWeight: 700, color: '#FFFFFF' }}>
                1. AI Reasoning Model & Air-Gap API Endpoint
              </div>
            </div>
            <span className="pill-badge pill-medium" style={{ fontSize: '9.5px', padding: '2px 8px' }}>
              AIR-GAPPED LOCAL INFERENCE
            </span>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1.2fr 2fr 1fr', gap: '16px', alignItems: 'flex-start' }}>
            <div>
              <label style={{ fontSize: '11px', color: '#8E9BAE', display: 'block', marginBottom: '4px', fontWeight: 600 }}>
                Primary Repair Model
              </label>
              <select 
                value={settings.model}
                onChange={(e) => setSettings({ ...settings, model: e.target.value })}
                className="font-mono"
                style={{
                  width: '100%',
                  background: '#040711',
                  border: '1px solid rgba(53, 230, 200, 0.3)',
                  borderRadius: '6px',
                  padding: '8px 10px',
                  color: '#35E6C8',
                  fontSize: '11px',
                  outline: 'none'
                }}
              >
                <option value="Ollama Llama-3 Security 70B (Air-Gapped)">Ollama Llama-3 Security 70B (Air-Gapped)</option>
                <option value="DeepSeek Coder V2 (Air-Gapped)">DeepSeek Coder V2 (Air-Gapped)</option>
                <option value="Custom Local SMT Engine">Custom Local SMT Engine</option>
              </select>
            </div>

            <div>
              <label style={{ fontSize: '11px', color: '#8E9BAE', display: 'block', marginBottom: '4px', fontWeight: 600 }}>
                Local Air-Gap Base API Endpoint
              </label>
              <div style={{ display: 'flex', gap: '8px' }}>
                <input 
                  type="text"
                  value={settings.endpoint}
                  onChange={(e) => setSettings({ ...settings, endpoint: e.target.value })}
                  className="font-mono"
                  style={{
                    flex: 1,
                    background: '#040711',
                    border: '1px solid rgba(53, 230, 200, 0.3)',
                    borderRadius: '6px',
                    padding: '8px 10px',
                    color: '#FFFFFF',
                    fontSize: '11px',
                    outline: 'none'
                  }}
                />
                <button
                  onClick={handleTestConnection}
                  style={{
                    padding: '8px 14px',
                    borderRadius: '6px',
                    background: 'rgba(53, 230, 200, 0.15)',
                    border: '1px solid rgba(53, 230, 200, 0.4)',
                    color: '#35E6C8',
                    fontSize: '11px',
                    fontWeight: 600,
                    cursor: 'pointer',
                    display: 'flex',
                    alignItems: 'center',
                    gap: '6px',
                    whiteSpace: 'nowrap'
                  }}
                >
                  <RefreshCw size={12} />
                  {testingConnection ? 'Testing...' : 'Test Link'}
                </button>
              </div>
              {connectionStatus && (
                <div style={{ fontSize: '10px', color: 'var(--neon-green)', marginTop: '4px', fontFamily: 'var(--font-mono)' }}>
                  ✅ {connectionStatus}
                </div>
              )}
            </div>

            <div>
              <label style={{ fontSize: '11px', color: '#8E9BAE', display: 'block', marginBottom: '4px', fontWeight: 600 }}>
                Sampling Temperature ({settings.temperature})
              </label>
              <input 
                type="range"
                min="0"
                max="1"
                step="0.05"
                value={settings.temperature}
                onChange={(e) => setSettings({ ...settings, temperature: parseFloat(e.target.value) })}
                style={{ width: '100%', accentColor: '#35E6C8', marginTop: '6px' }}
              />
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '9.5px', color: '#8E9BAE' }}>
                <span>0.0 (Deterministic)</span>
                <span>1.0 (Creative)</span>
              </div>
            </div>
          </div>
        </div>

        {/* CARD 2: Verification Toolchains & Binary Paths */}
        <div className="stat-card-sample" style={{ padding: '16px 20px', display: 'flex', flexDirection: 'column', gap: '12px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid rgba(255, 255, 255, 0.08)', paddingBottom: '8px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <Shield size={18} color="var(--neon-green)" />
              <div style={{ fontSize: '13.5px', fontWeight: 700, color: '#FFFFFF' }}>
                2. Verification Toolchains & Local Binary Paths
              </div>
            </div>
            <span className="pill-badge pill-low" style={{ fontSize: '9.5px', padding: '2px 8px' }}>
              3 TOOLCHAINS ACTIVE
            </span>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: '16px' }}>
            <div style={{ background: '#040711', padding: '10px 12px', borderRadius: '8px', border: '1px solid rgba(255, 255, 255, 0.06)' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '6px' }}>
                <label style={{ fontSize: '11px', color: '#FFFFFF', fontWeight: 700 }}>LLVM Clang Compiler</label>
                <span style={{ fontSize: '9.5px', color: 'var(--neon-green)', fontWeight: 600 }}>● Active</span>
              </div>
              <input 
                type="text"
                value={settings.clangPath}
                onChange={(e) => setSettings({ ...settings, clangPath: e.target.value })}
                className="font-mono"
                style={{
                  width: '100%',
                  background: 'rgba(255, 255, 255, 0.03)',
                  border: '1px solid rgba(53, 230, 200, 0.3)',
                  borderRadius: '6px',
                  padding: '6px 8px',
                  color: '#35E6C8',
                  fontSize: '10.5px',
                  outline: 'none'
                }}
              />
              <div style={{ fontSize: '9.5px', color: '#8E9BAE', marginTop: '4px' }}>clang v22.0.0 (ASan + UBSan)</div>
            </div>

            <div style={{ background: '#040711', padding: '10px 12px', borderRadius: '8px', border: '1px solid rgba(255, 255, 255, 0.06)' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '6px' }}>
                <label style={{ fontSize: '11px', color: '#FFFFFF', fontWeight: 700 }}>CBMC Model Checker</label>
                <span style={{ fontSize: '9.5px', color: 'var(--neon-green)', fontWeight: 600 }}>● Active</span>
              </div>
              <input 
                type="text"
                value={settings.cbmcPath}
                onChange={(e) => setSettings({ ...settings, cbmcPath: e.target.value })}
                className="font-mono"
                style={{
                  width: '100%',
                  background: 'rgba(255, 255, 255, 0.03)',
                  border: '1px solid rgba(53, 230, 200, 0.3)',
                  borderRadius: '6px',
                  padding: '6px 8px',
                  color: '#35E6C8',
                  fontSize: '10.5px',
                  outline: 'none'
                }}
              />
              <div style={{ fontSize: '9.5px', color: '#8E9BAE', marginTop: '4px' }}>cbmc v6.10.0 (SAT/SMT solver)</div>
            </div>

            <div style={{ background: '#040711', padding: '10px 12px', borderRadius: '8px', border: '1px solid rgba(255, 255, 255, 0.06)' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '6px' }}>
                <label style={{ fontSize: '11px', color: '#FFFFFF', fontWeight: 700 }}>Semgrep Static Analyzer</label>
                <span style={{ fontSize: '9.5px', color: 'var(--neon-green)', fontWeight: 600 }}>● Active</span>
              </div>
              <input 
                type="text"
                value={settings.semgrepRules}
                onChange={(e) => setSettings({ ...settings, semgrepRules: e.target.value })}
                className="font-mono"
                style={{
                  width: '100%',
                  background: 'rgba(255, 255, 255, 0.03)',
                  border: '1px solid rgba(53, 230, 200, 0.3)',
                  borderRadius: '6px',
                  padding: '6px 8px',
                  color: '#35E6C8',
                  fontSize: '10.5px',
                  outline: 'none'
                }}
              />
              <div style={{ fontSize: '9.5px', color: '#8E9BAE', marginTop: '4px' }}>ruleset: p/security-audit</div>
            </div>
          </div>
        </div>

        {/* CARD 3: Repair Safeguards & Execution Policies */}
        <div className="stat-card-sample" style={{ padding: '16px 20px', display: 'flex', flexDirection: 'column', gap: '12px' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid rgba(255, 255, 255, 0.08)', paddingBottom: '8px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
              <Database size={18} color="var(--cyan-primary)" />
              <div style={{ fontSize: '13.5px', fontWeight: 700, color: '#FFFFFF' }}>
                3. Repair Safeguards & Semantic Memory Policies
              </div>
            </div>
            <span className="pill-badge pill-high" style={{ fontSize: '9.5px', padding: '2px 8px' }}>
              ENFORCEMENT ACTIVE
            </span>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '12px' }}>
            {[
              { label: 'AddressSanitizer / UBSan', sub: 'Runtime heap & boundary check', key: 'enableASan', color: '#00E57C' },
              { label: 'CBMC SMT Formal Proofs', sub: 'Mathematical safety proof K=20', key: 'enableFormal', color: '#35E6C8' },
              { label: '20s Adversarial Re-Fuzzing', sub: 'Phase 6 patch hardening fuzzer', key: 'enableHardening', color: '#00E57C' },
              { label: '4-Tier Cross-Run Memory', sub: 'Persistent SQLite knowledge store', key: 'enableMemory', color: '#35E6C8' }
            ].map((chk, i) => (
              <div 
                key={i}
                onClick={() => setSettings({ ...settings, [chk.key]: !settings[chk.key] })}
                style={{
                  padding: '12px 14px',
                  borderRadius: '8px',
                  background: settings[chk.key] ? 'rgba(53, 230, 200, 0.1)' : '#040711',
                  border: `1px solid ${settings[chk.key] ? 'rgba(53, 230, 200, 0.4)' : 'rgba(255, 255, 255, 0.08)'}`,
                  cursor: 'pointer',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: '4px'
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                  <div style={{ width: '14px', height: '14px', borderRadius: '4px', background: settings[chk.key] ? chk.color : 'transparent', border: `1px solid ${chk.color}`, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
                    {settings[chk.key] && <span style={{ fontSize: '10px', color: '#040711', fontWeight: 800 }}>✓</span>}
                  </div>
                  <div style={{ fontSize: '11.5px', fontWeight: 700, color: settings[chk.key] ? '#FFFFFF' : '#8E9BAE' }}>
                    {chk.label}
                  </div>
                </div>
                <div style={{ fontSize: '9.5px', color: '#8E9BAE', paddingLeft: '22px' }}>
                  {chk.sub}
                </div>
              </div>
            ))}
          </div>
        </div>

      </div>
    </div>
  );
}
