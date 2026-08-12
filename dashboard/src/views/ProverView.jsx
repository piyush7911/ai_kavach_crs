import React, { useState } from 'react';
import { MOCK_ORIGINAL_CODE, MOCK_PATCHED_CODE } from '../data/mockData';
import { ShieldCheck, CheckCircle2, FileCode, GitBranch, Copy, Sparkles, Award, Cpu, Zap, Download, Shield } from 'lucide-react';

export default function ProverView() {
  const [copied, setCopied] = useState(false);

  const handleCopy = () => {
    navigator.clipboard.writeText(MOCK_PATCHED_CODE);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '12px', height: '100%', justifyContent: 'space-between' }}>
      
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
            VERIFICATION WORKSTATION // CODE INSPECTOR
          </div>
          <h1 style={{ fontSize: '20px', fontWeight: 800, color: '#FFFFFF', letterSpacing: '-0.02em', marginTop: '2px' }}>
            Patch Prover & Ground-Truth Verification Matrix
          </h1>
        </div>

        <div style={{ display: 'flex', gap: '8px' }}>
          <button 
            onClick={handleCopy}
            className="stat-card-sample" 
            style={{
              padding: '6px 12px',
              background: 'rgba(255, 255, 255, 0.05)',
              border: '1px solid rgba(255, 255, 255, 0.15)',
              color: '#FFFFFF',
              fontWeight: 600,
              fontSize: '11px',
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: '4px'
            }}
          >
            <Copy size={12} />
            {copied ? 'Copied Diff!' : 'Copy Diff'}
          </button>
          <button 
            className="stat-card-sample" 
            style={{
              padding: '6px 14px',
              background: 'linear-gradient(135deg, #35E6C8 0%, #00E57C 100%)',
              border: 'none',
              color: '#040711',
              fontWeight: 800,
              fontSize: '11px',
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              gap: '4px',
              boxShadow: '0 0 15px rgba(53, 230, 200, 0.3)'
            }}
          >
            <GitBranch size={14} color="#040711" />
            Apply Patch to Git Branch
          </button>
        </div>
      </div>

      {/* Main Split Grid */}
      <div style={{ display: 'grid', gridTemplateColumns: '2.4fr 1fr', gap: '12px', flex: 1, minHeight: 0 }}>
        
        {/* Left Side-by-Side Code Inspector */}
        <div className="stat-card-sample" style={{ padding: '14px', display: 'flex', flexDirection: 'column', height: '100%' }}>
          
          {/* File Bar Toolbar */}
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px', borderBottom: '1px solid rgba(255, 255, 255, 0.06)', paddingBottom: '6px' }}>
            <div style={{ fontSize: '12px', fontWeight: 700, color: '#FFFFFF', display: 'flex', alignItems: 'center', gap: '6px' }}>
              <FileCode size={14} color="var(--cyan-primary)" />
              <span className="font-mono" style={{ color: '#35E6C8' }}>cJSON.c:660</span> (parse_string AST whole-function splice)
            </div>
            <div style={{ display: 'flex', gap: '6px' }}>
              <span className="pill-badge pill-critical">- VULNERABLE ORIGINAL</span>
              <span className="pill-badge pill-low">+ AI KAVACH VERIFIED FIX</span>
            </div>
          </div>

          {/* Code Panes Split */}
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '8px', flex: 1, minHeight: 0 }}>
            
            {/* Left Original */}
            <div style={{
              background: '#040711',
              borderRadius: '8px',
              border: '1px solid rgba(255, 74, 74, 0.35)',
              padding: '10px 12px',
              overflowY: 'auto'
            }}>
              <div style={{ fontSize: '10px', color: '#FF4A4A', fontFamily: 'var(--font-mono)', marginBottom: '6px', fontWeight: 700 }}>
                ORIGINAL (cJSON.c:660)
              </div>
              <pre className="font-mono" style={{ fontSize: '10.5px', lineHeight: 1.5, color: '#A0AEC0' }}>
{MOCK_ORIGINAL_CODE.split('\n').map((line, i) => (
  <div key={i} style={{
    background: line.includes('VULNERABLE') || line.includes('while (*input_end') ? 'rgba(255, 74, 74, 0.2)' : 'transparent',
    color: line.includes('VULNERABLE') ? '#FF4A4A' : '#A0AEC0',
    padding: '1px 4px',
    borderRadius: '3px'
  }}>
    <span style={{ color: 'var(--text-dim)', marginRight: '8px', userSelect: 'none' }}>{i + 1}</span>
    {line}
  </div>
))}
              </pre>
            </div>

            {/* Right Verified Patched */}
            <div style={{
              background: '#040711',
              borderRadius: '8px',
              border: '1.5px solid rgba(0, 229, 124, 0.5)',
              padding: '10px 12px',
              overflowY: 'auto',
              boxShadow: '0 0 15px rgba(0, 229, 124, 0.08)'
            }}>
              <div style={{ fontSize: '10px', color: 'var(--neon-green)', fontFamily: 'var(--font-mono)', marginBottom: '6px', fontWeight: 700 }}>
                PATCHED (cJSON.c:660)
              </div>
              <pre className="font-mono" style={{ fontSize: '10.5px', lineHeight: 1.5, color: '#E2E8F0' }}>
{MOCK_PATCHED_CODE.split('\n').map((line, i) => (
  <div key={i} style={{
    background: line.includes('VERIFIED') || line.includes('input_buffer->length') ? 'rgba(0, 229, 124, 0.2)' : 'transparent',
    color: line.includes('VERIFIED') ? 'var(--neon-green)' : '#E2E8F0',
    padding: '1px 4px',
    borderRadius: '3px'
  }}>
    <span style={{ color: 'var(--text-dim)', marginRight: '8px', userSelect: 'none' }}>{i + 1}</span>
    {line}
  </div>
))}
              </pre>
            </div>

          </div>
        </div>

        {/* Right Verification Matrix Panel (Redesigned as a Futuristic Badge & Matrix Dashboard) */}
        <div className="stat-card-sample stat-card-sample-green" style={{ padding: '16px', display: 'flex', flexDirection: 'column', gap: '12px', height: '100%', justifyContent: 'space-between' }}>
          
          {/* Top Verification Hero Badge */}
          <div style={{
            background: 'linear-gradient(135deg, rgba(0, 229, 124, 0.15) 0%, rgba(53, 230, 200, 0.05) 100%)',
            border: '1px solid rgba(0, 229, 124, 0.35)',
            borderRadius: '10px',
            padding: '12px',
            display: 'flex',
            alignItems: 'center',
            gap: '12px',
            boxShadow: '0 0 15px rgba(0, 229, 124, 0.1)'
          }}>
            <div style={{
              width: '42px',
              height: '42px',
              borderRadius: '50%',
              background: 'rgba(0, 229, 124, 0.2)',
              border: '1.5px solid #00E57C',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              boxShadow: '0 0 12px rgba(0, 229, 124, 0.3)'
            }}>
              <ShieldCheck size={24} color="#00E57C" />
            </div>

            <div>
              <div style={{ fontSize: '10px', fontFamily: 'var(--font-mono)', color: 'var(--neon-green)', fontWeight: 700 }}>
                GROUND-TRUTH VERIFIED
              </div>
              <div style={{ fontSize: '15px', fontWeight: 800, color: '#FFFFFF' }}>
                PASSED & PROVEN
              </div>
              <div style={{ fontSize: '10px', color: '#8E9BAE', marginTop: '1px' }}>
                Author: <span style={{ color: '#35E6C8', fontWeight: 600 }}>Agent Beta (Minimalist)</span>
              </div>
            </div>
          </div>

          {/* Core Verification Matrix Table */}
          <div style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: '8px', justifyContent: 'center' }}>
            <div style={{ fontSize: '11px', fontWeight: 700, color: '#FFFFFF', borderBottom: '1px solid rgba(255, 255, 255, 0.08)', paddingBottom: '4px' }}>
              Verification Gate Matrix
            </div>

            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: '11px' }}>
              <span style={{ color: '#8E9BAE' }}>Compiler ASan + UBSan</span>
              <span className="pill-badge pill-low" style={{ fontSize: '9.5px', padding: '1px 6px' }}>Gate 1 PASS</span>
            </div>

            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: '11px' }}>
              <span style={{ color: '#8E9BAE' }}>PoV Replay Signals</span>
              <span className="pill-badge pill-low" style={{ fontSize: '9.5px', padding: '1px 6px' }}>0 Crash Signals</span>
            </div>

            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: '11px' }}>
              <span style={{ color: '#8E9BAE' }}>Regression Test Suite</span>
              <span className="pill-badge pill-low" style={{ fontSize: '9.5px', padding: '1px 6px' }}>100% Exit 0</span>
            </div>

            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: '11px' }}>
              <span style={{ color: '#8E9BAE' }}>Semgrep Static Audit</span>
              <span className="pill-badge pill-low" style={{ fontSize: '9.5px', padding: '1px 6px' }}>0 Findings</span>
            </div>

            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: '11px' }}>
              <span style={{ color: '#8E9BAE' }}>Phase 6 Patch Hardening</span>
              <span className="pill-badge pill-medium" style={{ fontSize: '9.5px', padding: '1px 6px' }}>SURVIVED 20s</span>
            </div>

            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: '11px' }}>
              <span style={{ color: '#8E9BAE' }}>Phase 7 CBMC SMT Proof</span>
              <span className="pill-badge pill-medium" style={{ fontSize: '9.5px', padding: '1px 6px' }}>PROVEN (K=20)</span>
            </div>
          </div>

          {/* Quick Metrics Bar */}
          <div style={{
            display: 'grid',
            gridTemplateColumns: '1fr 1fr',
            gap: '8px',
            background: '#040711',
            borderRadius: '8px',
            padding: '8px 10px',
            border: '1px solid rgba(255, 255, 255, 0.06)'
          }}>
            <div>
              <div style={{ fontSize: '9.5px', color: '#8E9BAE' }}>Wall Time</div>
              <div className="font-mono" style={{ fontSize: '12px', fontWeight: 700, color: '#35E6C8' }}>65.6s</div>
            </div>
            <div>
              <div style={{ fontSize: '9.5px', color: '#8E9BAE' }}>Compute Cost</div>
              <div className="font-mono" style={{ fontSize: '12px', fontWeight: 700, color: '#00E57C' }}>$0.0188</div>
            </div>
          </div>

          {/* Action Buttons */}
          <div style={{ display: 'flex', gap: '6px' }}>
            <button className="stat-card-sample" style={{ flex: 1, padding: '8px', fontSize: '11px', fontWeight: 700, color: '#040711', background: 'linear-gradient(135deg, #35E6C8 0%, #00E57C 100%)', border: 'none', cursor: 'pointer', display: 'flex', alignItems: 'center', justifyContent: 'center', gap: '4px', borderRadius: '6px' }}>
              <Download size={12} fill="#040711" /> Export .patch File
            </button>
          </div>

        </div>

      </div>
    </div>
  );
}
