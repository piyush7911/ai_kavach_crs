import React, { useState } from 'react';
import { FolderPlus, Play, Terminal, CheckSquare, Layers, Shield, Zap, AlertTriangle, FileCode } from 'lucide-react';

export default function ScannerView({ onNavigate }) {
  const [buildCommand, setBuildCommand] = useState('clang -fsanitize=address,undefined -g target.c -o binary');
  const [povPath, setPovPath] = useState('benchmark_workspace/pov_payload.bin');
  const [isScanning, setIsScanning] = useState(false);

  const [toggles, setToggles] = useState({
    fuzzing: true,
    hardening: true,
    formal: true,
    memory: true
  });

  const handleStartScan = () => {
    setIsScanning(true);
    setTimeout(() => {
      onNavigate('pipeline');
    }, 1200);
  };

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '14px', height: '100%', justifyContent: 'space-between' }}>
      
      {/* Header */}
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
            TARGET SETUP // REPOSITORY SCANNER
          </div>
          <h1 style={{ fontSize: '20px', fontWeight: 800, color: '#FFFFFF', letterSpacing: '-0.02em', marginTop: '2px' }}>
            Target & Scanner Hub
          </h1>
        </div>
      </div>

      {/* Split Grid: Left Form Setup + Right Console Log (Fits 1 screen) */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '14px', flex: 1, minHeight: 0 }}>
        
        {/* Left Form Setup */}
        <div className="stat-card-sample" style={{ padding: '18px 20px', display: 'flex', flexDirection: 'column', gap: '14px', height: '100%' }}>
          <h2 style={{ fontSize: '14px', fontWeight: 700, color: '#FFFFFF', display: 'flex', alignItems: 'center', gap: '8px' }}>
            <FolderPlus size={16} color="var(--cyan-primary)" />
            Project & Scan Setup
          </h2>

          {/* Folder Dropzone */}
          <div style={{
            border: '1.5px dashed rgba(53, 230, 200, 0.3)',
            borderRadius: '10px',
            padding: '16px',
            textAlign: 'center',
            background: 'rgba(53, 230, 200, 0.03)',
            cursor: 'pointer'
          }}>
            <FileCode size={28} color="var(--cyan-primary)" style={{ marginBottom: '6px', opacity: 0.8 }} />
            <div style={{ fontSize: '13px', fontWeight: 600, color: '#FFFFFF' }}>
              Drop C/C++ Project Folder Here
            </div>
            <div style={{ fontSize: '11px', color: '#8E9BAE', marginTop: '2px' }}>
              Selected: <span className="font-mono" style={{ color: '#35E6C8' }}>cJSON (CVE-2019-11834)</span>
            </div>
          </div>

          {/* Build Command Input */}
          <div>
            <label style={{ fontSize: '11px', fontWeight: 600, color: '#8E9BAE', display: 'block', marginBottom: '4px' }}>
              Build Command (Compiler & Sanitizers)
            </label>
            <input 
              type="text"
              value={buildCommand}
              onChange={(e) => setBuildCommand(e.target.value)}
              className="font-mono"
              style={{
                width: '100%',
                background: 'rgba(4, 7, 17, 0.8)',
                border: '1px solid rgba(53, 230, 200, 0.3)',
                borderRadius: '6px',
                padding: '8px 10px',
                color: 'var(--cyan-primary)',
                fontSize: '11px',
                outline: 'none'
              }}
            />
          </div>

          {/* PoV Payload Input */}
          <div>
            <label style={{ fontSize: '11px', fontWeight: 600, color: '#8E9BAE', display: 'block', marginBottom: '4px' }}>
              Proof-of-Vulnerability (PoV) Payload Path / Input
            </label>
            <input 
              type="text"
              value={povPath}
              onChange={(e) => setPovPath(e.target.value)}
              className="font-mono"
              style={{
                width: '100%',
                background: 'rgba(4, 7, 17, 0.8)',
                border: '1px solid rgba(53, 230, 200, 0.3)',
                borderRadius: '6px',
                padding: '8px 10px',
                color: '#FFFFFF',
                fontSize: '11px',
                outline: 'none'
              }}
            />
          </div>

          {/* Execution Option Toggles */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
            <label style={{ fontSize: '11px', fontWeight: 600, color: '#8E9BAE' }}>
              Verification Engines & Safeguards
            </label>
            
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '8px' }}>
              <div 
                onClick={() => setToggles({...toggles, fuzzing: !toggles.fuzzing})}
                style={{
                  padding: '8px 10px',
                  borderRadius: '8px',
                  background: toggles.fuzzing ? 'rgba(53, 230, 200, 0.1)' : 'rgba(255,255,255,0.03)',
                  border: `1px solid ${toggles.fuzzing ? 'rgba(53, 230, 200, 0.4)' : 'rgba(255,255,255,0.08)'}`,
                  cursor: 'pointer',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '8px'
                }}
              >
                <div style={{ width: '8px', height: '8px', borderRadius: '50%', background: toggles.fuzzing ? 'var(--cyan-primary)' : 'var(--text-dim)' }} />
                <span style={{ fontSize: '11px', fontWeight: 600, color: toggles.fuzzing ? '#FFFFFF' : '#8E9BAE' }}>
                  Coverage Fuzzing
                </span>
              </div>

              <div 
                onClick={() => setToggles({...toggles, hardening: !toggles.hardening})}
                style={{
                  padding: '8px 10px',
                  borderRadius: '8px',
                  background: toggles.hardening ? 'rgba(0, 229, 124, 0.1)' : 'rgba(255,255,255,0.03)',
                  border: `1px solid ${toggles.hardening ? 'rgba(0, 229, 124, 0.4)' : 'rgba(255,255,255,0.08)'}`,
                  cursor: 'pointer',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '8px'
                }}
              >
                <div style={{ width: '8px', height: '8px', borderRadius: '50%', background: toggles.hardening ? 'var(--neon-green)' : 'var(--text-dim)' }} />
                <span style={{ fontSize: '11px', fontWeight: 600, color: toggles.hardening ? '#FFFFFF' : '#8E9BAE' }}>
                  Patch Hardening
                </span>
              </div>

              <div 
                onClick={() => setToggles({...toggles, formal: !toggles.formal})}
                style={{
                  padding: '8px 10px',
                  borderRadius: '8px',
                  background: toggles.formal ? 'rgba(180, 130, 255, 0.1)' : 'rgba(255,255,255,0.03)',
                  border: `1px solid ${toggles.formal ? 'rgba(180, 130, 255, 0.4)' : 'rgba(255,255,255,0.08)'}`,
                  cursor: 'pointer',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '8px'
                }}
              >
                <div style={{ width: '8px', height: '8px', borderRadius: '50%', background: toggles.formal ? 'var(--violet-purple)' : 'var(--text-dim)' }} />
                <span style={{ fontSize: '11px', fontWeight: 600, color: toggles.formal ? '#FFFFFF' : '#8E9BAE' }}>
                  CBMC Formal Proof
                </span>
              </div>

              <div 
                onClick={() => setToggles({...toggles, memory: !toggles.memory})}
                style={{
                  padding: '8px 10px',
                  borderRadius: '8px',
                  background: toggles.memory ? 'rgba(255, 159, 67, 0.1)' : 'rgba(255,255,255,0.03)',
                  border: `1px solid ${toggles.memory ? 'rgba(255, 159, 67, 0.4)' : 'rgba(255,255,255,0.08)'}`,
                  cursor: 'pointer',
                  display: 'flex',
                  alignItems: 'center',
                  gap: '8px'
                }}
              >
                <div style={{ width: '8px', height: '8px', borderRadius: '50%', background: toggles.memory ? 'var(--amber-orange)' : 'var(--text-dim)' }} />
                <span style={{ fontSize: '11px', fontWeight: 600, color: toggles.memory ? '#FFFFFF' : '#8E9BAE' }}>
                  4-Tier Memory Engine
                </span>
              </div>
            </div>
          </div>

          {/* Submit Button */}
          <button
            onClick={handleStartScan}
            disabled={isScanning}
            style={{
              padding: '12px',
              borderRadius: '8px',
              background: 'linear-gradient(135deg, #35E6C8 0%, #00E57C 100%)',
              border: 'none',
              color: '#040711',
              fontSize: '13px',
              fontWeight: 800,
              cursor: 'pointer',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'center',
              gap: '6px',
              boxShadow: '0 0 15px rgba(53, 230, 200, 0.3)',
              marginTop: 'auto'
            }}
          >
            <Play size={16} fill="#040711" />
            {isScanning ? 'INITIATING REPAIR PIPELINE...' : 'START SCAN & REPRODUCTION'}
          </button>
        </div>

        {/* Right Console Log */}
        <div className="stat-card-sample" style={{ padding: '18px 20px', display: 'flex', flexDirection: 'column', height: '100%' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '12px' }}>
            <div style={{ fontSize: '13px', fontWeight: 700, color: '#FFFFFF', display: 'flex', alignItems: 'center', gap: '6px' }}>
              <Terminal size={16} color="var(--cyan-primary)" />
              Scan & Reproduction Logs
            </div>
            <span style={{ fontSize: '10px', fontFamily: 'var(--font-mono)', color: 'var(--neon-green)' }}>
              LIVE PRE-FLIGHT
            </span>
          </div>

          <div 
            className="font-mono"
            style={{
              flex: 1,
              background: '#040711',
              borderRadius: '8px',
              border: '1px solid rgba(53, 230, 200, 0.2)',
              padding: '14px',
              fontSize: '11px',
              lineHeight: 1.5,
              color: '#CFE0F0',
              overflowY: 'auto'
            }}
          >
            <div style={{ color: 'var(--cyan-primary)' }}>[INFO] Pre-flight checks started...</div>
            <div style={{ color: '#8E9BAE' }}>[INFO] Validating build command: clang -fsanitize=address,undefined target.c</div>
            <div style={{ color: 'var(--neon-green)' }}>[EXEC] Compiling target.c with ASan and UBSan...</div>
            <div style={{ color: '#8E9BAE' }}>clang -fsanitize=address,undefined target.c -o target</div>
            <div style={{ color: 'var(--neon-green)' }}>[INFO] Compilation successful.</div>
            <div style={{ color: 'var(--amber-orange)' }}>[INFO] Starting PoV crash reproduction...</div>
            <div style={{ color: 'var(--amber-orange)' }}>[EXEC] Running: ./target &lt; /path/to/pov_payload.bin</div>
            <div style={{ color: 'var(--text-dim)', margin: '6px 0' }}>==================================================</div>
            <div style={{ color: 'var(--coral-red)', fontWeight: 700 }}>
              ==12345==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x603000000100 at pc 0x000000401234
            </div>
            <div style={{ color: 'var(--coral-red)' }}>READ of size 4 at 0x603000000100 thread T0</div>
            <div style={{ color: '#8E9BAE' }}>    #0 0x401233 in parse_string target.c:25</div>
            <div style={{ color: '#8E9BAE' }}>    #1 0x401456 in main target.c:50</div>
            <div style={{ color: 'var(--text-dim)', margin: '6px 0' }}>==================================================</div>
            <div style={{ color: 'var(--neon-green)', fontWeight: 700 }}>
              SUMMARY: AddressSanitizer: heap-buffer-overflow target.c:25 in parse_string
            </div>
            <div style={{ color: 'var(--cyan-primary)', marginTop: '8px', fontWeight: 600 }}>
              ✅ PRE-FLIGHT VERIFIED: Crash reproduced on unpatched target. Ready for multi-agent dispatch!
            </div>
          </div>
        </div>

      </div>
    </div>
  );
}
