import React from 'react';
import { MOCK_KPIS, MOCK_VULNERABILITIES } from '../data/mockData';
import { ShieldAlert, CheckCircle2, ShieldCheck, Zap } from 'lucide-react';

export default function DashboardView({ onNavigate }) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '14px', height: '100%', justifyContent: 'space-between' }}>
      
      {/* Top Row: All 6 Hero Stat Cards in ONE Horizontal Line */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(6, 1fr)', gap: '12px' }}>
        
        <div className="stat-card-sample" style={{ padding: '10px 14px' }}>
          <div style={{ fontSize: '11px', color: '#8E9BAE', fontWeight: 500, whiteSpace: 'nowrap' }}>
            Targets Scanned
          </div>
          <div className="font-mono" style={{ fontSize: '24px', fontWeight: 800, color: '#35E6C8', marginTop: '4px', textShadow: '0 0 12px rgba(53, 230, 200, 0.4)' }}>
            {MOCK_KPIS.targetsScanned}
          </div>
        </div>

        <div className="stat-card-sample stat-card-sample-green" style={{ padding: '10px 14px' }}>
          <div style={{ fontSize: '11px', color: '#8E9BAE', fontWeight: 500, whiteSpace: 'nowrap' }}>
            Pass Rate
          </div>
          <div className="font-mono" style={{ fontSize: '24px', fontWeight: 800, color: '#00E57C', marginTop: '4px', textShadow: '0 0 12px rgba(0, 229, 124, 0.4)' }}>
            {MOCK_KPIS.passRate}
          </div>
        </div>

        <div className="stat-card-sample" style={{ padding: '10px 14px' }}>
          <div style={{ fontSize: '11px', color: '#8E9BAE', fontWeight: 500, whiteSpace: 'nowrap' }}>
            PoV Proven
          </div>
          <div className="font-mono" style={{ fontSize: '24px', fontWeight: 800, color: '#35E6C8', marginTop: '4px', textShadow: '0 0 12px rgba(53, 230, 200, 0.4)' }}>
            {MOCK_KPIS.povProven}
          </div>
        </div>

        <div className="stat-card-sample stat-card-sample-green" style={{ padding: '10px 14px' }}>
          <div style={{ fontSize: '11px', color: '#8E9BAE', fontWeight: 500, whiteSpace: 'nowrap' }}>
            Hardening
          </div>
          <div className="font-mono" style={{ fontSize: '24px', fontWeight: 800, color: '#00E57C', marginTop: '4px', textShadow: '0 0 12px rgba(0, 229, 124, 0.4)' }}>
            {MOCK_KPIS.hardening}
          </div>
        </div>

        <div className="stat-card-sample" style={{ padding: '10px 14px' }}>
          <div style={{ fontSize: '11px', color: '#8E9BAE', fontWeight: 500, whiteSpace: 'nowrap' }}>
            Formal Proofs
          </div>
          <div className="font-mono" style={{ fontSize: '24px', fontWeight: 800, color: '#35E6C8', marginTop: '4px', textShadow: '0 0 12px rgba(53, 230, 200, 0.4)' }}>
            {MOCK_KPIS.formalProofs}
          </div>
        </div>

        <div className="stat-card-sample stat-card-sample-green" style={{ padding: '10px 14px' }}>
          <div style={{ fontSize: '11px', color: '#8E9BAE', fontWeight: 500, whiteSpace: 'nowrap' }}>
            Compute Cost
          </div>
          <div className="font-mono" style={{ fontSize: '24px', fontWeight: 800, color: '#00E57C', marginTop: '4px', textShadow: '0 0 12px rgba(0, 229, 124, 0.4)' }}>
            {MOCK_KPIS.computeCost}
          </div>
        </div>

      </div>

      {/* Middle Section: FULL WIDTH (100%) Recent Vulnerabilities Table */}
      <div className="stat-card-sample" style={{ padding: '14px 18px', flex: 1, display: 'flex', flexDirection: 'column', minHeight: 0 }}>
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '10px' }}>
          <div>
            <h2 style={{ fontSize: '14px', fontWeight: 700, color: '#FFFFFF' }}>
              Recent Vulnerabilities Feed
            </h2>
            <p style={{ fontSize: '11px', color: '#8E9BAE', marginTop: '1px' }}>
              Ground-truth verified patches with ASan/UBSan & CBMC formal proof logs
            </p>
          </div>
          <div style={{ fontSize: '11px', color: '#35E6C8', display: 'flex', alignItems: 'center', gap: '4px', cursor: 'pointer' }} onClick={() => onNavigate('prover')}>
            Inspect Code Diffs →
          </div>
        </div>

        {/* Full Width Table */}
        <div style={{ flex: 1, overflowY: 'auto' }}>
          <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left' }}>
            <thead>
              <tr style={{ borderBottom: '1px solid rgba(255, 255, 255, 0.08)' }}>
                <th style={{ padding: '8px 10px', fontSize: '11px', color: '#8E9BAE', fontWeight: 500 }}>Target ID / Description</th>
                <th style={{ padding: '8px 10px', fontSize: '11px', color: '#8E9BAE', fontWeight: 500 }}>CWE</th>
                <th style={{ padding: '8px 10px', fontSize: '11px', color: '#8E9BAE', fontWeight: 500 }}>Severity</th>
                <th style={{ padding: '8px 10px', fontSize: '11px', color: '#8E9BAE', fontWeight: 500 }}>DRV Gates</th>
                <th style={{ padding: '8px 10px', fontSize: '11px', color: '#8E9BAE', fontWeight: 500 }}>CBMC Proof</th>
                <th style={{ padding: '8px 10px', fontSize: '11px', color: '#8E9BAE', fontWeight: 500 }}>Winning Agent</th>
                <th style={{ padding: '8px 10px', fontSize: '11px', color: '#8E9BAE', fontWeight: 500 }}>Status</th>
              </tr>
            </thead>
            <tbody>
              {MOCK_VULNERABILITIES.map((v) => (
                <tr 
                  key={v.id} 
                  onClick={() => onNavigate('prover')}
                  style={{ borderBottom: '1px solid rgba(255, 255, 255, 0.04)', cursor: 'pointer' }}
                >
                  <td style={{ padding: '8px 10px' }}>
                    <div style={{ fontWeight: 600, fontSize: '12px', color: '#FFFFFF' }}>{v.id}</div>
                    <div style={{ fontSize: '10.5px', color: '#8E9BAE' }}>{v.title}</div>
                  </td>
                  <td style={{ padding: '8px 10px' }}>
                    <span className="font-mono" style={{ fontSize: '11px', color: '#35E6C8', fontWeight: 600 }}>{v.cwe}</span>
                  </td>
                  <td style={{ padding: '8px 10px' }}>
                    <span className={
                      v.severity === 'CRITICAL' ? 'pill-badge pill-critical' :
                      v.severity === 'HIGH' ? 'pill-badge pill-high' : 'pill-badge pill-medium'
                    }>
                      {v.severity}
                    </span>
                  </td>
                  <td style={{ padding: '8px 10px', fontSize: '11px', color: '#00E57C', fontFamily: 'var(--font-mono)', fontWeight: 600 }}>
                    {v.drvGates}
                  </td>
                  <td style={{ padding: '8px 10px', fontSize: '11px', color: '#35E6C8', fontFamily: 'var(--font-mono)' }}>
                    {v.cbmcStatus}
                  </td>
                  <td style={{ padding: '8px 10px', fontSize: '11px', color: '#8E9BAE' }}>
                    {v.winningAgent}
                  </td>
                  <td style={{ padding: '8px 10px' }}>
                    <span className="pill-badge pill-low">
                      <CheckCircle2 size={10} style={{ marginRight: '4px' }} />
                      {v.status}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Bottom Section: Sleek 3-Column Horizontal Status Cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '12px' }}>
        
        {/* Card 1: Threat Severity Breakdown */}
        <div className="stat-card-sample stat-card-sample-red" style={{ padding: '12px 16px', display: 'flex', alignItems: 'center', gap: '16px' }}>
          <div style={{ position: 'relative', width: '56px', height: '56px' }}>
            <svg width="56" height="56" viewBox="0 0 100 100">
              <circle cx="50" cy="50" r="38" fill="none" stroke="rgba(255,255,255,0.06)" strokeWidth="8" />
              <circle cx="50" cy="50" r="38" fill="none" stroke="#FF4A4A" strokeWidth="8" strokeDasharray="238" strokeDashoffset="45" strokeLinecap="round" transform="rotate(-90 50 50)" />
            </svg>
            <div style={{ position: 'absolute', top: '50%', left: '50%', transform: 'translate(-50%, -50%)' }}>
              <ShieldAlert size={16} color="#FF4A4A" />
            </div>
          </div>
          <div style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: '2px' }}>
            <div style={{ fontSize: '12px', fontWeight: 700, color: '#FFFFFF' }}>Threat Severity Breakdown</div>
            <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '10.5px' }}>
              <span style={{ color: '#8E9BAE' }}>Critical (Red):</span>
              <span className="font-mono" style={{ color: '#FF4A4A', fontWeight: 700 }}>4 Critical</span>
            </div>
            <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '10.5px' }}>
              <span style={{ color: '#8E9BAE' }}>High (Orange):</span>
              <span className="font-mono" style={{ color: '#FF9F43', fontWeight: 700 }}>2 High</span>
            </div>
          </div>
        </div>

        {/* Card 2: System Engine Utilization */}
        <div className="stat-card-sample" style={{ padding: '12px 16px', display: 'flex', flexDirection: 'column', justifyContent: 'center' }}>
          <div style={{ fontSize: '12px', fontWeight: 700, color: '#FFFFFF', marginBottom: '6px' }}>System Engine Utilization</div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '8px' }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
              <div className="accent-vertical-line" />
              <div>
                <div className="font-mono" style={{ fontSize: '15px', fontWeight: 800, color: '#FFFFFF' }}>80%</div>
                <div style={{ fontSize: '9.5px', color: '#8E9BAE' }}>CPU Core Unit</div>
              </div>
            </div>
            <div>
              <div className="font-mono" style={{ fontSize: '15px', fontWeight: 800, color: '#00E57C' }}>56%</div>
              <div style={{ fontSize: '9.5px', color: '#8E9BAE' }}>Hardening Status</div>
            </div>
          </div>
        </div>

        {/* Card 3: Professional Autonomous Verification Suite */}
        <div className="stat-card-sample stat-card-sample-green" style={{ padding: '12px 16px', display: 'flex', flexDirection: 'column', justifyContent: 'center' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '6px' }}>
            <div style={{ fontSize: '12px', fontWeight: 700, color: '#FFFFFF', display: 'flex', alignItems: 'center', gap: '6px' }}>
              <ShieldCheck size={14} color="#00E57C" />
              Autonomous Verification Suite
            </div>
            <span className="pill-badge pill-low" style={{ fontSize: '9px', padding: '1px 6px' }}>100% PASSED</span>
          </div>

          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '6px', fontSize: '10px' }}>
            <div style={{ background: '#040711', padding: '6px 8px', borderRadius: '6px', border: '1px solid rgba(255, 255, 255, 0.06)' }}>
              <div style={{ color: '#8E9BAE', fontSize: '9px' }}>CBMC SMT Solver</div>
              <div className="font-mono" style={{ color: '#35E6C8', fontWeight: 700, fontSize: '11px' }}>14 Formal Proofs</div>
            </div>
            <div style={{ background: '#040711', padding: '6px 8px', borderRadius: '6px', border: '1px solid rgba(255, 255, 255, 0.06)' }}>
              <div style={{ color: '#8E9BAE', fontSize: '9px' }}>PoV Sanitizer Replay</div>
              <div className="font-mono" style={{ color: '#00E57C', fontWeight: 700, fontSize: '11px' }}>21/21 Replays Passed</div>
            </div>
          </div>
        </div>

      </div>

    </div>
  );
}
