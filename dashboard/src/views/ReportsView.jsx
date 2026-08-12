import React, { useState } from 'react';
import { Download, FileJson, Award } from 'lucide-react';

export default function ReportsView() {
  const [reportType, setReportType] = useState('full');

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: '12px', height: '100%', justifyContent: 'space-between' }}>
      
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
            COMPLIANCE // AUDIT REPORT GENERATOR
          </div>
          <h1 style={{ fontSize: '20px', fontWeight: 800, color: '#FFFFFF', letterSpacing: '-0.02em', marginTop: '2px' }}>
            Executive Audit & Compliance Reports
          </h1>
        </div>

        <div style={{ display: 'flex', gap: '10px' }}>
          <button className="stat-card-sample" style={{
            padding: '8px 14px',
            background: 'rgba(255, 255, 255, 0.05)',
            border: '1px solid rgba(255, 255, 255, 0.15)',
            color: '#FFFFFF',
            fontWeight: 600,
            fontSize: '12px',
            cursor: 'pointer',
            display: 'flex',
            alignItems: 'center',
            gap: '6px'
          }}>
            <FileJson size={14} /> Export SARIF v2.1.0
          </button>
          <button className="stat-card-sample" style={{
            padding: '8px 16px',
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
          }}>
            <Download size={14} /> Export PDF Audit Report
          </button>
        </div>
      </div>

      {/* Main Grid (Fits Height) */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 2.5fr', gap: '14px', flex: 1, minHeight: 0 }}>
        
        {/* Template Selector */}
        <div className="stat-card-sample" style={{ padding: '16px', display: 'flex', flexDirection: 'column', gap: '10px' }}>
          <h2 style={{ fontSize: '13px', fontWeight: 700, color: '#FFFFFF' }}>
            Report Templates
          </h2>

          {[
            { id: 'full', title: 'Full Cyber Defense Security Audit', desc: 'Complete breakdown with ASan logs & formal proofs' },
            { id: 'dev', title: 'Developer Remediation Summary', desc: 'Minimal unified diffs and AST splice ranges' },
            { id: 'sarif', title: 'SARIF v2.1.0 Compliance Schema', desc: 'Standardized JSON schema for enterprise SIEM' }
          ].map((tmpl) => (
            <div 
              key={tmpl.id}
              onClick={() => setReportType(tmpl.id)}
              style={{
                padding: '12px',
                borderRadius: '8px',
                background: reportType === tmpl.id ? 'rgba(53, 230, 200, 0.1)' : 'rgba(4, 7, 17, 0.6)',
                border: reportType === tmpl.id ? '1px solid rgba(53, 230, 200, 0.4)' : '1px solid rgba(255, 255, 255, 0.06)',
                cursor: 'pointer'
              }}
            >
              <div style={{ fontSize: '12px', fontWeight: 700, color: reportType === tmpl.id ? 'var(--cyan-primary)' : '#FFFFFF' }}>
                {tmpl.title}
              </div>
              <div style={{ fontSize: '10px', color: '#8E9BAE', marginTop: '2px', lineHeight: 1.3 }}>
                {tmpl.desc}
              </div>
            </div>
          ))}
        </div>

        {/* Live Document Preview */}
        <div className="stat-card-sample" style={{ padding: '20px', display: 'flex', flexDirection: 'column', gap: '14px', overflowY: 'auto' }}>
          
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', borderBottom: '1px solid rgba(255, 255, 255, 0.08)', paddingBottom: '12px' }}>
            <div>
              <div style={{ fontSize: '11px', fontFamily: 'var(--font-mono)', color: 'var(--cyan-primary)', fontWeight: 700 }}>
                CONFIDENTIAL // AI KAVACH CRS AUDIT CERTIFICATE
              </div>
              <h2 style={{ fontSize: '18px', fontWeight: 800, color: '#FFFFFF', marginTop: '2px' }}>
                Autonomous Remediation Verification Report
              </h2>
            </div>
            <Award size={28} color="var(--neon-green)" />
          </div>

          <div style={{ display: 'flex', flexDirection: 'column', gap: '14px', fontSize: '12px', lineHeight: 1.5, color: '#CFE0F0' }}>
            <div>
              <h3 style={{ fontSize: '13px', color: '#FFFFFF', fontWeight: 700, marginBottom: '4px' }}>
                1. Executive Summary
              </h3>
              <p>
                AI Kavach Cyber Reasoning System analyzed 37 target software units, resolving 100% of detected memory-safety vulnerabilities. 21 of 21 targets with reproducible runtime exploits were dynamically proven resolved against the exact crashing payload under AddressSanitizer and UndefinedBehaviorSanitizer instrumentation.
              </p>
            </div>

            <div>
              <h3 style={{ fontSize: '13px', color: '#FFFFFF', fontWeight: 700, marginBottom: '4px' }}>
                2. Key Verification Highlights
              </h3>
              <ul style={{ paddingLeft: '16px', display: 'flex', flexDirection: 'column', gap: '4px' }}>
                <li><strong>Real-World CVE Suite:</strong> 3/3 real published CVEs in unmodified cJSON (CVE-2019-11835, CVE-2019-11834, GH-800) patched and hardened.</li>
                <li><strong>Phase 6 Patch Hardening:</strong> 34 of 34 patches survived 20-second adversarial re-fuzzing and 25 differential test cases.</li>
                <li><strong>Phase 7 CBMC Formal Proofs:</strong> 14 target functions bit-precisely proven safe against arithmetic overflow and out-of-bounds indexing.</li>
              </ul>
            </div>

            <div className="font-mono" style={{ background: '#040711', padding: '12px', borderRadius: '8px', fontSize: '11px', color: 'var(--cyan-primary)' }}>
              Total Wall Time: 794.0s | LLM Spend: $0.0521 | Avg Cost/Target: ~$0.0014 | 102/102 Unit Tests Passing
            </div>
          </div>

        </div>

      </div>
    </div>
  );
}
