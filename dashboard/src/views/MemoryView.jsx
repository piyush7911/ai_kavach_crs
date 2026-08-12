import React, { useState } from 'react';
import { MOCK_MEMORY_PATTERNS } from '../data/mockData';
import { Search, AlertCircle } from 'lucide-react';

export default function MemoryView() {
  const [search, setSearch] = useState('');
  const [activeTier, setActiveTier] = useState('semantic');

  const filteredPatterns = MOCK_MEMORY_PATTERNS.filter(p => 
    p.cwe.toLowerCase().includes(search.toLowerCase()) ||
    p.crashClass.toLowerCase().includes(search.toLowerCase()) ||
    p.rootCause.toLowerCase().includes(search.toLowerCase())
  );

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
            CROSS-RUN REASONING // KNOWLEDGE STORE
          </div>
          <h1 style={{ fontSize: '20px', fontWeight: 800, color: '#FFFFFF', letterSpacing: '-0.02em', marginTop: '2px' }}>
            Semantic Memory Hub
          </h1>
        </div>

        <div style={{ position: 'relative', width: '240px' }}>
          <Search size={14} color="#8E9BAE" style={{ position: 'absolute', left: '10px', top: '50%', transform: 'translateY(-50%)' }} />
          <input 
            type="text"
            placeholder="Search CWE pattern..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            style={{
              width: '100%',
              background: 'rgba(4, 7, 17, 0.8)',
              border: '1px solid rgba(53, 230, 200, 0.3)',
              borderRadius: '8px',
              padding: '6px 10px 6px 30px',
              color: '#FFFFFF',
              fontSize: '11px',
              outline: 'none'
            }}
          />
        </div>
      </div>

      {/* 4 Tier Tabs */}
      <div style={{ display: 'flex', gap: '10px' }}>
        {[
          { id: 'working', label: '1. Working Memory' },
          { id: 'episodic', label: '2. Episodic Trajectories' },
          { id: 'semantic', label: '3. Semantic Fix Patterns' },
          { id: 'procedural', label: '4. Procedural Routing' }
        ].map(t => (
          <button
            key={t.id}
            onClick={() => setActiveTier(t.id)}
            style={{
              padding: '6px 14px',
              borderRadius: '8px',
              background: activeTier === t.id ? 'rgba(53, 230, 200, 0.15)' : 'rgba(255, 255, 255, 0.03)',
              border: activeTier === t.id ? '1px solid rgba(53, 230, 200, 0.4)' : '1px solid rgba(255, 255, 255, 0.08)',
              color: activeTier === t.id ? 'var(--cyan-primary)' : '#8E9BAE',
              fontSize: '11px',
              fontWeight: 600,
              cursor: 'pointer'
            }}
          >
            {t.label}
          </button>
        ))}
      </div>

      {/* Pattern Cards Grid (Fits height) */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '12px', flex: 1, minHeight: 0 }}>
        {filteredPatterns.map((pat, i) => (
          <div key={i} className="stat-card-sample" style={{ padding: '16px', display: 'flex', flexDirection: 'column', gap: '10px', height: '100%' }}>
            
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
              <div>
                <span className={pat.cwe === 'CWE-125' || pat.cwe === 'CWE-122' ? 'pill-badge pill-critical' : 'pill-badge pill-high'}>
                  {pat.cwe}
                </span>
                <div style={{ fontSize: '13px', fontWeight: 700, color: '#FFFFFF', marginTop: '6px' }}>
                  {pat.crashClass}
                </div>
              </div>
              <div style={{ textAlign: 'right' }}>
                <div style={{ fontSize: '10px', color: '#8E9BAE' }}>Confidence</div>
                <div className="font-mono" style={{ fontSize: '14px', fontWeight: 700, color: 'var(--neon-green)' }}>
                  {(pat.confidence * 100).toFixed(0)}%
                </div>
              </div>
            </div>

            <div>
              <div style={{ fontSize: '10px', color: '#8E9BAE', textTransform: 'uppercase', fontFamily: 'var(--font-mono)' }}>
                Root Cause Signature
              </div>
              <div style={{ fontSize: '11px', color: '#CFE0F0', marginTop: '2px', lineHeight: 1.4 }}>
                {pat.rootCause}
              </div>
            </div>

            <div>
              <div style={{ fontSize: '10px', color: 'var(--neon-green)', textTransform: 'uppercase', fontFamily: 'var(--font-mono)' }}>
                Proven Fix Strategy
              </div>
              <div style={{ fontSize: '11px', color: '#FFFFFF', marginTop: '2px', lineHeight: 1.4, fontWeight: 500 }}>
                {pat.fixStrategy}
              </div>
            </div>

            <div style={{ marginTop: 'auto', paddingTop: '8px', borderTop: '1px solid rgba(255, 255, 255, 0.06)' }}>
              <div style={{ fontSize: '10px', color: 'var(--amber-orange)', textTransform: 'uppercase', fontFamily: 'var(--font-mono)', marginBottom: '4px' }}>
                Observed Pitfalls
              </div>
              {pat.pitfalls.map((pit, idx) => (
                <div key={idx} style={{ fontSize: '10px', color: '#8E9BAE', display: 'flex', alignItems: 'center', gap: '4px', marginTop: '2px' }}>
                  <AlertCircle size={10} color="var(--amber-orange)" />
                  {pit}
                </div>
              ))}
            </div>

          </div>
        ))}
      </div>

    </div>
  );
}
