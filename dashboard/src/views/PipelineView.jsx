import React, { useState } from 'react';
import { Activity, ShieldCheck, Terminal, Cpu, AlertTriangle, CheckCircle2, Play, Pause, RotateCcw, Zap, Sparkles, Award, Code2 } from 'lucide-react';

export default function PipelineView({ onNavigate }) {
  const [isPaused, setIsPaused] = useState(false);

  const stages = [
    { id: 1, name: '1. Detection', status: 'done', desc: 'Semgrep static' },
    { id: 2, name: '2. AST Context', status: 'done', desc: 'Tree-sitter' },
    { id: 3, name: '3. Ensemble', status: 'active', desc: 'Alpha+Beta+Gamma' },
    { id: 4, name: '4. DRV Sandbox', status: 'active', desc: 'ASan / UBSan' },
    { id: 5, name: '5. Hardening', status: 'pending', desc: 'Adversarial Fuzz' },
    { id: 6, name: '6. CBMC Formal', status: 'pending', desc: 'SMT Solver' }
  ];

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
            REAL-TIME OODA PIPELINE // AGENT RACE TRACK
          </div>
          <h1 style={{ fontSize: '20px', fontWeight: 800, color: '#FFFFFF', letterSpacing: '-0.02em', marginTop: '2px' }}>
            Target: <span style={{ color: 'var(--cyan-primary)' }}>CVE-2019-11834</span> (parse_string heap over-read)
          </h1>
        </div>

        <div style={{ display: 'flex', gap: '8px' }}>
          <button 
            onClick={() => setIsPaused(!isPaused)}
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
            {isPaused ? <Play size={12} fill="#FFFFFF" /> : <Pause size={12} />}
            {isPaused ? 'Resume Race' : 'Pause Race'}
          </button>
          <button 
            onClick={() => onNavigate('prover')}
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
            <ShieldCheck size={14} color="#040711" />
            Inspect Validated Patch Diffs
          </button>
        </div>
      </div>

      {/* Top Section: FULL-WIDTH 6-Stage Node Flow Stepper */}
      <div className="stat-card-sample" style={{ padding: '14px 20px' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', position: 'relative' }}>
          {stages.map((stg, i) => (
            <React.Fragment key={stg.id}>
              <div style={{ display: 'flex', alignItems: 'center', gap: '8px', zIndex: 2 }}>
                <div style={{
                  width: '32px',
                  height: '32px',
                  borderRadius: '8px',
                  background: stg.status === 'done' ? 'rgba(0, 229, 124, 0.18)' :
                              stg.status === 'active' ? 'rgba(53, 230, 200, 0.25)' : 'rgba(255, 255, 255, 0.04)',
                  border: stg.status === 'done' ? '1.5px solid #00E57C' :
                          stg.status === 'active' ? '1.5px solid #35E6C8' : '1px solid rgba(255, 255, 255, 0.1)',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  boxShadow: stg.status === 'active' ? '0 0 12px rgba(53, 230, 200, 0.4)' : 'none'
                }}>
                  {stg.status === 'done' && <CheckCircle2 size={16} color="var(--neon-green)" />}
                  {stg.status === 'active' && <Cpu size={16} color="var(--cyan-primary)" />}
                  {stg.status === 'pending' && <Activity size={14} color="#8E9BAE" />}
                </div>
                
                <div>
                  <div style={{ fontSize: '11px', fontWeight: 700, color: stg.status === 'pending' ? '#8E9BAE' : '#FFFFFF' }}>
                    {stg.name}
                  </div>
                  <div style={{ fontSize: '9.5px', color: '#8E9BAE', fontFamily: 'var(--font-mono)' }}>
                    {stg.desc}
                  </div>
                </div>
              </div>

              {i < stages.length - 1 && (
                <div style={{
                  flex: 1,
                  height: '2px',
                  background: i < 3 ? 'linear-gradient(90deg, #00E57C 0%, #35E6C8 100%)' : 'rgba(255, 255, 255, 0.08)',
                  margin: '0 8px',
                  zIndex: 1
                }} />
              )}
            </React.Fragment>
          ))}
        </div>
      </div>

      {/* Middle Banner: Agent Delta Critic Diagnostic Feedback */}
      <div style={{
        background: 'linear-gradient(135deg, rgba(255, 74, 74, 0.12) 0%, rgba(15, 23, 42, 0.8) 100%)',
        border: '1px solid rgba(255, 74, 74, 0.4)',
        borderRadius: '10px',
        padding: '10px 14px',
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        boxShadow: '0 4px 15px rgba(255, 74, 74, 0.15)'
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
          <div style={{
            width: '28px',
            height: '28px',
            borderRadius: '6px',
            background: 'rgba(255, 74, 74, 0.2)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center'
          }}>
            <AlertTriangle size={16} color="#FF4A4A" />
          </div>
          <div>
            <div style={{ fontSize: '11.5px', fontWeight: 700, color: '#FFFFFF', display: 'flex', alignItems: 'center', gap: '6px' }}>
              Agent Delta Critic Diagnostic Feedback
              <span className="pill-badge pill-critical" style={{ fontSize: '9px', padding: '1px 6px' }}>ATTEMPT GIST #3</span>
            </div>
            <div style={{ fontSize: '10.5px', color: '#CFE0F0', marginTop: '1px' }}>
              Root Cause: <span className="font-mono" style={{ color: '#FF4A4A' }}>heap-buffer-overflow</span> in parse_string (cJSON.c:660). <span style={{ color: '#35E6C8', fontWeight: 600 }}>Guidance: Swap while condition order—check length bounds BEFORE pointer dereference.</span>
            </div>
          </div>
        </div>

        <div style={{ textAlign: 'right', fontFamily: 'var(--font-mono)', fontSize: '10px', color: '#8E9BAE' }}>
          Stall Tracker: <span style={{ color: '#00E57C', fontWeight: 700 }}>1/4 (Evolving)</span>
        </div>
      </div>

      {/* Bottom Section: 3 High-Tech Agent Terminal Race Cards */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '12px', flex: 1, minHeight: 0 }}>
        
        {/* Agent Alpha (Analyst) */}
        <div className="stat-card-sample" style={{ padding: '14px', display: 'flex', flexDirection: 'column', height: '100%' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px', borderBottom: '1px solid rgba(255, 255, 255, 0.06)', paddingBottom: '6px' }}>
            <div style={{ fontSize: '12px', fontWeight: 700, color: '#FFFFFF', display: 'flex', alignItems: 'center', gap: '6px' }}>
              <Terminal size={14} color="#35E6C8" />
              Agent Alpha (Analyst)
            </div>
            <span className="pill-badge pill-high">Iteration 4/5</span>
          </div>

          <div className="font-mono" style={{
            flex: 1,
            background: '#040711',
            borderRadius: '8px',
            border: '1px solid rgba(53, 230, 200, 0.2)',
            padding: '10px 12px',
            fontSize: '10.5px',
            lineHeight: 1.5,
            color: '#CFE0F0',
            overflowY: 'auto'
          }}>
            <div style={{ color: '#35E6C8', fontWeight: 600 }}>[CoT Reasoning & AST Analysis]</div>
            <div style={{ color: '#8E9BAE' }}>Ingesting ASan stack trace...</div>
            <div style={{ color: '#FF4A4A' }}>READ size 4 out-of-bounds at cJSON.c:660</div>
            <div style={{ color: '#FF9F43', marginTop: '4px' }}>Critic Feedback: Reorder short-circuit evaluate</div>
            <div style={{ color: '#00E57C', marginTop: '6px', background: 'rgba(0, 229, 124, 0.1)', padding: '4px', borderRadius: '4px' }}>
              + while (((size_t)(input_end - input_buffer-&gt;content) &lt; input_buffer-&gt;length) &amp;&amp; (*input_end != '"'))
            </div>
            <div style={{ color: '#8E9BAE', marginTop: '4px' }}>Gate 0 Apply: PASS | Gate 1 Build: PASS</div>
            <div style={{ color: '#FF4A4A', marginTop: '2px' }}>Gate 2 PoV Replay: FAIL (Attempt 3)</div>
          </div>
        </div>

        {/* Agent Beta (Minimalist - WINNER) */}
        <div className="stat-card-sample stat-card-sample-green" style={{
          padding: '14px',
          display: 'flex',
          flexDirection: 'column',
          height: '100%',
          border: '1.5px solid #00E57C',
          boxShadow: '0 0 20px rgba(0, 229, 124, 0.15)'
        }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px', borderBottom: '1px solid rgba(0, 229, 124, 0.2)', paddingBottom: '6px' }}>
            <div style={{ fontSize: '12px', fontWeight: 700, color: '#00E57C', display: 'flex', alignItems: 'center', gap: '6px' }}>
              <Award size={14} color="#00E57C" />
              Agent Beta (Minimalist)
            </div>
            <span className="pill-badge pill-low">🏆 WINNER</span>
          </div>

          <div className="font-mono" style={{
            flex: 1,
            background: '#040711',
            borderRadius: '8px',
            border: '1px solid rgba(0, 229, 124, 0.3)',
            padding: '10px 12px',
            fontSize: '10.5px',
            lineHeight: 1.5,
            color: '#CFE0F0',
            overflowY: 'auto'
          }}>
            <div style={{ color: '#00E57C', fontWeight: 600 }}>[Minimal Condition Swap]</div>
            <div style={{ color: '#8E9BAE' }}>Extracting AST whole-function range...</div>
            <div style={{ color: '#00E57C', marginTop: '4px', background: 'rgba(0, 229, 124, 0.12)', padding: '4px', borderRadius: '4px', borderLeft: '3px solid #00E57C' }}>
              while ((input_end &lt; end) &amp;&amp; (*input_end != '"'))
            </div>
            <div style={{ color: '#00E57C', marginTop: '6px' }}>🟢 Gate 0 Apply: PASS</div>
            <div style={{ color: '#00E57C' }}>🟢 Gate 1 Build ASan+UBSan: PASS</div>
            <div style={{ color: '#00E57C', fontWeight: 700 }}>🟢 Gate 2 PoV Replay: PASS (0 signals)</div>
            <div style={{ color: '#00E57C', fontWeight: 700 }}>🟢 Gate 3 Regression: PASS</div>
            <div style={{ color: '#00E57C', marginTop: '6px', fontWeight: 800, background: 'rgba(0, 229, 124, 0.2)', padding: '6px', borderRadius: '4px', textAlign: 'center' }}>
              ✅ VERIFIED PATCH VALIDATED AT ITERATION 5!
            </div>
          </div>
        </div>

        {/* Agent Gamma (SARIF) */}
        <div className="stat-card-sample" style={{ padding: '14px', display: 'flex', flexDirection: 'column', height: '100%' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px', borderBottom: '1px solid rgba(255, 255, 255, 0.06)', paddingBottom: '6px' }}>
            <div style={{ fontSize: '12px', fontWeight: 700, color: '#FFFFFF', display: 'flex', alignItems: 'center', gap: '6px' }}>
              <Terminal size={14} color="#B482FF" />
              Agent Gamma (SARIF)
            </div>
            <span className="pill-badge pill-medium">Iteration 3/5</span>
          </div>

          <div className="font-mono" style={{
            flex: 1,
            background: '#040711',
            borderRadius: '8px',
            border: '1px solid rgba(180, 130, 255, 0.2)',
            padding: '10px 12px',
            fontSize: '10.5px',
            lineHeight: 1.5,
            color: '#CFE0F0',
            overflowY: 'auto'
          }}>
            <div style={{ color: '#B482FF', fontWeight: 600 }}>[SARIF Template Fixer]</div>
            <div style={{ color: '#8E9BAE' }}>Ingesting rule: p/security-audit</div>
            <div style={{ color: '#00E57C', marginTop: '4px' }}>🟢 Gate 0 Apply: PASS</div>
            <div style={{ color: '#00E57C' }}>🟢 Gate 1 Build ASan: PASS</div>
            <div style={{ color: '#00E57C' }}>🟢 Gate 2 PoV Replay: PASS</div>
            <div style={{ color: '#B482FF', marginTop: '6px' }}>
              Candidate patch validated. Standing by for minimal patch winner selection.
            </div>
          </div>
        </div>

      </div>
    </div>
  );
}
