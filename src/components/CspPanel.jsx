import React, { useState } from 'react';

/**
 * CspPanel Component
 * WHY: Provides interactive education on Content Security Policy (CSP).
 * Outlines how CSP forms the final, critical layer of defence against XSS
 * even when input validation and output sanitization fail.
 * Features a live simulator to test how policies handle dynamic scripts.
 */
export function CspPanel() {
  const [isOpen, setIsOpen] = useState(false);
  const [selectedPreset, setSelectedPreset] = useState('strict');
  const [customDirective, setCustomDirective] = useState("script-src 'self' https://trustedscripts.com");
  const [testScriptType, setTestScriptType] = useState('inline');
  const [testScriptSource, setTestScriptSource] = useState('alert(1)');

  // Policy Presets config
  const policyPresets = {
    strict: {
      name: "🔒 Strict (Best Practice)",
      header: "Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none';",
      desc: "Only load scripts hosted on the exact same domain. Block all inline scripts, iframes, and plug-ins.",
      rules: {
        inline: false,
        externalSelf: true,
        externalThirdParty: false,
        eval: false
      }
    },
    medium: {
      name: "🛡️ Standard (Permissive Third-Party)",
      header: "Content-Security-Policy: default-src 'self'; script-src 'self' https://apis.google.com; object-src 'none';",
      desc: "Allows scripts from self and google APIs domain. Still blocks dangerous inline scripts.",
      rules: {
        inline: false,
        externalSelf: true,
        externalThirdParty: true, // google apis would pass
        eval: false
      }
    },
    unsafe: {
      name: "⚠️ Unsafe Inline (Vulnerable)",
      header: "Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval';",
      desc: "Allows inline scripts (<script>alert(1)</script>) and eval(). Highly vulnerable to XSS!",
      rules: {
        inline: true,
        externalSelf: true,
        externalThirdParty: false,
        eval: true
      }
    },
    none: {
      name: "🚫 Block All Scripts",
      header: "Content-Security-Policy: default-src 'self'; script-src 'none';",
      desc: "Completely disables JavaScript execution on the website. Maximally secure but breaks most modern apps.",
      rules: {
        inline: false,
        externalSelf: false,
        externalThirdParty: false,
        eval: false
      }
    }
  };

  // Run simulation checks
  const simulateCheck = () => {
    const rules = policyPresets[selectedPreset].rules;
    if (testScriptType === 'inline') {
      return rules.inline 
        ? { allowed: true, reason: "Allowed because 'unsafe-inline' is explicitly included in the policy." }
        : { allowed: false, reason: "Blocked! Strict CSP forbids inline scripts to prevent XSS payloads injecting directly into HTML." };
    } else if (testScriptType === 'external-self') {
      return rules.externalSelf
        ? { allowed: true, reason: "Allowed because scripts hosted on your own server ('self') are permitted." }
        : { allowed: false, reason: "Blocked! The policy blocks all script sources, even from your own server." };
    } else if (testScriptType === 'external-third') {
      if (selectedPreset === 'medium' && testScriptSource.includes('apis.google.com')) {
        return { allowed: true, reason: "Allowed because https://apis.google.com is explicitly whitelisted in this policy." };
      }
      return rules.externalThirdParty
        ? { allowed: true, reason: "Allowed because third-party scripts are permitted." }
        : { allowed: false, reason: `Blocked! '${testScriptSource}' is not whitelisted. Browsers will refuse to fetch or execute it.` };
    } else if (testScriptType === 'eval') {
      return rules.eval
        ? { allowed: true, reason: "Allowed because 'unsafe-eval' is present (unsafe practice)." }
        : { allowed: false, reason: "Blocked! setTimeout/setInterval strings and eval() are blocked to prevent dynamic code injection." };
    }
    return { allowed: false, reason: "Unknown script context." };
  };

  const simResult = simulateCheck();

  return (
    <div className={`csp-panel-container ${isOpen ? 'open' : ''}`}>
      <button 
        className="csp-toggle-btn"
        onClick={() => setIsOpen(!isOpen)}
      >
        <span className="btn-icon">💡</span>
        <div className="btn-text-content">
          <span className="btn-title">Understanding Content Security Policy (CSP)</span>
          <span className="btn-sub">Click to expand the final layer of defence deep-dive</span>
        </div>
        <span className={`arrow-indicator ${isOpen ? 'up' : 'down'}`}>▼</span>
      </button>

      {isOpen && (
        <div className="csp-content-area animate-fade-in">
          
          <div className="csp-explanation-grid">
            <div className="csp-concept-card">
              <h4>🛡️ What is CSP?</h4>
              <p>
                Content Security Policy (CSP) is an HTTP header sent by servers telling the web browser 
                which resources (scripts, styles, images) are trusted and allowed to execute. It acts as 
                a bouncer for web requests.
              </p>
            </div>
            
            <div className="csp-concept-card">
              <h4>🎯 Why is it Critical for XSS?</h4>
              <p>
                Sanitizers like DOMPurify catch attacks on input. But if a clever bypass gets past 
                the sanitizer and lands in the HTML, <strong>CSP is the browser's last line of defence</strong>. 
                Even if the payload is in the DOM, a strict CSP stops the browser from executing it.
              </p>
            </div>
          </div>

          <div className="csp-simulator-section">
            <h4>🧪 Interactive CSP Header Simulator</h4>
            <p className="sim-sub">Select a policy template and see how the browser evaluates script execution requests:</p>
            
            <div className="sim-grid">
              {/* Left Side: Preset selector */}
              <div className="sim-controls">
                <div className="control-group">
                  <label>Select CSP Template:</label>
                  <select 
                    value={selectedPreset} 
                    onChange={(e) => setSelectedPreset(e.target.value)}
                    className="csp-select"
                  >
                    {Object.entries(policyPresets).map(([key, preset]) => (
                      <option key={key} value={key}>{preset.name}</option>
                    ))}
                  </select>
                </div>

                <div className="directive-display">
                  <strong>HTTP Response Header:</strong>
                  <pre className="csp-header-code">
                    <code>{policyPresets[selectedPreset].header}</code>
                  </pre>
                  <p className="preset-desc">{policyPresets[selectedPreset].desc}</p>
                </div>
              </div>

              {/* Middle Side: Simulation Tester */}
              <div className="sim-tester-controls">
                <div className="control-group">
                  <label>Simulate Injected Script Type:</label>
                  <div className="sim-radio-group">
                    <label className="radio-label">
                      <input 
                        type="radio" 
                        name="scriptType" 
                        value="inline"
                        checked={testScriptType === 'inline'}
                        onChange={() => {
                          setTestScriptType('inline');
                          setTestScriptSource("alert('inline XSS')");
                        }} 
                      />
                      Inline Script (e.g. <code>&lt;script&gt;alert(1)&lt;/script&gt;</code>)
                    </label>
                    
                    <label className="radio-label">
                      <input 
                        type="radio" 
                        name="scriptType" 
                        value="external-self"
                        checked={testScriptType === 'external-self'}
                        onChange={() => {
                          setTestScriptType('external-self');
                          setTestScriptSource("https://yourdomain.com/js/app.js");
                        }}
                      />
                      Same-Origin File (e.g. hosted on your own server)
                    </label>

                    <label className="radio-label">
                      <input 
                        type="radio" 
                        name="scriptType" 
                        value="external-third"
                        checked={testScriptType === 'external-third'}
                        onChange={() => {
                          setTestScriptType('external-third');
                          setTestScriptSource("https://apis.google.com/auth.js");
                        }}
                      />
                      Third-Party CDN script (e.g. <code>apis.google.com</code>)
                    </label>

                    <label className="radio-label">
                      <input 
                        type="radio" 
                        name="scriptType" 
                        value="eval"
                        checked={testScriptType === 'eval'}
                        onChange={() => {
                          setTestScriptType('eval');
                          setTestScriptSource("eval('alert(1)')");
                        }}
                      />
                      Dynamic Evaluation (e.g. <code>eval()</code> / <code>Function()</code>)
                    </label>
                  </div>
                </div>

                {testScriptType === 'external-third' && (
                  <div className="control-group">
                    <label>CDN Script URL Source:</label>
                    <input 
                      type="text" 
                      value={testScriptSource}
                      onChange={(e) => setTestScriptSource(e.target.value)}
                      className="cdn-url-input"
                    />
                  </div>
                )}
              </div>

              {/* Right Side: Simulation Result Indicator */}
              <div className="sim-result-card">
                <h5>Simulation Result</h5>
                <div className={`sim-status-banner ${simResult.allowed ? 'allowed' : 'blocked'}`}>
                  <span className="status-badge-icon">
                    {simResult.allowed ? "🔓 ALLOWED" : "🛡️ BLOCKED"}
                  </span>
                  <span className="status-badge-text">
                    by browser policy
                  </span>
                </div>
                
                <div className="sim-code-preview">
                  <strong>Script Attempt:</strong>
                  <pre>
                    <code>
                      {testScriptType === 'inline' && `<script>${testScriptSource}</script>`}
                      {testScriptType === 'external-self' && `<script src="${testScriptSource}"></script>`}
                      {testScriptType === 'external-third' && `<script src="${testScriptSource}"></script>`}
                      {testScriptType === 'eval' && testScriptSource}
                    </code>
                  </pre>
                </div>
                
                <p className="sim-reason">{simResult.reason}</p>
              </div>
            </div>
          </div>
          
        </div>
      )}
    </div>
  );
}
