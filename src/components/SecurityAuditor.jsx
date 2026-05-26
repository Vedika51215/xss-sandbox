import React, { useState } from 'react';
import './SecurityAuditor.css';

// ─── Header Scanner Logic ──────────────────────────────────────────────────────
const SECURITY_HEADERS = [
  {
    key: 'content-security-policy',
    name: 'Content-Security-Policy',
    weight: 30,
    check: (val) => {
      if (!val) return { pass: false, warn: false, msg: "Missing. No browser-level XSS execution barrier exists." };
      if (val.includes("'unsafe-inline'") || val.includes("'unsafe-eval'"))
        return { pass: false, warn: true, msg: "Present but weak — 'unsafe-inline' or 'unsafe-eval' allows injected scripts to run." };
      return { pass: true, warn: false, msg: "Configured. Browser will block unauthorized inline scripts and external sources." };
    },
    fix: `Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none';`
  },
  {
    key: 'x-content-type-options',
    name: 'X-Content-Type-Options',
    weight: 15,
    check: (val) => {
      if (!val) return { pass: false, warn: false, msg: "Missing. Browser may sniff MIME types, enabling content injection." };
      if (val.toLowerCase().includes('nosniff'))
        return { pass: true, warn: false, msg: "Set to 'nosniff'. Browser will not guess content types." };
      return { pass: false, warn: true, msg: "Present but incorrect value. Must be 'nosniff'." };
    },
    fix: `X-Content-Type-Options: nosniff`
  },
  {
    key: 'x-frame-options',
    name: 'X-Frame-Options',
    weight: 15,
    check: (val) => {
      if (!val) return { pass: false, warn: false, msg: "Missing. Site can be embedded in iframes — enables clickjacking attacks." };
      if (val.toLowerCase().includes('deny') || val.toLowerCase().includes('sameorigin'))
        return { pass: true, warn: false, msg: "Configured. Site is protected from being embedded in hostile iframes." };
      return { pass: false, warn: true, msg: "Present but value not recognized. Use DENY or SAMEORIGIN." };
    },
    fix: `X-Frame-Options: DENY`
  },
  {
    key: 'strict-transport-security',
    name: 'Strict-Transport-Security (HSTS)',
    weight: 20,
    check: (val) => {
      if (!val) return { pass: false, warn: false, msg: "Missing. Connections may be downgraded from HTTPS to HTTP." };
      if (val.includes('max-age'))
        return { pass: true, warn: false, msg: "Configured. Browser will enforce HTTPS for all future connections." };
      return { pass: false, warn: true, msg: "Present but missing max-age directive." };
    },
    fix: `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`
  },
  {
    key: 'referrer-policy',
    name: 'Referrer-Policy',
    weight: 10,
    check: (val) => {
      if (!val) return { pass: false, warn: false, msg: "Missing. Full URLs (including tokens) may be leaked in Referer headers." };
      const safe = ['no-referrer', 'strict-origin', 'strict-origin-when-cross-origin', 'same-origin'];
      if (safe.some(s => val.toLowerCase().includes(s)))
        return { pass: true, warn: false, msg: "Configured safely. Referrer data is restricted." };
      return { pass: false, warn: true, msg: "Present but policy may leak sensitive URL data to third parties." };
    },
    fix: `Referrer-Policy: strict-origin-when-cross-origin`
  },
  {
    key: 'permissions-policy',
    name: 'Permissions-Policy',
    weight: 10,
    check: (val) => {
      if (!val) return { pass: false, warn: false, msg: "Missing. Browser APIs (camera, mic, geolocation) are unrestricted." };
      return { pass: true, warn: false, msg: "Configured. Browser feature access is policy-restricted." };
    },
    fix: `Permissions-Policy: geolocation=(), microphone=(), camera=()`
  }
];

function parseHeaders(rawText) {
  const result = {};
  const lines = rawText.split('\n');
  for (const line of lines) {
    const idx = line.indexOf(':');
    if (idx === -1) continue;
    const key = line.slice(0, idx).trim().toLowerCase();
    const val = line.slice(idx + 1).trim();
    if (key) result[key] = val;
  }
  return result;
}

function analyzeHeaders(parsed) {
  let totalScore = 0;
  let maxScore = 0;
  const findings = SECURITY_HEADERS.map(h => {
    maxScore += h.weight;
    const result = h.check(parsed[h.key]);
    if (result.pass) totalScore += h.weight;
    else if (result.warn) totalScore += Math.floor(h.weight * 0.3);
    return { ...h, ...result, value: parsed[h.key] || null };
  });
  const pct = Math.round((totalScore / maxScore) * 100);
  let grade, gradeClass;
  if (pct >= 90) { grade = 'A+'; gradeClass = 'grade-a'; }
  else if (pct >= 75) { grade = 'B'; gradeClass = 'grade-b'; }
  else if (pct >= 50) { grade = 'C'; gradeClass = 'grade-c'; }
  else if (pct >= 25) { grade = 'D'; gradeClass = 'grade-d'; }
  else { grade = 'F'; gradeClass = 'grade-f'; }
  return { findings, pct, grade, gradeClass };
}

// ─── Header Scanner Component ─────────────────────────────────────────────────
function HeaderScanner() {
  const [rawHeaders, setRawHeaders] = useState('');
  const [result, setResult] = useState(null);
  const [showInstructions, setShowInstructions] = useState(false);
  const [copied, setCopied] = useState(false);

  const handleScan = () => {
    if (!rawHeaders.trim()) return;
    const parsed = parseHeaders(rawHeaders);
    setResult(analyzeHeaders(parsed));
  };

  const handleCopyAll = (fixes) => {
    navigator.clipboard.writeText(fixes.join('\n'));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const missingFixes = result
    ? result.findings.filter(f => !f.pass).map(f => f.fix)
    : [];

  return (
    <div className="scanner-container animate-fade-in">
      <div className="scanner-intro-card">
        <div className="scanner-intro-header">
          <div className="scanner-intro-icon">🔍</div>
          <div>
            <h3>HTTP Security Header Analyzer</h3>
            <p>
              As the admin of your own website, paste your HTTP response headers below.
              The tool will grade your security configuration and show you exactly what to fix.
            </p>
          </div>
        </div>

        <button className="btn-show-instructions" onClick={() => setShowInstructions(v => !v)}>
          {showInstructions ? '▲ Hide' : '▼ How to get my headers?'}
        </button>

        {showInstructions && (
          <div className="instructions-box animate-fade-in">
            <div className="instruction-step">
              <span className="step-num">1</span>
              <span>Open your website in <strong>Chrome or Firefox</strong></span>
            </div>
            <div className="instruction-step">
              <span className="step-num">2</span>
              <span>Press <strong>F12</strong> to open DevTools → click the <strong>Network</strong> tab</span>
            </div>
            <div className="instruction-step">
              <span className="step-num">3</span>
              <span>Press <strong>F5</strong> to reload — click the first request (your domain name)</span>
            </div>
            <div className="instruction-step">
              <span className="step-num">4</span>
              <span>Click <strong>Response Headers</strong> → select all text and copy it</span>
            </div>
            <div className="instruction-step">
              <span className="step-num">5</span>
              <span>Paste it in the box below and click <strong>Analyze Headers</strong></span>
            </div>
          </div>
        )}
      </div>

      <div className="scanner-input-card">
        <label className="scanner-input-label">
          Paste your HTTP Response Headers here:
        </label>
        <textarea
          className="scanner-textarea"
          rows={9}
          placeholder={`Example:\ncontent-security-policy: default-src 'self'\nx-content-type-options: nosniff\nx-frame-options: DENY\nstrict-transport-security: max-age=31536000\nreferrer-policy: strict-origin-when-cross-origin`}
          value={rawHeaders}
          onChange={e => setRawHeaders(e.target.value)}
          spellCheck={false}
        />
        <div className="scanner-actions">
          <button className="btn-scan" onClick={handleScan} disabled={!rawHeaders.trim()}>
            🔍 Analyze Headers
          </button>
          <button className="btn-scan-clear" onClick={() => { setRawHeaders(''); setResult(null); }}>
            ✕ Clear
          </button>
        </div>
      </div>

      {result && (
        <div className="scanner-result animate-fade-in">
          {/* Grade Card */}
          <div className="scanner-grade-card">
            <div className={`grade-circle ${result.gradeClass}`}>{result.grade}</div>
            <div className="grade-meta">
              <span className="grade-pct">{result.pct}% Security Score</span>
              <span className="grade-sub">
                {result.pct >= 75 ? "Your headers are well configured." :
                 result.pct >= 50 ? "Some gaps detected — review findings below." :
                 "Significant vulnerabilities found — apply fixes immediately."}
              </span>
            </div>
            {missingFixes.length > 0 && (
              <button className="btn-copy-all" onClick={() => handleCopyAll(missingFixes)}>
                {copied ? '✅ Copied!' : '📋 Copy All Fixes'}
              </button>
            )}
          </div>

          {/* Findings Table */}
          <div className="scanner-findings-grid">
            {result.findings.map(f => (
              <div key={f.key} className={`finding-row ${f.pass ? 'pass' : f.warn ? 'warn' : 'fail'}`}>
                <div className="finding-row-header">
                  <span className="finding-status-icon">
                    {f.pass ? '✅' : f.warn ? '⚠️' : '❌'}
                  </span>
                  <span className="finding-header-name">{f.name}</span>
                  <span className={`finding-tag ${f.pass ? 'tag-pass' : f.warn ? 'tag-warn' : 'tag-fail'}`}>
                    {f.pass ? 'PASS' : f.warn ? 'WEAK' : 'MISSING'}
                  </span>
                </div>

                {f.value && (
                  <div className="finding-current-value">
                    <span className="value-label">Current value:</span>
                    <code>{f.value}</code>
                  </div>
                )}

                <p className="finding-msg">{f.msg}</p>

                {!f.pass && (
                  <div className="finding-fix-block">
                    <span className="fix-label">✏️ Recommended fix:</span>
                    <pre><code>{f.fix}</code></pre>
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

// ─── Wizard Component (existing) ──────────────────────────────────────────────
function AuditWizard() {
  const [currentStep, setCurrentStep] = useState(1);
  const [selections, setSelections] = useState({ rendering: null, sanitization: null, csp: null, storage: null });
  const [showResult, setShowResult] = useState(false);
  const [activeSolutionTab, setActiveSolutionTab] = useState('sanitize');

  const questions = [
    {
      id: 'rendering', title: "1. How does your website display dynamic user input?",
      subtitle: "Think about comments, profiles, search inputs, or forum posts.",
      options: [
        { value: 'raw-html', label: "HTML Injection / Raw Rendering", desc: "We render rich text using innerHTML, dangerouslySetInnerHTML, or equivalent templates.", score: 3 },
        { value: 'escaped', label: "Text-Only / Escaped Output", desc: "We only display plain text (e.g., using innerText, textContent, or standard React { }).", score: 0 }
      ]
    },
    {
      id: 'sanitization', title: "2. Do you sanitize user input before rendering it?",
      subtitle: "Sanitizing cleanses input of hazardous event attributes and script blocks.",
      options: [
        { value: 'none', label: "No Sanitization", desc: "We output inputs exactly as the database stores them without running any filters.", score: 3 },
        { value: 'custom-regex', label: "Custom String / Regex Replacing", desc: "We manually strip script tags or replace < and > using custom functions.", score: 2 },
        { value: 'dompurify', label: "Robust HTML Sanitizer (DOMPurify)", desc: "We run all HTML inputs through an industry-standard DOM-parsing library before rendering.", score: 0 }
      ]
    },
    {
      id: 'csp', title: "3. Does your website enforce a Content Security Policy (CSP)?",
      subtitle: "A CSP header is the browser-level firewall against executed script injections.",
      options: [
        { value: 'none', label: "No Content Security Policy", desc: "We do not send CSP HTTP headers or set meta tags.", score: 3 },
        { value: 'permissive', label: "Permissive CSP (Allows 'unsafe-inline')", desc: "We have a CSP, but it includes 'unsafe-inline' or wildcard script-src domains.", score: 1 },
        { value: 'strict', label: "Strict Content Security Policy", desc: "Our CSP blocks inline scripts, restricts script-src to trusted sources, and disables object-src.", score: 0 }
      ]
    },
    {
      id: 'storage', title: "4. Where do you store sensitive user tokens (JWT, Session IDs)?",
      subtitle: "Attackers targeting XSS look for access tokens to hijack user sessions.",
      options: [
        { value: 'localstorage', label: "LocalStorage or SessionStorage", desc: "Tokens are stored in browser local storage and are readable by Javascript.", score: 2 },
        { value: 'normal-cookie', label: "Standard Document Cookie", desc: "Tokens are stored in normal cookies and are readable using document.cookie.", score: 2 },
        { value: 'httponly-cookie', label: "HttpOnly, Secure Cookies", desc: "Tokens are stored in server-set cookies with HttpOnly flags, making them invisible to Javascript.", score: 0 }
      ]
    }
  ];

  const getAuditScore = () => {
    let score = 0;
    questions.forEach(q => {
      const option = q.options.find(o => o.value === selections[q.id]);
      if (option) score += option.score;
    });
    return score;
  };

  const getRiskStatus = (score) => {
    if (score >= 8) return { label: "CRITICAL RISK", cls: "risk-critical" };
    if (score >= 5) return { label: "HIGH RISK", cls: "risk-high" };
    if (score >= 2) return { label: "MODERATE RISK", cls: "risk-moderate" };
    return { label: "LOW RISK", cls: "risk-low" };
  };

  const totalScore = getAuditScore();
  const risk = getRiskStatus(totalScore);
  const activeQuestion = questions[currentStep - 1];
  const isOptionSelected = selections[activeQuestion.id] !== null;

  const handleReset = () => {
    setSelections({ rendering: null, sanitization: null, csp: null, storage: null });
    setCurrentStep(1);
    setShowResult(false);
  };

  if (!showResult) return (
    <div className="auditor-wizard-card">
      <div className="wizard-progress-bar">
        <div className="progress-fill" style={{ width: `${(currentStep / questions.length) * 100}%` }}></div>
      </div>
      <div className="wizard-step-indicator">Question {currentStep} of {questions.length}</div>
      <div className="wizard-content">
        <h3 className="wizard-question-title">{activeQuestion.title}</h3>
        <p className="wizard-question-sub">{activeQuestion.subtitle}</p>
        <div className="wizard-options-list">
          {activeQuestion.options.map(option => (
            <div
              key={option.value}
              className={`wizard-option-card ${selections[activeQuestion.id] === option.value ? 'selected' : ''}`}
              onClick={() => setSelections(prev => ({ ...prev, [activeQuestion.id]: option.value }))}
            >
              <div className="option-radio-circle">
                {selections[activeQuestion.id] === option.value && <div className="radio-inner-dot" />}
              </div>
              <div className="option-details">
                <span className="option-label">{option.label}</span>
                <p className="option-desc">{option.desc}</p>
              </div>
            </div>
          ))}
        </div>
      </div>
      <div className="wizard-actions">
        <button className="btn-wizard-back" onClick={() => setCurrentStep(p => p - 1)} disabled={currentStep === 1}>Back</button>
        <button className="btn-wizard-next" onClick={() => currentStep < questions.length ? setCurrentStep(p => p + 1) : setShowResult(true)} disabled={!isOptionSelected}>
          {currentStep === questions.length ? "Submit Audit" : "Next Question"}
        </button>
      </div>
    </div>
  );

  return (
    <div className="auditor-result-layout">
      <div className="result-overview-card">
        <h3>Diagnostic Summary Report</h3>
        <div className="risk-badge-container">
          <span className={`risk-grade-badge ${risk.cls}`}>{risk.label}</span>
          <div className="risk-score-details">Exposure Score: <strong>{totalScore} / 11</strong></div>
        </div>
        <div className="audit-findings-list">
          <div className="finding-item">
            <div className="finding-icon">{selections.rendering === 'raw-html' ? "❌" : "✅"}</div>
            <div className="finding-body"><strong>Dynamic Output Rendering:</strong>{' '}
              {selections.rendering === 'raw-html' ? "Raw HTML rendering enables DOM injection if inputs are unsanitized." : "Escaped/text-only rendering blocks XSS tags from executing."}
            </div>
          </div>
          <div className="finding-item">
            <div className="finding-icon">{selections.sanitization === 'dompurify' ? "✅" : selections.sanitization === 'custom-regex' ? "⚠️" : "❌"}</div>
            <div className="finding-body"><strong>Input Sanitization:</strong>{' '}
              {selections.sanitization === 'dompurify' ? "DOMPurify neutralizes parser-differential bypasses." : selections.sanitization === 'custom-regex' ? "Custom regex is easily bypassed by encoding or nested tags." : "No sanitization — database inputs can execute scripts directly."}
            </div>
          </div>
          <div className="finding-item">
            <div className="finding-icon">{selections.csp === 'strict' ? "✅" : selections.csp === 'permissive' ? "⚠️" : "❌"}</div>
            <div className="finding-body"><strong>Content Security Policy:</strong>{' '}
              {selections.csp === 'strict' ? "Strict CSP blocks inline event triggers as a fallback defense." : selections.csp === 'permissive' ? "'unsafe-inline' allows injected scripts to run." : "No CSP leaves no defense if sanitizers fail."}
            </div>
          </div>
          <div className="finding-item">
            <div className="finding-icon">{selections.storage === 'httponly-cookie' ? "✅" : "❌"}</div>
            <div className="finding-body"><strong>Credentials Storage:</strong>{' '}
              {selections.storage === 'httponly-cookie' ? "HttpOnly cookies prevent JavaScript from reading session tokens." : "LocalStorage or plain cookies are readable via document.cookie."}
            </div>
          </div>
        </div>
        <button className="btn-audit-retry" onClick={handleReset}>🔄 Restart Diagnostic Audit</button>
      </div>

      <div className="solutions-hub-card">
        <div className="solutions-hub-header">
          <h3>🛠️ Hand-to-Hand Remediation Solutions</h3>
          <p>Apply these direct implementations to fix the vulnerabilities above.</p>
        </div>
        <div className="solution-tabs">
          {['sanitize', 'csp', 'cookies'].map((tab, i) => (
            <button key={tab} className={`solution-tab-btn ${activeSolutionTab === tab ? 'active' : ''}`} onClick={() => setActiveSolutionTab(tab)}>
              {i + 1}. {tab === 'sanitize' ? 'Sanitizing HTML' : tab === 'csp' ? 'Enforcing CSP' : 'Securing Sessions'}
            </button>
          ))}
        </div>
        <div className="solution-tab-content">
          {activeSolutionTab === 'sanitize' && (
            <div className="solution-pane animate-fade-in">
              <h4>🧼 Neutralize Script Injections via DOMPurify</h4>
              <p>If you render HTML strings (like comments), sanitize them before injecting into the DOM.</p>
              <div className="solution-code-block">
                <div className="code-header"><span>JavaScript Integration</span></div>
                <pre>{`import DOMPurify from 'dompurify';
// Purge script tags, inline events and dangerous protocols
const cleanHtml = DOMPurify.sanitize(rawHtmlFromDatabase);
document.getElementById('comment-box').innerHTML = cleanHtml;`}</pre>
              </div>
              <div className="solution-code-block">
                <div className="code-header"><span>React JSX Implementation</span></div>
                <pre>{`function SafeComment({ rawBody }) {
  const sanitizedHtml = DOMPurify.sanitize(rawBody);
  return <div dangerouslySetInnerHTML={{ __html: sanitizedHtml }} />;
}`}</pre>
              </div>
            </div>
          )}
          {activeSolutionTab === 'csp' && (
            <div className="solution-pane animate-fade-in">
              <h4>🔒 Enforce a Strict Content Security Policy</h4>
              <p>A CSP header tells the browser which scripts are allowed to run — blocking injections even if sanitizers fail.</p>
              <div className="solution-code-block">
                <div className="code-header"><span>Recommended Production Header</span></div>
                <pre>{`Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'; frame-ancestors 'none';`}</pre>
              </div>
              <div className="solution-code-block">
                <div className="code-header"><span>Static HTML Meta Tag Fallback</span></div>
                <pre>{`<meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'self'; object-src 'none';">`}</pre>
              </div>
            </div>
          )}
          {activeSolutionTab === 'cookies' && (
            <div className="solution-pane animate-fade-in">
              <h4>🍪 Prevent Session Hijacking with HttpOnly Cookies</h4>
              <p>HttpOnly cookies are invisible to JavaScript — so even if XSS executes, it cannot steal session tokens.</p>
              <div className="solution-code-block">
                <div className="code-header"><span>Server Set-Cookie Header</span></div>
                <pre>{`Set-Cookie: session_token=YOUR_VALUE; Secure; HttpOnly; SameSite=Strict;`}</pre>
              </div>
              <div className="solution-alert-box">
                <strong>🔑 Why it works:</strong> The <code>HttpOnly</code> flag blocks <code>document.cookie</code> from reading this token — even if an attacker injects a script onto your page.
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}

// ─── Main Export ──────────────────────────────────────────────────────────────
export function SecurityAuditor() {
  const [activeMode, setActiveMode] = useState('scanner');

  return (
    <div className="auditor-outer-container animate-fade-in">
      <div className="auditor-header">
        <h2>🏥 Website XSS Security Center</h2>
        <p className="auditor-sub">
          Two tools for website owners: scan your live security headers for instant grading, or take the guided vulnerability wizard for a full audit.
        </p>
      </div>

      {/* Mode switcher */}
      <div className="auditor-mode-tabs">
        <button
          className={`auditor-mode-btn ${activeMode === 'scanner' ? 'active' : ''}`}
          onClick={() => setActiveMode('scanner')}
        >
          🔍 Header Security Scanner
        </button>
        <button
          className={`auditor-mode-btn ${activeMode === 'wizard' ? 'active' : ''}`}
          onClick={() => setActiveMode('wizard')}
        >
          📋 Guided Audit Wizard
        </button>
      </div>

      {activeMode === 'scanner' ? <HeaderScanner /> : <AuditWizard />}
    </div>
  );
}
