import React from 'react';

/**
 * BlogPost Component
 * WHY: Establishes the application as an actual "Anti-XSS Blog" page.
 * Displays a mock blog post describing XSS vulnerabilities in user comment sections,
 * which serves as the educational context for the interactive security dashboard below it.
 */
export function BlogPost() {
  return (
    <div className="blog-post-card animate-fade-in">
      <div className="blog-post-meta">
        <span className="blog-tag">#cybersecurity</span>
        <span className="blog-tag">#appsec</span>
        <span className="blog-read-time">⏱️ 4 min read</span>
      </div>
      
      <h2 className="blog-title">Defeating Stored XSS in Dynamic Comment Sections</h2>
      
      <div className="blog-author-bar">
        <div className="blog-author-avatar">🛡️</div>
        <div className="blog-author-details">
          <span className="blog-author-name">CyberSentinel Admin</span>
          <span className="blog-post-date">Published May 25, 2026</span>
        </div>
      </div>
      
      <div className="blog-content">
        <p>
          Interactive comment blocks are the lifeblood of blogs, forums, and social sites. 
          However, allowing users to supply text that other users view introduces a critical attack vector: 
          <strong>Stored Cross-Site Scripting (XSS)</strong>.
        </p>
        
        <p>
          When comments are rendered unsanitized directly in the DOM (such as through standard HTML injection), 
          an attacker can submit dynamic scripts. Once saved to the database, these scripts execute within the 
          context of any user viewing the page. This allows attackers to steal session tokens, hijack accounts, 
          or redirect users to malicious domains.
        </p>

        <div className="blog-alert-tip">
          <strong>💡 Security Insight:</strong> Stored XSS is particularly dangerous because it does not require 
          the victim to click a suspicious link. Simply visiting the compromised blog post triggers the exploit.
        </div>

        <p>
          To secure this blog, we utilize a two-layer defense. First, a real-time regex scanner monitors inputs 
          and flags security vectors. Second, a strict HTML sanitizer (DOMPurify) intercepts raw input, parses it 
          into a virtual DOM, and strips out dangerous tags (e.g., <code>&lt;script&gt;</code>, <code>&lt;iframe&gt;</code>) 
          and events (e.g., <code>onerror</code>, <code>onload</code>) before they can be parsed by the browser.
        </p>
      </div>

      <div className="blog-divider"></div>
      
      <div className="blog-footer-cta">
        <span className="cta-icon">🔥</span>
        <span>
          <strong>Try to exploit this blog!</strong> Choose or write an XSS script from the vault, 
          then post it as <strong>Vulnerable</strong> (demonstrating the attack) or <strong>Safe</strong> (neutralized by our sanitizer).
        </span>
      </div>
    </div>
  );
}
