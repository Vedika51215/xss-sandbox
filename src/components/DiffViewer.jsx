import React from 'react';

/**
 * DiffViewer Component
 * WHY: Displays a side-by-side or stacked view comparing the original raw payload
 * to the sanitized DOMPurify output. This comparison makes it visually obvious to users
 * exactly which parts of their input were stripped (like event handlers or script tags)
 * for educational security purposes.
 * Props:
 *  - raw: The un-sanitized original user input string.
 *  - sanitized: The clean output string returned by DOMPurify.
 */
export function DiffViewer({ raw, sanitized }) {
  return (
    <div className="diff-viewer-wrapper">
      <div className="diff-panel diff-raw">
        <div className="diff-header">🚨 Original Payload (Raw)</div>
        <pre className="diff-content"><code>{raw}</code></pre>
      </div>
      <div className="diff-panel diff-sanitized">
        <div className="diff-header">🛡️ Sanitized Output (DOMPurify)</div>
        <pre className="diff-content"><code>{sanitized || "(All code was stripped)"}</code></pre>
      </div>
    </div>
  );
}
