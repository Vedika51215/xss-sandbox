import React from 'react';
import { getStrippedSummary } from '../utils/sanitizer';

/**
 * CommentCard Component
 * WHY: Displays a single comment post.
 * Props:
 *  - comment: The data object containing author, raw body, sanitized body, isAttack flag, and timestamp.
 *  - isSafeMode: The global toggle state that decides whether we render clean or raw output.
 */
export function CommentCard({ comment, isSafeMode }) {
  // WHY: We select the content to render. If the application is currently in global Safe Mode,
  // or if this specific comment was sanitized during form submission (input-side), we use the
  // sanitized HTML string. Otherwise, we load the raw text (which might contain active script tags).
  const renderBody = (isSafeMode || comment.wasPostedSafely) 
    ? comment.sanitizedBody 
    : comment.rawBody;

  // WHY: React escapes dynamic strings (like {renderBody}) to prevent XSS by default.
  // If we render them normally, the browser displays tags as plain text. To let HTML render
  // and scripts run (demonstrating XSS), we must explicitly use React's `dangerouslySetInnerHTML`.
  // Under Safe Mode, we are injecting DOMPurify-sanitized content, which is safe.
  const bodyMarkup = { __html: renderBody };
  
  // Similarly, if the author field was posted vulnerably, we allow HTML parsing on it.
  const authorMarkup = { __html: comment.author };

  return (
    <div className={`comment-card animate-slide-in ${comment.isAttack ? 'flagged-attack' : ''} ${comment.wasPostedSafely ? 'safe-post' : 'vuln-post'}`}>
      <div className="comment-header">
        <div className="author-info">
          <span className="author-name">
            {comment.wasPostedSafely ? (
              /* Safe mode rendering: renders plain text to prevent script execution */
              comment.author
            ) : (
              /* Vulnerable mode rendering: renders HTML, exposing XSS in author name field */
              <span dangerouslySetInnerHTML={authorMarkup} />
            )}
          </span>
          <span className={`post-badge ${comment.wasPostedSafely ? 'badge-safe' : 'badge-vuln'}`}>
            {comment.wasPostedSafely ? '🛡️ Posted Safe' : '⚠️ Posted Vuln'}
          </span>
        </div>
        <span className="comment-time">{comment.timestamp}</span>
      </div>
      
      <div className="comment-body-wrapper">
        <div 
          className="comment-body" 
          dangerouslySetInnerHTML={bodyMarkup} 
        />
      </div>

      {/* Flagged attack badge — shows attack type AND severity level */}
      {comment.isAttack && (
        <div className="attack-indicator-badge">
          <div className="badge-row">
            <span className="pulse-dot"></span>
            <span>⚠️ XSS Detected: {comment.attackType}</span>
            {comment.attackSeverity && (
              <span className={`severity-badge severity-badge-inline sev-${comment.attackSeverity.toLowerCase()}`}>
                {comment.attackSeverity}
              </span>
            )}
          </div>
          
          {/* Show what was stripped if we neutralized it */}
          {comment.wasPostedSafely && (() => {
            const stripped = getStrippedSummary(comment.rawBody, comment.sanitizedBody);
            return stripped.length > 0 ? (
              <div className="card-stripped-summary">
                <span className="clean-label">🧹 Sanitized:</span>
                <div className="clean-list-inline">
                  {stripped.map((item, idx) => (
                    <span key={idx} className="clean-pill">{item}</span>
                  ))}
                </div>
              </div>
            ) : null;
          })()}
        </div>
      )}
    </div>
  );
}
