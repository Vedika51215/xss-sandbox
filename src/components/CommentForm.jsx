import React, { useState, useEffect } from 'react';
import { detectAttack } from '../utils/detector';
import { sanitizeInput, getStrippedSummary } from '../utils/sanitizer';
import { DiffViewer } from './DiffViewer';

/**
 * CommentForm Component
 * WHY: Contains controlled form inputs. Controlled inputs couple HTML form values
 * to React state using useState, which serves as the single source of truth.
 * Props:
 *  - onPostComment: Callback function to push the submitted message to the App list.
 *  - injectedComment: Text loaded from the payload vault, used to trigger the forms.
 */
export function CommentForm({ onPostComment, injectedComment }) {
  // useState Hook:
  // WHY: We initialize state variables to keep track of the text typed in inputs.
  // useState returns the variable and its setter function. Updating the state triggers React
  // to re-render the form and display the new characters.
  const [author, setAuthor] = useState('');
  const [comment, setComment] = useState('');
  const [error, setError] = useState('');
  // WHY cooldown: tracks the remaining seconds of rate limiting to prevent spam submission.
  const [cooldown, setCooldown] = useState(0);

  // useEffect Hook:
  // WHY: Handles the countdown timer. When cooldown changes and is > 0, we decrement it
  // by 1 every second until it reaches 0.
  useEffect(() => {
    if (cooldown <= 0) return;
    const timer = setInterval(() => {
      setCooldown((prev) => prev - 1);
    }, 1000);
    return () => clearInterval(timer);
  }, [cooldown]);

  // useEffect Hook for injectedComment
  useEffect(() => {
    if (injectedComment) {
      setComment(injectedComment);
      if (!author.trim()) {
        setAuthor('Attacker'); // auto-fill so validation passes
      }
      setError('');
    }
  }, [injectedComment]);

  // Live detection checks
  const commentAttack = detectAttack(comment);
  const authorAttack = detectAttack(author);
  const liveAttackDetected = commentAttack.isAttack || authorAttack.isAttack;
  
  const activePayload = commentAttack.isAttack ? comment : author;
  const sanitizedPayload = sanitizeInput(activePayload);

  // Submit Handler
  // WHY: Blocks posting comments if rate limit is active. On successful post,
  // initializes a 3-second cooldown.
  const handleSubmit = (e, wasPostedSafely) => {
    e.preventDefault();
    if (cooldown > 0) {
      setError(`⏳ Rate limit active. Please wait ${cooldown}s before posting again.`);
      return;
    }
    if (!author.trim() || !comment.trim()) {
      setError('⚠️ Both Author and Comment/HTML Payload fields are required.');
      return;
    }
    setError('');
    onPostComment(author, comment, wasPostedSafely);
    
    // Activate 3-second rate limit cooldown
    setCooldown(3);

    // Reset local inputs
    setAuthor('');
    setComment('');
  };


  return (
    <div className="comment-form-container">
      <h3>✍️ Sandbox Comment Form</h3>
      <form>
        <div className="input-group">
          <label htmlFor="author-input">Author Name</label>
          <input
            id="author-input"
            type="text"
            placeholder="e.g. CyberSecuritySpecialist"
            value={author}
            onChange={(e) => {
              setAuthor(e.target.value);
              if (error) setError('');
            }}
            required
          />
        </div>

        <div className="input-group">
          <label htmlFor="comment-input">Comment Text / HTML Payload</label>
          <textarea
            id="comment-input"
            rows="4"
            placeholder="Post a safe message, or write raw HTML payloads to test execution..."
            value={comment}
            onChange={(e) => {
              setComment(e.target.value);
              if (error) setError('');
            }}
            required
          />
        </div>

        {/* Live Attack Warning & Visual Diff Viewer
           WHY: Only displayed if `liveAttackDetected` is true. This teaches the user
           in real-time what sections of their code are considered dangerous.
        */}
        {liveAttackDetected && (() => {
          const stripped = getStrippedSummary(activePayload, sanitizedPayload);
          return (
            <div className="live-warning-container animate-fade-in">
              <div className="warning-header">
                <span className="warning-icon">🚨</span>
                <div>
                  <strong>Live Exploit Vector Detected!</strong>
                  <p className="warning-sub">
                    Type flagged: {commentAttack.isAttack ? commentAttack.type : authorAttack.type}
                  </p>
                </div>
              </div>
              
              {/* Visual diff viewer component */}
              <DiffViewer 
                raw={activePayload} 
                sanitized={sanitizedPayload} 
              />

              {/* WHY: Show a clean list of exactly what DOMPurify stripped to help the user learn. */}
              {stripped.length > 0 && (
                <div className="stripped-summary-box">
                  <strong>🧹 DOMPurify Clean Action:</strong>
                  <ul className="stripped-list">
                    {stripped.map((item, index) => (
                      <li key={index} className="stripped-item">{item}</li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          );
        })()}

        {/* Error Feedback Display */}
        {error && <p className="form-error">{error}</p>}

        <div className="form-actions">
          {/* Post Vulnerable Button
             WHY: Submits comment raw, representing a database storing unfiltered inputs.
          */}
          <button
            type="button"
            className="btn btn-vuln"
            disabled={cooldown > 0}
            onClick={(e) => handleSubmit(e, false)}
          >
            {cooldown > 0 ? `⏳ Cooldown (${cooldown}s)` : '☢️ Post (Vulnerable)'}
          </button>

          {/* Post Safe Button
             WHY: Cleans the comment via DOMPurify before storing it. Represents secure input filtering.
          */}
          <button
            type="button"
            className="btn btn-safe"
            disabled={cooldown > 0}
            onClick={(e) => handleSubmit(e, true)}
          >
            {cooldown > 0 ? `⏳ Cooldown (${cooldown}s)` : '🛡️ Post (Safe)'}
          </button>
        </div>
      </form>
    </div>
  );
}
