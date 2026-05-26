import React from 'react';

/**
 * AttackLog Component
 * WHY: Displays a running log of XSS attacks detected in this session.
 * Each entry now includes a color-coded severity badge so analysts can
 * instantly prioritize CRITICAL threats over MEDIUM filter-bypass attempts.
 * Props:
 *  - logs: Array of security log data objects (includes severity field).
 *  - onClearLogs: Callback function to reset the logs state in the parent App.
 */

// Maps severity string → CSS class suffix for dynamic coloring
const SEVERITY_CLASS = {
  CRITICAL: 'sev-critical',
  HIGH:     'sev-high',
  MEDIUM:   'sev-medium',
  LOW:      'sev-low',
};

export function AttackLog({ logs, onClearLogs }) {
  // WHY handleExportJSON: Allows security analysts to download session logs
  // as a structured JSON file to import into external analysis/reporting tools.
  const handleExportJSON = () => {
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(logs, null, 2));
    const downloadAnchor = document.createElement('a');
    downloadAnchor.setAttribute("href", dataStr);
    downloadAnchor.setAttribute("download", `xssafe_attack_logs_${Date.now()}.json`);
    document.body.appendChild(downloadAnchor);
    downloadAnchor.click();
    downloadAnchor.remove();
  };

  return (
    <div className="attack-log-container">
      <div className="panel-header">
        <div className="panel-title-group">
          <h3>📊 Security Attack Logs</h3>
          <span className={`log-count-badge ${logs.length > 0 ? 'pulse-alert' : ''}`}>
            {logs.length}
          </span>
        </div>
        {logs.length > 0 && (
          <div className="log-action-buttons">
            <button className="btn-export-logs" onClick={handleExportJSON} title="Download logs as JSON">
              📥 Export JSON
            </button>
            <button className="btn-clear-logs" onClick={onClearLogs} title="Clear all logs">
              🗑️ Clear
            </button>
          </div>
        )}
      </div>

      <div className="log-list-wrapper">
        {logs.length === 0 ? (
          <div className="empty-log-state">
            <span className="shield-icon">🛡️</span>
            <p>No attack vector logged in this session.</p>
            <p className="subtext">Use the "Payload Vault" to inject XSS vectors and test sanitization.</p>
          </div>
        ) : (
          <div className="log-list">
            {logs.map((log) => {
              const sevClass = SEVERITY_CLASS[log.severity] || 'sev-high';
              return (
                /* WHY key: React uses the unique key to reconcile the virtual DOM
                   efficiently — only changed items are re-rendered. */
                <div key={log.id} className={`log-item animate-slide-in ${sevClass}-border`}>
                  <div className="log-meta">
                    <span className="log-type">{log.type}</span>
                    <div className="log-meta-right">
                      {log.severity && (
                        <span className={`severity-badge ${sevClass}`}>
                          {log.severity}
                        </span>
                      )}
                      <span className="log-time">{log.timestamp}</span>
                    </div>
                  </div>
                  <div className="log-payload">
                    <code>{log.payload}</code>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}
