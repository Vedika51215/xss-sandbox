import DOMPurify from 'dompurify';

/**
 * sanitizeInput
 * WHY: This utility function sanitizes user input using DOMPurify,
 * an industry-standard library that strips malicious HTML, scripts, and attributes
 * while leaving safe HTML nodes (like <strong> or <em>) intact.
 * WHY DOMPURIFY? Instead of basic regex replacements, DOMPurify uses the browser's 
 * actual HTML parser to construct an in-memory DOM tree, cleans it against a whitelist,
 * and outputs the safe HTML string. This prevents parser-differential bypasses.
 *
 * @param {string} input - The raw comment body.
 * @returns {string} - The sanitized comment body.
 */
export function sanitizeInput(input) {
  if (!input) return "";
  return DOMPurify.sanitize(input);
}

/**
 * getStrippedSummary
 * WHY: Compares raw input to DOMPurify's sanitized output to determine
 * exactly what hazardous elements (script tags, event listeners, inline style blocks)
 * were removed, providing educational telemetry on the filtering process.
 */
export function getStrippedSummary(raw, sanitized) {
  if (!raw || raw === sanitized) return [];
  const changes = [];
  
  const rawLower = raw.toLowerCase();
  const sanLower = sanitized.toLowerCase();
  
  // 1. Script tags
  if (/<script/i.test(raw) && !/<script/i.test(sanitized)) {
    changes.push("Removed executable <script> tags");
  }
  
  // 2. Inline Event Handlers (onerror, onload, etc.)
  const eventRegex = /\bon[a-z]+/gi;
  const rawEvents = rawLower.match(eventRegex) || [];
  const sanEvents = sanLower.match(eventRegex) || [];
  if (rawEvents.length > sanEvents.length) {
    const strippedEvents = rawEvents.filter(ev => !sanEvents.includes(ev));
    if (strippedEvents.length > 0) {
      const uniqueStripped = [...new Set(strippedEvents)];
      changes.push(`Stripped dangerous event attributes: ${uniqueStripped.join(', ')}`);
    }
  }
  
  // 3. JavaScript URLs (javascript:alert(1))
  if (/javascript:/i.test(raw) && !/javascript:/i.test(sanitized)) {
    changes.push("Neutralized 'javascript:' URI schemes");
  }

  // 4. SVG Tags
  if (/<svg/i.test(raw) && !/<svg/i.test(sanitized)) {
    changes.push("Removed <svg> XML vectors");
  }

  // 5. Iframes
  if (/<iframe/i.test(raw) && !/<iframe/i.test(sanitized)) {
    changes.push("Blocked <iframe> sandboxes");
  }

  // 6. Style elements
  if (/<style/i.test(raw) && !/<style/i.test(sanitized)) {
    changes.push("Removed inline style injection blocks");
  }

  // 7. General fallback
  if (changes.length === 0 && raw !== sanitized) {
    // If text changed but no specific rules hit, generic tag stripping occurred
    const tagRegex = /<\/?[a-z][^>]*>/gi;
    const rawTags = raw.match(tagRegex) || [];
    const sanTags = sanitized.match(tagRegex) || [];
    if (rawTags.length > sanTags.length) {
      changes.push("Filtered unauthorized HTML structure tags");
    } else {
      changes.push("Scrubbed suspicious encoding bypasses");
    }
  }

  return changes;
}

