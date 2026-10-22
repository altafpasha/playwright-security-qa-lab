/**
 * ============================================================================
 * DETECTION RULE: SEC-DET-001 - REPEATED FAILED AUTHENTICATION (BRUTE-FORCE)
 * ============================================================================
 * 
 * Purpose:
 * Analyzes synthetic authentication telemetry and triggers a structured security alert
 * when a single source IP address exceeds a configurable threshold of failed login
 * attempts within a defined sliding time window.
 * 
 * Detection Engineering Rationale:
 * - Threat Category: Credential Guessing / Password Spray / Brute-Force (MITRE ATT&CK T1110).
 * - Primary Indicator: High frequency of `login_failure` events tied to a single origin IP.
 * - Granularity: Evaluated per source IP, ignoring successful logins and tracking targeted usernames.
 * 
 * Scope & Limitations (Detection Tuning & Real-World Context):
 * ----------------------------------------------------------------------------
 * 1. False Positives (FP):
 *    - Corporate NAT Gateways: Hundreds of legitimate enterprise users behind a single
 *      public egress IP. If 5 employees enter typos around the same time, this rule triggers.
 *    - Misconfigured Service Accounts: Client scripts retrying expired tokens in loops.
 *    - Mitigation: Whitelist trusted corporate egress IPs, or calculate failure rate
 *      relative to distinct usernames (e.g. failure count / unique usernames ratio).
 * 
 * 2. False Negatives (FN):
 *    - Distributed Brute-Force / Credential Stuffing (T1110.004): Attackers routing requests
 *      through residential proxies or botnets (e.g. 1 attempt per IP across 1,000 IPs).
 *      A per-IP rule will NEVER trigger on this pattern.
 *    - Low-and-Slow Attacks: Guessing 1 password every 10 minutes (outside the 5-minute window).
 *    - Mitigation: Complement IP-based detection with User-based brute force rules
 *      (e.g., failed attempts against the SAME username across ANY IP) and WAF rate limits.
 */

/**
 * @typedef {Object} AuthEvent
 * @property {string} timestamp - ISO-8601 formatted timestamp
 * @property {string} event_type - 'login_failure' | 'login_success' | etc.
 * @property {string} source_ip - Client IP address
 * @property {string} [username] - Account identifier targeted
 * @property {string} [user_agent] - Client browser or tool string
 */

/**
 * @typedef {Object} DetectionOptions
 * @property {number} [threshold=5] - Minimum failures needed to trigger alert
 * @property {number} [windowSeconds=300] - Sliding time window in seconds
 * @property {string} [ruleId='SEC-DET-001'] - Identifier for SIEM correlation
 * @property {string} [severity='HIGH'] - Alert severity level
 */

/**
 * Evaluates an array of authentication events and returns structured alerts
 * for IPs exceeding the failed login threshold within the sliding time window.
 * 
 * @param {Array<AuthEvent>} events - Raw telemetry event stream
 * @param {DetectionOptions} [options={}] - Configurable rule thresholds
 * @returns {Array<Object>} List of structured alert objects
 */
function detectBruteForce(events, options = {}) {
  const threshold = options.threshold ?? 5;
  const windowSeconds = options.windowSeconds ?? 300;
  const ruleId = options.ruleId ?? 'SEC-DET-001';
  const severity = options.severity ?? 'HIGH';
  const windowMs = windowSeconds * 1000;

  // Defensive input validation
  if (!Array.isArray(events)) {
    return [];
  }

  // 1. Filter, sanitize, and normalize valid login failure events
  const validFailures = [];

  for (const event of events) {
    if (!event || typeof event !== 'object') continue;

    // Filter strictly for login failure events (ignore successes or other actions)
    if (event.event_type !== 'login_failure') continue;

    // Validate mandatory telemetry attributes
    if (!event.source_ip || typeof event.source_ip !== 'string') continue;
    if (!event.timestamp || typeof event.timestamp !== 'string') continue;

    const parsedTime = Date.parse(event.timestamp);
    if (isNaN(parsedTime)) continue; // Malformed date string

    validFailures.push({
      source_ip: event.source_ip.trim(),
      timestamp: event.timestamp,
      epochTime: parsedTime,
      username: typeof event.username === 'string' ? event.username.trim() : 'UNKNOWN'
    });
  }

  // 2. Group failures by source IP address
  const failuresByIp = new Map();
  for (const failure of validFailures) {
    if (!failuresByIp.has(failure.source_ip)) {
      failuresByIp.set(failure.source_ip, []);
    }
    failuresByIp.get(failure.source_ip).push(failure);
  }

  const alerts = [];

  // 3. Evaluate sliding time window per IP
  for (const [ip, ipFailures] of failuresByIp.entries()) {
    // Sort chronologically ascending
    ipFailures.sort((a, b) => a.epochTime - b.epochTime);

    // Sliding window evaluation
    let left = 0;
    let windowTriggered = false;

    for (let right = 0; right < ipFailures.length; right++) {
      // Shrink window from the left until duration is within windowMs
      while (ipFailures[right].epochTime - ipFailures[left].epochTime > windowMs) {
        left++;
      }

      const countInWindow = right - left + 1;

      // If threshold is reached and we haven't already alerted on this burst
      if (countInWindow >= threshold && !windowTriggered) {
        const windowEvents = ipFailures.slice(left, right + 1);
        const firstTime = windowEvents[0].timestamp;
        const lastTime = windowEvents[windowEvents.length - 1].timestamp;
        const durationSec = Math.round((windowEvents[windowEvents.length - 1].epochTime - windowEvents[0].epochTime) / 1000);

        const targetedUsernames = Array.from(new Set(windowEvents.map((e) => e.username)));

        alerts.push({
          rule_id: ruleId,
          rule_name: 'Repeated Failed Logins from Single Source IP',
          severity: severity,
          source_ip: ip,
          failure_count: windowEvents.length,
          threshold: threshold,
          window_seconds: windowSeconds,
          first_failure_time: firstTime,
          last_failure_time: lastTime,
          targeted_usernames: targetedUsernames,
          alert_timestamp: new Date().toISOString(),
          explanation: `Detected ${windowEvents.length} failed login attempts from IP ${ip} within ${durationSec}s, meeting or exceeding detection threshold of ${threshold} attempts in a ${windowSeconds}s window.`
        });

        windowTriggered = true; // Avoid spamming duplicate alerts for the same burst
      }
    }
  }

  return alerts;
}

module.exports = {
  detectBruteForce
};
