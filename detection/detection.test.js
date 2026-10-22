const { test, describe } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const { detectBruteForce } = require('./detect-bruteforce');

describe('Security Detection Rule: SEC-DET-001 (Brute-Force & Credential Guessing)', () => {

  test('Unit: Triggers structured alert when threshold is exactly met', () => {
    const baseTime = 1700000000000;
    const events = [];

    // Generate exactly 5 failures (default threshold = 5) within 2 minutes (default window = 300s)
    for (let i = 0; i < 5; i++) {
      events.push({
        timestamp: new Date(baseTime + i * 30000).toISOString(),
        event_type: 'login_failure',
        source_ip: '198.51.100.5',
        username: `target_user_${i}`
      });
    }

    const alerts = detectBruteForce(events, { threshold: 5, windowSeconds: 300 });

    assert.equal(alerts.length, 1, 'Expected exactly 1 alert for threshold of 5 failures');
    const alert = alerts[0];

    // Schema validation
    assert.equal(alert.rule_id, 'SEC-DET-001');
    assert.equal(alert.source_ip, '198.51.100.5');
    assert.equal(alert.failure_count, 5);
    assert.equal(alert.severity, 'HIGH');
    assert.equal(alert.targeted_usernames.length, 5);
    assert.ok(alert.explanation.includes('198.51.100.5'));
    assert.ok(alert.alert_timestamp);
  });

  test('Unit: Does not trigger alert when failures are below threshold', () => {
    const baseTime = 1700000000000;
    const events = [];

    // Only 4 failures (boundary test: threshold - 1)
    for (let i = 0; i < 4; i++) {
      events.push({
        timestamp: new Date(baseTime + i * 20000).toISOString(),
        event_type: 'login_failure',
        source_ip: '198.51.100.10',
        username: 'user@demo.local'
      });
    }

    const alerts = detectBruteForce(events, { threshold: 5, windowSeconds: 300 });
    assert.equal(alerts.length, 0, 'No alert should fire for 4 failures when threshold is 5');
  });

  test('Unit: Tracks multiple source IPs independently without crosstalk', () => {
    const baseTime = 1700000000000;
    const events = [];

    // IP A: 5 failures within window -> Should trigger
    for (let i = 0; i < 5; i++) {
      events.push({
        timestamp: new Date(baseTime + i * 10000).toISOString(),
        event_type: 'login_failure',
        source_ip: '10.0.0.1',
        username: 'victim_a'
      });
    }

    // IP B: 2 failures within window -> Should NOT trigger
    for (let i = 0; i < 2; i++) {
      events.push({
        timestamp: new Date(baseTime + i * 10000).toISOString(),
        event_type: 'login_failure',
        source_ip: '10.0.0.2',
        username: 'victim_b'
      });
    }

    // IP C: 6 failures within window -> Should trigger
    for (let i = 0; i < 6; i++) {
      events.push({
        timestamp: new Date(baseTime + i * 10000).toISOString(),
        event_type: 'login_failure',
        source_ip: '10.0.0.3',
        username: 'admin'
      });
    }

    const alerts = detectBruteForce(events, { threshold: 5, windowSeconds: 300 });

    assert.equal(alerts.length, 2, 'Should detect exactly 2 offending IPs');
    const alertedIps = alerts.map((a) => a.source_ip).sort();
    assert.deepEqual(alertedIps, ['10.0.0.1', '10.0.0.3']);
  });

  test('Unit: Ignores login_success events and interleaved successes', () => {
    const baseTime = 1700000000000;
    const events = [
      // 5 successes should never alert
      { timestamp: new Date(baseTime).toISOString(), event_type: 'login_success', source_ip: '192.168.1.50', username: 'user1' },
      { timestamp: new Date(baseTime + 1000).toISOString(), event_type: 'login_success', source_ip: '192.168.1.50', username: 'user1' },
      { timestamp: new Date(baseTime + 2000).toISOString(), event_type: 'login_success', source_ip: '192.168.1.50', username: 'user1' },
      { timestamp: new Date(baseTime + 3000).toISOString(), event_type: 'login_success', source_ip: '192.168.1.50', username: 'user1' },
      { timestamp: new Date(baseTime + 4000).toISOString(), event_type: 'login_success', source_ip: '192.168.1.50', username: 'user1' },
      // 2 failures interleaved
      { timestamp: new Date(baseTime + 5000).toISOString(), event_type: 'login_failure', source_ip: '192.168.1.50', username: 'user1' },
      { timestamp: new Date(baseTime + 6000).toISOString(), event_type: 'login_failure', source_ip: '192.168.1.50', username: 'user1' }
    ];

    const alerts = detectBruteForce(events, { threshold: 5, windowSeconds: 300 });
    assert.equal(alerts.length, 0, 'Successful logins must not count towards failure threshold');
  });

  test('Unit: Enforces sliding time window boundaries (low-and-slow rejection)', () => {
    const baseTime = 1700000000000;
    const events = [];

    // 5 failures spread over 50 minutes (10 minutes apart)
    // Window is 5 minutes (300s). No burst meets the window requirement.
    for (let i = 0; i < 5; i++) {
      events.push({
        timestamp: new Date(baseTime + i * 600000).toISOString(), // 600,000ms = 10 minutes apart
        event_type: 'login_failure',
        source_ip: '198.51.100.77',
        username: 'admin'
      });
    }

    const alerts = detectBruteForce(events, { threshold: 5, windowSeconds: 300 });
    assert.equal(alerts.length, 0, 'Failures outside time window must not trigger alert');
  });

  test('Unit: Resilient to corrupt, incomplete, and malformed telemetry', () => {
    const corruptEvents = [
      null,
      undefined,
      'not_an_object',
      {},
      { event_type: 'login_failure' }, // missing source_ip and timestamp
      { event_type: 'login_failure', source_ip: '10.10.10.10' }, // missing timestamp
      { event_type: 'login_failure', source_ip: '10.10.10.10', timestamp: 'not-a-valid-date' }, // corrupt date
      { event_type: 'login_failure', source_ip: 12345, timestamp: new Date().toISOString() } // invalid IP type
    ];

    // Must not crash or throw unhandled exceptions
    assert.doesNotThrow(() => {
      const alerts = detectBruteForce(corruptEvents);
      assert.equal(alerts.length, 0);
    });

    // Test non-array input
    assert.doesNotThrow(() => {
      const alerts = detectBruteForce(null);
      assert.equal(alerts.length, 0);
    });
  });

  test('Integration: Evaluates sample-auth-events.json dataset accurately', () => {
    const samplePath = path.join(__dirname, 'sample-auth-events.json');
    const rawData = fs.readFileSync(samplePath, 'utf8');
    const events = JSON.parse(rawData);

    const alerts = detectBruteForce(events, { threshold: 5, windowSeconds: 300 });

    assert.equal(alerts.length, 1, 'Sample file should produce exactly 1 brute force alert');
    assert.equal(alerts[0].source_ip, '198.51.100.42');
    assert.equal(alerts[0].failure_count, 5);
    assert.equal(alerts[0].severity, 'HIGH');
    assert.deepEqual(alerts[0].targeted_usernames.sort(), ['admin', 'admin@demo.local', 'administrator', 'root', 'user@demo.local'].sort());
  });
});
