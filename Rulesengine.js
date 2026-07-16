/**
 * AccessOS — Rules Engine
 * Owner: Lead (Architecture + Rules Engine)
 *
 * Two entry points other devs / routes will call:
 *
 *   scoreEvent(pool, event)         -> sync, call this INLINE from
 *                                      /api/auth/login (Backend Dev 1) and
 *                                      any sensitive action route right
 *                                      after you insert the audit_logs row.
 *
 *   runBatchAnomalyScan(pool)       -> async, run on an interval (see
 *                                      startBatchScanner below). Catches
 *                                      anything inserted into audit_logs
 *                                      that skipped scoreEvent, and
 *                                      cross-checks recent failure bursts.
 *
 * Neither function talks HTTP — pass them a `pg` Pool/Client. Keeps this
 * testable and reusable from the sync path, the batch job, and tests.
 */

'use strict';

// ---------------------------------------------------------------------------
// Config — tune here, not scattered through the rules
// ---------------------------------------------------------------------------
const WEIGHTS = {
  NEW_DEVICE: 40,
  ODD_HOUR: 30,
  FAILED_BURST: 60,
  IP_CHANGE: 15, // lightweight companion to NEW_DEVICE, see checkIpChange()
};

const THRESHOLDS = {
  FLAG_FOR_STEP_UP: 50, // risk_score >= this => require step-up verification
  CREATE_ALERT: 60, // risk_score >= this => write a row to `alerts`
};

const FAILED_LOGIN_WINDOW_MINUTES = 2;
const FAILED_LOGIN_THRESHOLD = 5;
const BASELINE_LOOKBACK_DAYS = 90;
const BASELINE_MIN_SAMPLES = 5; // below this, skip the odd-hour rule (cold start)

// ---------------------------------------------------------------------------
// Public: scoreEvent — the sync, per-event entry point
// ---------------------------------------------------------------------------
/**
 * @param {import('pg').Pool | import('pg').PoolClient} db
 * @param {object} event
 * @param {number} event.userId
 * @param {number} event.auditLogId        - id of the row already inserted into audit_logs
 * @param {'login_success'|'login_failure'|'action'} event.eventType
 * @param {string} event.ip
 * @param {string} [event.deviceFingerprint]
 * @param {Date}   [event.timestamp]        - defaults to now
 * @returns {Promise<{riskScore:number, reasons:string[], flagged:boolean, alertCreated:boolean}>}
 */
async function scoreEvent(db, event) {
  const { userId, auditLogId, eventType, ip, deviceFingerprint } = event;
  const timestamp = event.timestamp || new Date();

  const reasons = [];
  let riskScore = 0;

  // Rule 1: new device
  if (deviceFingerprint) {
    const isNew = await checkNewDevice(db, userId, deviceFingerprint);
    if (isNew) {
      riskScore += WEIGHTS.NEW_DEVICE;
      reasons.push('new_device');
    } else {
      await touchTrustedDevice(db, userId, deviceFingerprint);
    }
  }

  // Rule 2: odd hour, vs. this user's own history
  if (eventType === 'login_success' || eventType === 'login_failure') {
    const isOdd = await checkOddHour(db, userId, timestamp);
    if (isOdd) {
      riskScore += WEIGHTS.ODD_HOUR;
      reasons.push('odd_hour');
    }
  }

  // Rule 3: repeated failures in a short window
  if (eventType === 'login_failure') {
    const burst = await checkFailedBurst(db, userId, ip);
    if (burst) {
      riskScore += WEIGHTS.FAILED_BURST;
      reasons.push('failed_login_burst');
    }
  }

  riskScore = Math.min(riskScore, 100);
  const flagged = riskScore >= THRESHOLDS.FLAG_FOR_STEP_UP;

  await db.query(
    `UPDATE audit_logs SET risk_score = $1, scored_at = now() WHERE id = $2`,
    [riskScore, auditLogId]
  );

  let alertCreated = false;
  if (riskScore >= THRESHOLDS.CREATE_ALERT || reasons.includes('failed_login_burst')) {
    await createAlert(db, { userId, auditLogId, riskScore, reasons });
    alertCreated = true;
  }

  return { riskScore, reasons, flagged, alertCreated };
}

// ---------------------------------------------------------------------------
// Public: runBatchAnomalyScan — async safety net
// ---------------------------------------------------------------------------
/**
 * Re-scores any audit_logs rows that slipped in without risk_score set
 * (e.g. inserted directly by another dev's route that forgot to call
 * scoreEvent). Also re-checks failure bursts across the whole table in
 * case events landed out of order. Designed to run on a timer.
 */
async function runBatchAnomalyScan(db, { lookbackMinutes = 10 } = {}) {
  const { rows } = await db.query(
    `SELECT id, user_id, event_type, ip_address, device_fingerprint, created_at
     FROM audit_logs
     WHERE risk_score IS NULL
       AND created_at > now() - ($1 || ' minutes')::interval
     ORDER BY created_at ASC`,
    [lookbackMinutes]
  );

  const results = [];
  for (const row of rows) {
    const result = await scoreEvent(db, {
      userId: row.user_id,
      auditLogId: row.id,
      eventType: row.event_type,
      ip: row.ip_address,
      deviceFingerprint: row.device_fingerprint,
      timestamp: row.created_at,
    });
    results.push({ auditLogId: row.id, ...result });
  }
  return results;
}

/** Convenience wrapper to run the batch scan on a fixed interval. */
function startBatchScanner(db, intervalMs = 60_000) {
  const handle = setInterval(() => {
    runBatchAnomalyScan(db).catch((err) => {
      // eslint-disable-next-line no-console
      console.error('[rulesEngine] batch scan failed:', err);
    });
  }, intervalMs);
  return () => clearInterval(handle); // caller can stop it in tests
}

// ---------------------------------------------------------------------------
// Rule implementations
// ---------------------------------------------------------------------------
async function checkNewDevice(db, userId, fingerprint) {
  const { rows } = await db.query(
    `SELECT 1 FROM trusted_devices WHERE user_id = $1 AND device_fingerprint = $2`,
    [userId, fingerprint]
  );
  return rows.length === 0;
}

async function touchTrustedDevice(db, userId, fingerprint) {
  await db.query(
    `UPDATE trusted_devices SET last_seen_at = now()
     WHERE user_id = $1 AND device_fingerprint = $2`,
    [userId, fingerprint]
  );
}

/**
 * Registers a device as trusted. Call this AFTER a successful login that
 * either passed step-up verification or wasn't flagged — not from
 * scoreEvent itself, so a brand-new device isn't silently auto-trusted
 * the moment it's first seen.
 */
async function trustDevice(db, userId, fingerprint, label = null) {
  await db.query(
    `INSERT INTO trusted_devices (user_id, device_fingerprint, label)
     VALUES ($1, $2, $3)
     ON CONFLICT (user_id, device_fingerprint)
     DO UPDATE SET last_seen_at = now()`,
    [userId, fingerprint, label]
  );
}

/**
 * Per-user baseline: looks at this user's own successful-login hours
 * (UTC) over the last BASELINE_LOOKBACK_DAYS. If they have too little
 * history, we skip the rule rather than risk false positives on new
 * accounts. Otherwise "odd" = an hour that's rare relative to their
 * own busiest hour.
 */
async function checkOddHour(db, userId, timestamp) {
  const { rows } = await db.query(
    `SELECT EXTRACT(HOUR FROM created_at)::int AS hr, COUNT(*)::int AS cnt
     FROM audit_logs
     WHERE user_id = $1
       AND event_type = 'login_success'
       AND created_at > now() - ($2 || ' days')::interval
     GROUP BY hr`,
    [userId, BASELINE_LOOKBACK_DAYS]
  );

  const totalSamples = rows.reduce((sum, r) => sum + r.cnt, 0);
  if (totalSamples < BASELINE_MIN_SAMPLES) return false; // cold start, skip

  const maxCount = Math.max(...rows.map((r) => r.cnt));
  const currentHour = new Date(timestamp).getUTCHours();
  const match = rows.find((r) => r.hr === currentHour);
  const currentCount = match ? match.cnt : 0;

  // "Typical" hour = at least 30% as frequent as this user's busiest hour.
  // A hour with zero history for this user is always odd.
  return currentCount < maxCount * 0.3;
}

async function checkFailedBurst(db, userId, ip) {
  const { rows } = await db.query(
    `SELECT COUNT(*)::int AS cnt FROM audit_logs
     WHERE event_type = 'login_failure'
       AND created_at > now() - ($1 || ' minutes')::interval
       AND (user_id = $2 OR ip_address = $3)`,
    [FAILED_LOGIN_WINDOW_MINUTES, userId, ip]
  );
  return rows[0].cnt >= FAILED_LOGIN_THRESHOLD;
}

async function createAlert(db, { userId, auditLogId, riskScore, reasons }) {
  const severity =
    reasons.includes('failed_login_burst') || riskScore >= 90
      ? 'critical'
      : riskScore >= 75
      ? 'high'
      : riskScore >= 60
      ? 'medium'
      : 'low';

  await db.query(
    `INSERT INTO alerts (audit_log_id, user_id, risk_score, severity, reasons)
     VALUES ($1, $2, $3, $4, $5::jsonb)`,
    [auditLogId, userId, riskScore, severity, JSON.stringify(reasons)]
  );
}

module.exports = {
  scoreEvent,
  runBatchAnomalyScan,
  startBatchScanner,
  trustDevice,
  // exported for unit tests:
  _internal: { checkNewDevice, checkOddHour, checkFailedBurst, WEIGHTS, THRESHOLDS },
};
