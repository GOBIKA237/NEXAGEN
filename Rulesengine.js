/**
 * AccessOS — Rules Engine
 * Owner: Lead (Architecture + Rules Engine)
 * Matches the team-agreed schema: no trusted_devices table, no alerts table —
 * "new device" is derived from login_events history, and alerts are computed
 * on the fly by adminAlerts.js reading risk_score off login_events.
 *
 * Two entry points other devs / routes call:
 *
 *   scoreEvent(pool, event)   -> sync. Call this INLINE from /api/auth/login
 *                                (Backend Dev 1), right after inserting the
 *                                login_events row.
 *
 *   runBatchAnomalyScan(pool) -> async, run on an interval (see
 *                                startBatchScanner). Re-scores recent
 *                                login_events so risk scores stay current
 *                                as new failed attempts accumulate, even
 *                                if nothing calls scoreEvent again.
 */

'use strict';

// ---------------------------------------------------------------------------
// Config — tune here, not scattered through the rules
// ---------------------------------------------------------------------------
const WEIGHTS = {
  NEW_DEVICE: 40,
  ODD_HOUR: 30,
  FAILED_BURST: 60,
};

const THRESHOLDS = {
  FLAG_FOR_STEP_UP: 50, // risk_score >= this => require step-up verification
  ALERT_VISIBLE: 60, // risk_score >= this => shows up in GET /api/admin/alerts
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
 * @param {number} event.loginEventId       - id of the row already inserted into login_events
 * @param {boolean} event.success
 * @param {string} event.ip
 * @param {string} [event.deviceFingerprint]
 * @param {Date}   [event.timestamp]        - defaults to now
 * @returns {Promise<{riskScore:number, reasons:string[], flagged:boolean}>}
 */
async function scoreEvent(db, event) {
  const { userId, loginEventId, success, ip, deviceFingerprint } = event;
  const timestamp = event.timestamp || new Date();

  const reasons = [];
  let riskScore = 0;

  // Rule 1: new device — no history of this user succeeding from this
  // fingerprint before. Only meaningful on successful logins; a failed
  // attempt from a new device is already covered by the burst rule.
  if (deviceFingerprint) {
    const isNew = await checkNewDevice(db, userId, deviceFingerprint, loginEventId);
    if (isNew) {
      riskScore += WEIGHTS.NEW_DEVICE;
      reasons.push('new_device');
    }
  }

  // Rule 2: odd hour, vs. this user's own history of successful logins
  const isOdd = await checkOddHour(db, userId, timestamp);
  if (isOdd) {
    riskScore += WEIGHTS.ODD_HOUR;
    reasons.push('odd_hour');
  }

  // Rule 3: 5+ failed attempts within 2 minutes (by this user or this IP)
  if (!success) {
    const burst = await checkFailedBurst(db, userId, ip);
    if (burst) {
      riskScore += WEIGHTS.FAILED_BURST;
      reasons.push('failed_login_burst');
    }
  }

  riskScore = Math.min(riskScore, 100);
  const flagged = riskScore >= THRESHOLDS.FLAG_FOR_STEP_UP;

  await db.query(`UPDATE login_events SET risk_score = $1 WHERE id = $2`, [
    riskScore,
    loginEventId,
  ]);

  return { riskScore, reasons, flagged };
}

// ---------------------------------------------------------------------------
// Public: runBatchAnomalyScan — async safety net
// ---------------------------------------------------------------------------
/**
 * Re-scores login_events from the last `lookbackMinutes`. Because
 * login_events.risk_score defaults to 0 (not NULL), we can't cheaply tell
 * "never scored" apart from "genuinely scored as zero risk" — so instead
 * of hunting for unscored rows, this just re-runs scoring on the recent
 * window. It's idempotent and cheap, and it's what lets the failed-burst
 * rule catch a user whose 5th failure happens after their earlier attempts
 * were already scored individually.
 */
async function runBatchAnomalyScan(db, { lookbackMinutes = 10 } = {}) {
  const { rows } = await db.query(
    `SELECT id, user_id, success, ip_address, device_fingerprint, created_at
     FROM login_events
     WHERE created_at > now() - ($1 || ' minutes')::interval
     ORDER BY created_at ASC`,
    [lookbackMinutes]
  );

  const results = [];
  for (const row of rows) {
    const result = await scoreEvent(db, {
      userId: row.user_id,
      loginEventId: row.id,
      success: row.success,
      ip: row.ip_address,
      deviceFingerprint: row.device_fingerprint,
      timestamp: row.created_at,
    });
    results.push({ loginEventId: row.id, ...result });
  }
  return results;
}

/** Runs the batch scan on a fixed interval. Returns a function to stop it. */
function startBatchScanner(db, intervalMs = 60_000) {
  const handle = setInterval(() => {
    runBatchAnomalyScan(db).catch((err) => {
      // eslint-disable-next-line no-console
      console.error('[rulesEngine] batch scan failed:', err);
    });
  }, intervalMs);
  return () => clearInterval(handle);
}

// ---------------------------------------------------------------------------
// Rule implementations
// ---------------------------------------------------------------------------

/** New device = no prior SUCCESSFUL login_events row for this user+fingerprint. */
async function checkNewDevice(db, userId, fingerprint, currentLoginEventId) {
  const { rows } = await db.query(
    `SELECT 1 FROM login_events
     WHERE user_id = $1 AND device_fingerprint = $2 AND success = true AND id <> $3
     LIMIT 1`,
    [userId, fingerprint, currentLoginEventId]
  );
  return rows.length === 0;
}

/**
 * Per-user baseline: this user's own successful-login hours (UTC) over the
 * last BASELINE_LOOKBACK_DAYS. Too little history => skip the rule rather
 * than risk false positives on new accounts. Otherwise "odd" = an hour
 * that's rare relative to their own busiest hour.
 */
async function checkOddHour(db, userId, timestamp) {
  const { rows } = await db.query(
    `SELECT EXTRACT(HOUR FROM created_at)::int AS hr, COUNT(*)::int AS cnt
     FROM login_events
     WHERE user_id = $1
       AND success = true
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
  return currentCount < maxCount * 0.3;
}

async function checkFailedBurst(db, userId, ip) {
  const { rows } = await db.query(
    `SELECT COUNT(*)::int AS cnt FROM login_events
     WHERE success = false
       AND created_at > now() - ($1 || ' minutes')::interval
       AND (user_id = $2 OR ip_address = $3)`,
    [FAILED_LOGIN_WINDOW_MINUTES, userId, ip]
  );
  return rows[0].cnt >= FAILED_LOGIN_THRESHOLD;
}

module.exports = {
  scoreEvent,
  runBatchAnomalyScan,
  startBatchScanner,
  // exported for unit tests:
  _internal: { checkNewDevice, checkOddHour, checkFailedBurst, WEIGHTS, THRESHOLDS },
};
