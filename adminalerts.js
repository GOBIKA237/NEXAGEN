/**
 * AccessOS — GET /api/admin/alerts
 * Owner: Lead
 *
 * Alerts are NOT stored in their own table — there is no `alerts` table in
 * the agreed schema. This endpoint computes them on the fly by reading
 * risk_score off login_events. If the team later wants persistent alert
 * status (acknowledge/resolve, alert history for the demo), add an
 * `alerts` table and this file just becomes a plain SELECT instead — flag
 * it and I'll update both this and rulesEngine.js.
 *
 * Wire this into the main app with:
 *   const checkPermission = require('../middleware/checkPermission'); // Backend Dev 2's middleware
 *   app.use('/api/admin/alerts', checkPermission('view_alerts'), require('./routes/adminAlerts')(pool));
 */

'use strict';
const express = require('express');

module.exports = function adminAlertsRouter(pool) {
  const router = express.Router();

  /**
   * GET /api/admin/alerts
   * Query params (all optional):
   *   minRiskScore - default 60 (matches THRESHOLDS.ALERT_VISIBLE in rulesEngine.js)
   *   userId       - filter to one user
   *   sinceHours   - how far back to look, default 24
   *   limit        - default 50, max 200
   *   offset       - default 0
   *
   * Response 200:
   * {
   *   "alerts": [
   *     {
   *       "loginEventId": 981,
   *       "userId": 4,
   *       "userEmail": "jane@college.edu",
   *       "riskScore": 85,
   *       "severity": "high",
   *       "success": true,
   *       "ipAddress": "10.0.0.4",
   *       "deviceFingerprint": "a1b2c3...",
   *       "createdAt": "2026-07-16T02:14:00.000Z"
   *     }
   *   ],
   *   "total": 1
   * }
   */
  router.get('/', async (req, res) => {
    try {
      const minRiskScore = req.query.minRiskScore ? Number(req.query.minRiskScore) : 60;
      const userId = req.query.userId ? Number(req.query.userId) : null;
      const sinceHours = req.query.sinceHours ? Number(req.query.sinceHours) : 24;
      const limit = Math.min(Number(req.query.limit) || 50, 200);
      const offset = Number(req.query.offset) || 0;

      const conditions = ['le.risk_score >= $1', `le.created_at > now() - ($2 || ' hours')::interval`];
      const params = [minRiskScore, sinceHours];

      if (userId) {
        params.push(userId);
        conditions.push(`le.user_id = $${params.length}`);
      }

      const whereClause = conditions.join(' AND ');

      const countResult = await pool.query(
        `SELECT COUNT(*)::int AS total FROM login_events le WHERE ${whereClause}`,
        params
      );

      params.push(limit, offset);
      const dataResult = await pool.query(
        `SELECT le.id, le.user_id, le.risk_score, le.success, le.ip_address,
                le.device_fingerprint, le.created_at, u.email AS user_email
         FROM login_events le
         LEFT JOIN users u ON u.id = le.user_id
         WHERE ${whereClause}
         ORDER BY le.risk_score DESC, le.created_at DESC
         LIMIT $${params.length - 1} OFFSET $${params.length}`,
        params
      );

      const alerts = dataResult.rows.map((r) => ({
        loginEventId: r.id,
        userId: r.user_id,
        userEmail: r.user_email,
        riskScore: r.risk_score,
        severity: severityFor(r.risk_score),
        success: r.success,
        ipAddress: r.ip_address,
        deviceFingerprint: r.device_fingerprint,
        createdAt: r.created_at,
      }));

      res.json({ alerts, total: countResult.rows[0].total });
    } catch (err) {
      // eslint-disable-next-line no-console
      console.error('[adminAlerts] GET / failed:', err);
      res.status(500).json({ error: 'Failed to fetch alerts' });
    }
  });

  return router;
};

function severityFor(riskScore) {
  if (riskScore >= 90) return 'critical';
  if (riskScore >= 75) return 'high';
  if (riskScore >= 60) return 'medium';
  return 'low';
}
