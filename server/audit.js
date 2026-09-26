import { newId, nowIso } from './db.js';
import { HttpError } from './http.js';

// Single INSERT — audit_events is append-only (triggers block UPDATE/DELETE), so this
// module never does anything but write new rows.
export function audit(db, { orgId, actorId, action, targetType = null, targetId = null, result, reasonCode = null, requestId = null }) {
  db.prepare(
    `INSERT INTO audit_events (id, org_id, actor_id, action, target_type, target_id, result, reason_code, request_id, at)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).run(newId('evt'), orgId, actorId ?? null, action, targetType, targetId, result, reasonCode, requestId, nowIso());
}

// Wrap a route's core logic: if fn() throws a 403 FORBIDDEN (a permission refusal),
// record that as a 'deny' row before rethrowing — so the audit log holds attempted
// actions, not just completed ones. Any other kind of error passes straight through
// unlogged (not every error is a permission decision worth auditing).
export function auditDenials(db, ctx, meta, fn) {
  try {
    return fn();
  } catch (err) {
    if (err instanceof HttpError && err.code === 'FORBIDDEN') {
      audit(db, {
        orgId: ctx.orgId,
        actorId: ctx.userId,
        action: meta.action,
        targetType: meta.targetType ?? null,
        targetId: meta.targetId ?? null,
        result: 'deny',
        reasonCode: err.reason ?? null,
        requestId: meta.requestId ?? null,
      });
    }
    throw err;
  }
}