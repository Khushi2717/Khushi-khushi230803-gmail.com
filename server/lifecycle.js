import { forbidden, badRequest, lastOwner } from './http.js';
import { resolve } from './permissions.js';

// roles.rank is MODIFICATION AUTHORITY ONLY (PERMISSIONS.md D8) — never used to
// answer a can() question. operator/auditor are unordered by permission; this rank
// exists solely to answer "who may modify whom".
export function roleRanks(db) {
  const rows = db.prepare(`SELECT key, rank FROM roles`).all();
  const ranks = {};
  for (const r of rows) ranks[r.key] = r.rank;
  return ranks;
}

export function assertRoleExists(db, role) {
  const row = db.prepare(`SELECT key FROM roles WHERE key = ?`).get(role);
  if (!row) throw badRequest(`unknown role: ${role}`);
}

// §6: modify a strictly-lower role -> allowed. Equal role (admin -> admin) -> 403.
// Assigning a role higher than your own is caught by the same comparison, since a
// caller can never outrank themselves. Self-role-change and last-owner protection
// are separate, more specific rules — checked by the caller, not here.
export function assertCanModify(db, callerRole, targetRole) {
  const ranks = roleRanks(db);
  const callerRank = ranks[callerRole];
  const targetRank = ranks[targetRole];
  if (callerRank === undefined || targetRank === undefined) {
    throw badRequest('unknown role in modification check');
  }
  // Higher rank number = higher authority (owner=50, admin=40, operator=30,
  // auditor=20, viewer=10 — confirmed against db/reference.sql, corrected after
  // check-api.js caught the original assumption being backwards). callerRank must
  // be STRICTLY more authoritative than targetRank.
  if (!(callerRank > targetRank)) {
    throw forbidden('cannot modify a member of equal or higher role', 'scope_mismatch');
  }
}

// An org must always have at least one owner (invariant 5). Call this BEFORE removing,
// demoting, or suspending someone who currently holds 'owner'.
export function assertNotLastOwner(db, orgId, userId) {
  const membership = db
    .prepare(`SELECT role FROM memberships WHERE org_id = ? AND user_id = ? AND status = 'active'`)
    .get(orgId, userId);
  if (!membership || membership.role !== 'owner') return; // not an owner, nothing to protect

  const ownerCount = db
    .prepare(`SELECT COUNT(*) AS n FROM memberships WHERE org_id = ? AND role = 'owner' AND status = 'active'`)
    .get(orgId).n;

  if (ownerCount <= 1) throw lastOwner();
}

// The one place sessions get ended. §7.2: account/tenancy events cascade (suspend,
// remove, device transfer); permission tweaks never do — there is deliberately no
// 'permission_revoked' end_reason.
export function endActiveSessions(db, { orgId, userId = null, deviceId = null, reason, exceptSessionId = null }) {
  const conditions = [`org_id = ?`, `state = 'active'`];
  const params = [orgId];

  if (userId !== null) { conditions.push(`user_id = ?`); params.push(userId); }
  if (deviceId !== null) { conditions.push(`device_id = ?`); params.push(deviceId); }
  if (exceptSessionId !== null) { conditions.push(`id != ?`); params.push(exceptSessionId); }

  const now = new Date().toISOString();
  db.prepare(
    `UPDATE sessions SET state = 'ended', end_reason = ?, ended_at = ?
     WHERE ${conditions.join(' AND ')}`
  ).run(reason, now, ...params);
}

// A session's authority is a SNAPSHOT taken at start time and frozen for the session's
// life (§7.1) — later grant/role changes don't retroactively touch it. authorized_by
// is stored as JSON text (schema requires json_valid()).
export function snapshotAuthority(db, { userId, orgId, deviceId }) {
  const resolved = resolve(db, { userId, orgId, deviceId });
  return JSON.stringify(resolved.permissions);
}

// expires_at = started_at + org.max_session_minutes (default 60). This is what makes
// grandfathering safe: a revoked grant's authority dies with the session, within the
// hour at the latest, with no restart needed.
export function sessionExpiry(db, orgId) {
  const org = db.prepare(`SELECT max_session_minutes FROM organizations WHERE id = ?`).get(orgId);
  const minutes = org ? org.max_session_minutes : 60;
  return new Date(Date.now() + minutes * 60 * 1000).toISOString();
}