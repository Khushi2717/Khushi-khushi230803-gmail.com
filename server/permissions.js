import { forbidden, badRequest } from './http.js';

export const MODE_PERMISSION = { view: 'device:view', control: 'device:control', terminal: 'device:terminal' };

function patternMatches(pattern, permission) {
  if (pattern === '*') return true;
  if (pattern === permission) return true;
  if (pattern.endsWith(':*')) {
    const prefix = pattern.slice(0, -1);
    return permission.startsWith(prefix);
  }
  return false;
}

export function resolve(db, { userId, orgId, deviceId = null, now = new Date() }) {
  const membership = db
    .prepare(`SELECT * FROM memberships WHERE org_id = ? AND user_id = ?`)
    .get(orgId, userId);

  const allPermissions = db.prepare(`SELECT key, resource FROM permissions`).all();
  const permissions = {};

  // No membership row at all: caller isn't a member of this org.
  if (!membership) {
    for (const p of allPermissions) permissions[p.key] = { effect: 'deny', source: null, reason: 'not_a_member' };
    return { role: null, permissions };
  }

  // Membership exists but isn't active: identity first (D4/§3 step 1). Distinguish
  // suspended from other non-active states since the API's reason codes do.
  if (membership.status !== 'active') {
    const reason = membership.status === 'suspended' ? 'suspended' : 'not_a_member';
    for (const p of allPermissions) permissions[p.key] = { effect: 'deny', source: null, reason };
    return { role: membership.role, permissions };
  }

  const role = membership.role;
  const baseline = new Set(
    db.prepare(`SELECT permission FROM role_permissions WHERE role = ?`).all(role).map((r) => r.permission)
  );

  const nowIso = now.toISOString();

  const grants = db
    .prepare(
      `SELECT g.id, g.device_id, g.effect, g.starts_at, g.expires_at, gp.permission AS pattern
       FROM grants g
       JOIN grant_permissions gp ON gp.grant_id = g.id
       WHERE g.org_id = ? AND g.user_id = ? AND g.revoked_at IS NULL`
    )
    .all(orgId, userId)
    .filter((g) => (g.starts_at === null || g.starts_at <= nowIso) && (g.expires_at === null || nowIso < g.expires_at));

  let orgDeviceIds = null;
  if (deviceId === null) {
    orgDeviceIds = db
      .prepare(`SELECT id FROM devices WHERE org_id = ? AND deleted_at IS NULL`)
      .all(orgId)
      .map((d) => d.id);
  }

  function resolveOneDevice(permission, devId) {
    const applicable = grants.filter(
      (g) => (g.device_id === null || g.device_id === devId) && patternMatches(g.pattern, permission)
    );
    const deny = applicable.find((g) => g.effect === 'deny');
    if (deny) return { effect: 'deny', source: `grant:${deny.id}`, reason: 'explicit_deny' };

    const allow = applicable.find((g) => g.effect === 'allow');
    if (allow) return { effect: 'allow', source: `grant:${allow.id}`, reason: null };

    if (baseline.has(permission)) return { effect: 'allow', source: `role:${role}`, reason: null };

    return { effect: 'deny', source: null, reason: 'implicit' };
  }

  for (const p of allPermissions) {
    const isDeviceScoped = p.resource === 'device';

    if (deviceId !== null) {
      permissions[p.key] = resolveOneDevice(p.key, deviceId);
    } else if (isDeviceScoped && orgDeviceIds && orgDeviceIds.length > 0) {
      let picked = null;
      for (const devId of orgDeviceIds) {
        const r = resolveOneDevice(p.key, devId);
        if (r.effect === 'allow') { picked = r; break; }
        if (!picked) picked = r;
      }
      permissions[p.key] = picked;
    } else {
      permissions[p.key] = resolveOneDevice(p.key, null);
    }
  }

  return { role, permissions };
}

export function resolveDevices(db, { userId, orgId, deviceIds, now = new Date() }) {
  const membership = db
    .prepare(`SELECT role FROM memberships WHERE org_id = ? AND user_id = ?`)
    .get(orgId, userId);

  const byDevice = {};
  for (const id of deviceIds) {
    byDevice[id] = resolve(db, { userId, orgId, deviceId: id, now }).permissions;
  }
  return { role: membership ? membership.role : null, byDevice };
}

export function can(db, ctx, permission, deviceId = null) {
  const resolved = resolve(db, { userId: ctx.userId, orgId: ctx.orgId, deviceId });
  return resolved.permissions[permission]?.effect === 'allow';
}

export function assertCan(db, ctx, permission, deviceId = null) {
  const resolved = resolve(db, { userId: ctx.userId, orgId: ctx.orgId, deviceId });
  const entry = resolved.permissions[permission];
  if (!entry || entry.effect !== 'allow') {
    throw forbidden(`missing permission: ${permission}`, entry?.reason ?? 'missing_permission');
  }
  return entry;
}

export function assertMayGrant(db, ctx, patterns, deviceId = null) {
  const allKeys = db.prepare(`SELECT key FROM permissions`).all().map((p) => p.key);
  const resolved = resolve(db, { userId: ctx.userId, orgId: ctx.orgId, deviceId });

  for (const pattern of patterns) {
    const covered = allKeys.filter((key) => patternMatches(pattern, key));
    for (const key of covered) {
      if (resolved.permissions[key]?.effect !== 'allow') {
        throw forbidden(`cannot grant ${pattern}: you do not hold ${key} at this scope`, 'scope_mismatch');
      }
    }
  }
}

// Compound check: session:start AND the mode's own permission, same device. The two
// failure reasons are FIXED codes (not resolve()'s own reason), so the caller can tell
// WHICH of the two was missing, per BRIEF.md §5.1.
export function assertCanStartSession(db, ctx, mode, deviceId) {
  const modePermission = MODE_PERMISSION[mode];
  if (!modePermission) throw badRequest(`invalid session mode: ${mode}`);

  const resolved = resolve(db, { userId: ctx.userId, orgId: ctx.orgId, deviceId }).permissions;

  if (resolved['session:start']?.effect !== 'allow') {
    throw forbidden('missing permission: session:start', 'missing_permission');
  }
  if (resolved[modePermission]?.effect !== 'allow') {
    throw forbidden(`missing permission: ${modePermission}`, 'missing_device_permission');
  }
}