import { randomUUID } from 'node:crypto';
import {
  badRequest, unauthenticated, forbidden, notFound, conflict, gone, selfRoleChange,
  deviceBusy, HttpError, send, normalizeTs,
} from '../http.js';
import { newId, nowIso, bumpPermVersion } from '../db.js';
import {
  issueAccessToken, newRefreshToken, newInviteToken, hashRefreshToken, hashInviteToken,
  hashPassword, verifyPassword, ACCESS_TTL_SECONDS,
} from '../auth.js';
import { resolve, resolveDevices, assertCan, assertMayGrant, assertCanStartSession } from '../permissions.js';
import { assertRoleExists, assertCanModify, assertNotLastOwner, endActiveSessions, snapshotAuthority, sessionExpiry } from '../lifecycle.js';
import { audit } from '../audit.js';

const REFRESH_TTL_MS = 30 * 24 * 60 * 60 * 1000;

export function registerRoutes(router, deps) {
  const { db, secret } = deps;

  // ---- small helpers, used across several routes ----------------------
  function setRefreshCookie(res, token, maxAgeSeconds) {
    res.setHeader('Set-Cookie', `refresh_token=${token}; HttpOnly; Path=/v1/auth; Max-Age=${maxAgeSeconds}; SameSite=Strict`);
  }
  function getCookie(req, name) {
    const header = req.headers.cookie;
    if (!header) return null;
    for (const part of header.split(';')) {
      const [k, ...v] = part.trim().split('=');
      if (k === name) return v.join('=');
    }
    return null;
  }
  function getOrgOr404(orgId) {
    const org = db.prepare(`SELECT * FROM organizations WHERE id = ? AND deleted_at IS NULL`).get(orgId);
    if (!org) throw notFound();
    return org;
  }
  function getDeviceOr404(orgId, deviceId) {
    const device = db.prepare(`SELECT * FROM devices WHERE id = ? AND org_id = ? AND deleted_at IS NULL`).get(deviceId, orgId);
    if (!device) throw notFound();
    return device;
  }
  function issueForMembership(userId, membership) {
    return issueAccessToken(
      { userId, orgId: membership.org_id, role: membership.role, permVersion: membership.perm_version },
      secret
    );
  }

  // =====================================================================
  // AUTH
  // =====================================================================
  router.post('/v1/auth/login', async (ctx, params, res) => {
    const { email, password } = ctx.body;
    if (!email || !password) throw badRequest('email and password are required');

    const user = db.prepare(`SELECT * FROM users WHERE email = ?`).get(String(email).toLowerCase());
    // Same failure for "no such user" and "wrong password" — avoids an account
    // enumeration oracle (BRIEF.md §5.3).
    if (!user || !verifyPassword(password, user.password_hash)) {
      throw unauthenticated('invalid email or password');
    }

    const memberships = db.prepare(
      `SELECT m.* FROM memberships m JOIN organizations o ON o.id = m.org_id
       WHERE m.user_id = ? AND m.status = 'active' AND o.deleted_at IS NULL`
    ).all(user.id);
    if (memberships.length === 0) throw unauthenticated('no active organization membership');

    const active = memberships[0]; // arbitrary but deterministic starting org
    const access = issueForMembership(user.id, active);

    const refreshRaw = newRefreshToken();
    db.prepare(
      `INSERT INTO refresh_tokens (id, user_id, token_hash, family_id, expires_at) VALUES (?, ?, ?, ?, ?)`
    ).run(newId('rt'), user.id, hashRefreshToken(refreshRaw), newId('fam'), new Date(Date.now() + REFRESH_TTL_MS).toISOString());

    setRefreshCookie(res, refreshRaw, REFRESH_TTL_MS / 1000);
    send(res, 200, { accessToken: access, expiresIn: ACCESS_TTL_SECONDS });
  });

  router.post('/v1/auth/refresh', async (ctx, params, res) => {
    const raw = getCookie(ctx.req, 'refresh_token');
    if (!raw) throw unauthenticated('missing refresh token');
    const row = db.prepare(`SELECT * FROM refresh_tokens WHERE token_hash = ?`).get(hashRefreshToken(raw));
    if (!row || row.revoked_at || row.expires_at <= nowIso()) throw unauthenticated('invalid refresh token');

    db.prepare(`UPDATE refresh_tokens SET revoked_at = ? WHERE id = ?`).run(nowIso(), row.id);
    const newRaw = newRefreshToken();
    db.prepare(
      `INSERT INTO refresh_tokens (id, user_id, token_hash, family_id, expires_at) VALUES (?, ?, ?, ?, ?)`
    ).run(newId('rt'), row.user_id, hashRefreshToken(newRaw), row.family_id, new Date(Date.now() + REFRESH_TTL_MS).toISOString());
    setRefreshCookie(res, newRaw, REFRESH_TTL_MS / 1000);

    const membership = db.prepare(`SELECT * FROM memberships WHERE user_id = ? AND status = 'active'`).get(row.user_id);
    if (!membership) throw unauthenticated('no active membership');
    send(res, 200, { accessToken: issueForMembership(row.user_id, membership), expiresIn: ACCESS_TTL_SECONDS });
  });

  router.post('/v1/auth/token', async (ctx, params, res) => {
    const { orgId } = ctx.body;
    if (!orgId) throw badRequest('orgId is required');
    const membership = db.prepare(`SELECT * FROM memberships WHERE org_id = ? AND user_id = ? AND status = 'active'`).get(orgId, ctx.userId);
    if (!membership) throw notFound(); // not a member -> invisible, never 403
    send(res, 200, { accessToken: issueForMembership(ctx.userId, membership), expiresIn: ACCESS_TTL_SECONDS });
  });

  router.get('/v1/auth/me', async (ctx, params, res) => {
    const user = db.prepare(`SELECT id, email, name FROM users WHERE id = ?`).get(ctx.userId);
    const orgs = db.prepare(
      `SELECT o.id, o.name, o.theme, m.role FROM memberships m JOIN organizations o ON o.id = m.org_id
       WHERE m.user_id = ? AND m.status = 'active' AND o.deleted_at IS NULL`
    ).all(ctx.userId);
    const resolved = resolve(db, { userId: ctx.userId, orgId: ctx.orgId, deviceId: null });
    send(res, 200, { user, orgId: ctx.orgId, role: ctx.role, orgs, permissions: resolved.permissions });
  });

  // =====================================================================
  // ORGS
  // =====================================================================
  router.get('/v1/orgs', async (ctx, params, res) => {
    const orgs = db.prepare(
      `SELECT o.id, o.name, o.theme, m.role FROM memberships m JOIN organizations o ON o.id = m.org_id
       WHERE m.user_id = ? AND m.status = 'active' AND o.deleted_at IS NULL`
    ).all(ctx.userId);
    send(res, 200, { orgs });
  });

  router.post('/v1/orgs', async (ctx, params, res) => {
    const { name, theme } = ctx.body;
    if (!name || typeof name !== 'string' || name.length > 200) throw badRequest('name is required');
    const orgId = newId('org');
    db.prepare(`INSERT INTO organizations (id, name, theme) VALUES (?, ?, ?)`).run(orgId, name, theme || 'slate');
    db.prepare(
      `INSERT INTO memberships (id, org_id, user_id, role, status, joined_at) VALUES (?, ?, ?, 'owner', 'active', ?)`
    ).run(newId('mem'), orgId, ctx.userId, nowIso());
    audit(db, { orgId, actorId: ctx.userId, action: 'org.create', targetType: 'organization', targetId: orgId, result: 'allow', requestId: ctx.requestId });
    send(res, 201, { id: orgId, name, theme: theme || 'slate', role: 'owner' });
  });

  router.patch('/v1/orgs/:org', async (ctx, params, res) => {
    getOrgOr404(ctx.orgId);
    assertCan(db, ctx, 'org:update');
    const { name, theme, maxSessionMinutes } = ctx.body;
    const updates = []; const values = [];
    if (name !== undefined) { updates.push('name = ?'); values.push(name); }
    if (theme !== undefined) { updates.push('theme = ?'); values.push(theme); }
    if (maxSessionMinutes !== undefined) { updates.push('max_session_minutes = ?'); values.push(maxSessionMinutes); }
    if (updates.length === 0) throw badRequest('nothing to update');
    values.push(ctx.orgId);
    db.prepare(`UPDATE organizations SET ${updates.join(', ')} WHERE id = ?`).run(...values);
    audit(db, { orgId: ctx.orgId, actorId: ctx.userId, action: 'org.update', targetType: 'organization', targetId: ctx.orgId, result: 'allow', requestId: ctx.requestId });
    send(res, 200, { ok: true });
  });

  router.delete('/v1/orgs/:org', async (ctx, params, res) => {
    getOrgOr404(ctx.orgId);
    assertCan(db, ctx, 'org:delete');
    db.prepare(`UPDATE organizations SET deleted_at = ? WHERE id = ?`).run(nowIso(), ctx.orgId);
    audit(db, { orgId: ctx.orgId, actorId: ctx.userId, action: 'org.delete', targetType: 'organization', targetId: ctx.orgId, result: 'allow', requestId: ctx.requestId });
    send(res, 200, { ok: true });
  });

  // =====================================================================
  // MEMBERS & INVITES
  // =====================================================================
  router.get('/v1/orgs/:org/members', async (ctx, params, res) => {
    assertCan(db, ctx, 'user:read');
    const rows = db.prepare(
      `SELECT m.user_id, u.email, u.name, m.role, m.status FROM memberships m JOIN users u ON u.id = m.user_id
       WHERE m.org_id = ? AND m.status != 'removed'`
    ).all(ctx.orgId);
    send(res, 200, { members: rows });
  });

  router.post('/v1/orgs/:org/invites', async (ctx, params, res) => {
    assertCan(db, ctx, 'user:invite');
    const { email, role } = ctx.body;
    if (!email || !role) throw badRequest('email and role are required');
    assertRoleExists(db, role);
    const raw = newInviteToken();
    const id = newId('inv');
    try {
      db.prepare(
        `INSERT INTO invites (id, org_id, email, role, token_hash, invited_by, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)`
      ).run(id, ctx.orgId, String(email).toLowerCase(), role, hashInviteToken(raw), ctx.userId, new Date(Date.now() + 7*24*60*60*1000).toISOString());
    } catch {
      throw conflict('an active invite for this email already exists');
    }
    audit(db, { orgId: ctx.orgId, actorId: ctx.userId, action: 'invite.create', targetType: 'invite', targetId: id, result: 'allow', requestId: ctx.requestId });
    send(res, 201, { id, email, role, token: raw }); // returned once, per BRIEF.md §4 (invite tokens are credentials)
  });

  router.get('/v1/orgs/:org/invites', async (ctx, params, res) => {
    assertCan(db, ctx, 'user:invite');
    const rows = db.prepare(`SELECT id, email, role, expires_at, accepted_at, revoked_at FROM invites WHERE org_id = ?`).all(ctx.orgId);
    send(res, 200, { invites: rows });
  });

  router.delete('/v1/orgs/:org/invites/:id', async (ctx, params, res) => {
    assertCan(db, ctx, 'user:invite');
    const invite = db.prepare(`SELECT * FROM invites WHERE id = ? AND org_id = ?`).get(params.id, ctx.orgId);
    if (!invite) throw notFound();
    db.prepare(`UPDATE invites SET revoked_at = ? WHERE id = ?`).run(nowIso(), invite.id);
    audit(db, { orgId: ctx.orgId, actorId: ctx.userId, action: 'invite.revoke', targetType: 'invite', targetId: invite.id, result: 'allow', requestId: ctx.requestId });
    send(res, 200, { ok: true });
  });

  // Public — no auth required.
  router.get('/v1/invites/:token', async (ctx, params, res) => {
    const invite = db.prepare(`SELECT * FROM invites WHERE token_hash = ?`).get(hashInviteToken(params.token));
    if (!invite || invite.revoked_at || invite.accepted_at || invite.expires_at <= nowIso()) throw gone();
    const org = db.prepare(`SELECT id, name, theme FROM organizations WHERE id = ?`).get(invite.org_id);
    send(res, 200, { email: invite.email, role: invite.role, org });
  });

  // Public — no auth required.
  router.post('/v1/invites/:token/accept', async (ctx, params, res) => {
    const invite = db.prepare(`SELECT * FROM invites WHERE token_hash = ?`).get(hashInviteToken(params.token));
    if (!invite || invite.revoked_at || invite.accepted_at || invite.expires_at <= nowIso()) throw gone();

    const { name, password } = ctx.body;
    let user = db.prepare(`SELECT * FROM users WHERE email = ?`).get(invite.email);
    if (!user) {
      if (!name || !password) throw badRequest('name and password are required for a new account');
      const userId = newId('usr');
      db.prepare(`INSERT INTO users (id, email, name, password_hash) VALUES (?, ?, ?, ?)`).run(userId, invite.email, name, hashPassword(password));
      user = { id: userId };
    }

    const existing = db.prepare(`SELECT * FROM memberships WHERE org_id = ? AND user_id = ?`).get(invite.org_id, user.id);
    if (existing) {
      db.prepare(`UPDATE memberships SET role = ?, status = 'active', joined_at = ? WHERE id = ?`).run(invite.role, nowIso(), existing.id);
    } else {
      db.prepare(
        `INSERT INTO memberships (id, org_id, user_id, role, status, invited_by, joined_at) VALUES (?, ?, ?, ?, 'active', ?, ?)`
      ).run(newId('mem'), invite.org_id, user.id, invite.role, invite.invited_by, nowIso());
    }

    db.prepare(`UPDATE invites SET accepted_at = ?, accepted_by = ? WHERE id = ?`).run(nowIso(), user.id, invite.id);
    audit(db, { orgId: invite.org_id, actorId: user.id, action: 'invite.accept', targetType: 'invite', targetId: invite.id, result: 'allow', requestId: ctx.requestId });
    send(res, 200, { ok: true, orgId: invite.org_id });
  });

  router.patch('/v1/orgs/:org/members/:userId', async (ctx, params, res) => {
    assertCan(db, ctx, 'user:role:update');
    if (params.userId === ctx.userId) throw selfRoleChange();
    const target = db.prepare(`SELECT * FROM memberships WHERE org_id = ? AND user_id = ? AND status != 'removed'`).get(ctx.orgId, params.userId);
    if (!target) throw notFound();
    const { role } = ctx.body;
    if (!role) throw badRequest('role is required');
    assertRoleExists(db, role);
    assertCanModify(db, ctx.role, target.role);
    if (role === 'owner' && ctx.role !== 'owner') throw forbidden('only an owner may assign the owner role');
    if (target.role === 'owner' && role !== 'owner') assertNotLastOwner(db, ctx.orgId, params.userId);

    db.prepare(`UPDATE memberships SET role = ?, perm_version = perm_version + 1 WHERE id = ?`).run(role, target.id);
    audit(db, { orgId: ctx.orgId, actorId: ctx.userId, action: 'member.role_update', targetType: 'user', targetId: params.userId, result: 'allow', requestId: ctx.requestId });
    send(res, 200, { ok: true });
  });

  router.post('/v1/orgs/:org/members/:userId/suspend', async (ctx, params, res) => {
    assertCan(db, ctx, 'user:remove');
    const target = db.prepare(`SELECT * FROM memberships WHERE org_id = ? AND user_id = ? AND status = 'active'`).get(ctx.orgId, params.userId);
    if (!target) throw notFound();
    assertCanModify(db, ctx.role, target.role);
    assertNotLastOwner(db, ctx.orgId, params.userId);

    db.prepare(`UPDATE memberships SET status = 'suspended', perm_version = perm_version + 1 WHERE id = ?`).run(target.id);
    endActiveSessions(db, { orgId: ctx.orgId, userId: params.userId, reason: 'user_suspended' });
    audit(db, { orgId: ctx.orgId, actorId: ctx.userId, action: 'member.suspend', targetType: 'user', targetId: params.userId, result: 'allow', requestId: ctx.requestId });
    send(res, 200, { ok: true });
  });

  router.delete('/v1/orgs/:org/members/:userId/suspend', async (ctx, params, res) => {
    assertCan(db, ctx, 'user:remove');
    const target = db.prepare(`SELECT * FROM memberships WHERE org_id = ? AND user_id = ? AND status = 'suspended'`).get(ctx.orgId, params.userId);
    if (!target) throw notFound();
    db.prepare(`UPDATE memberships SET status = 'active', perm_version = perm_version + 1 WHERE id = ?`).run(target.id);
    audit(db, { orgId: ctx.orgId, actorId: ctx.userId, action: 'member.reinstate', targetType: 'user', targetId: params.userId, result: 'allow', requestId: ctx.requestId });
    send(res, 200, { ok: true });
  });

  // Registered BEFORE /members/:userId so 'me' isn't swallowed as a userId param.
  router.delete('/v1/orgs/:org/members/me', async (ctx, params, res) => {
    const target = db.prepare(`SELECT * FROM memberships WHERE org_id = ? AND user_id = ? AND status = 'active'`).get(ctx.orgId, ctx.userId);
    if (!target) throw notFound();
    assertNotLastOwner(db, ctx.orgId, ctx.userId);
    db.prepare(`UPDATE memberships SET status = 'removed', perm_version = perm_version + 1 WHERE id = ?`).run(target.id);
    endActiveSessions(db, { orgId: ctx.orgId, userId: ctx.userId, reason: 'membership_removed' });
    audit(db, { orgId: ctx.orgId, actorId: ctx.userId, action: 'member.leave', targetType: 'user', targetId: ctx.userId, result: 'allow', requestId: ctx.requestId });
    send(res, 200, { ok: true });
  });

  router.delete('/v1/orgs/:org/members/:userId', async (ctx, params, res) => {
    assertCan(db, ctx, 'user:remove');
    const target = db.prepare(`SELECT * FROM memberships WHERE org_id = ? AND user_id = ? AND status != 'removed'`).get(ctx.orgId, params.userId);
    if (!target) throw notFound();
    assertCanModify(db, ctx.role, target.role);
    assertNotLastOwner(db, ctx.orgId, params.userId);
    db.prepare(`UPDATE memberships SET status = 'removed', perm_version = perm_version + 1 WHERE id = ?`).run(target.id);
    endActiveSessions(db, { orgId: ctx.orgId, userId: params.userId, reason: 'membership_removed' });
    audit(db, { orgId: ctx.orgId, actorId: ctx.userId, action: 'member.remove', targetType: 'user', targetId: params.userId, result: 'allow', requestId: ctx.requestId });
    send(res, 200, { ok: true });
  });

  // =====================================================================
  // DEVICES
  // =====================================================================
  router.get('/v1/orgs/:org/devices', async (ctx, params, res) => {
    assertCan(db, ctx, 'device:list');
    const devices = db.prepare(`SELECT * FROM devices WHERE org_id = ? AND deleted_at IS NULL`).all(ctx.orgId);
    const { byDevice } = resolveDevices(db, { userId: ctx.userId, orgId: ctx.orgId, deviceIds: devices.map(d => d.id) });
    // device:view decides visibility PER ROW — deny removes the row entirely, never
    // shown with redacted fields (PERMISSIONS.md §4).
    const rows = devices
      .filter(d => byDevice[d.id]['device:view']?.effect === 'allow')
      .map(d => ({ id: d.id, name: d.name, kind: d.kind, online: !!d.online, permissions: byDevice[d.id] }));
    send(res, 200, { devices: rows });
  });

  router.get('/v1/orgs/:org/devices/:id', async (ctx, params, res) => {
    const device = getDeviceOr404(ctx.orgId, params.id);
    assertCan(db, ctx, 'device:view', device.id);
    const resolved = resolve(db, { userId: ctx.userId, orgId: ctx.orgId, deviceId: device.id }).permissions;
    send(res, 200, { id: device.id, name: device.name, kind: device.kind, online: !!device.online, permissions: resolved });
  });

  router.post('/v1/orgs/:org/devices', async (ctx, params, res) => {
    assertCan(db, ctx, 'device:provision');
    const { name, kind } = ctx.body;
    if (!name || !kind) throw badRequest('name and kind are required');
    const id = newId('dev');
    db.prepare(`INSERT INTO devices (id, org_id, name, kind) VALUES (?, ?, ?, ?)`).run(id, ctx.orgId, name, kind);
    audit(db, { orgId: ctx.orgId, actorId: ctx.userId, action: 'device.create', targetType: 'device', targetId: id, result: 'allow', requestId: ctx.requestId });
    send(res, 201, { id, name, kind });
  });

  router.patch('/v1/orgs/:org/devices/:id', async (ctx, params, res) => {
    const device = getDeviceOr404(ctx.orgId, params.id);
    assertCan(db, ctx, 'device:update', device.id);
    const { name, online } = ctx.body;
    const updates = []; const values = [];
    if (name !== undefined) { updates.push('name = ?'); values.push(name); }
    if (online !== undefined) { updates.push('online = ?'); values.push(online ? 1 : 0); }
    if (updates.length === 0) throw badRequest('nothing to update');
    values.push(device.id);
    db.prepare(`UPDATE devices SET ${updates.join(', ')} WHERE id = ?`).run(...values);
    audit(db, { orgId: ctx.orgId, actorId: ctx.userId, action: 'device.update', targetType: 'device', targetId: device.id, result: 'allow', requestId: ctx.requestId });
    send(res, 200, { ok: true });
  });

  router.delete('/v1/orgs/:org/devices/:id', async (ctx, params, res) => {
    const device = getDeviceOr404(ctx.orgId, params.id);
    assertCan(db, ctx, 'device:provision', device.id);
    db.prepare(`UPDATE devices SET deleted_at = ? WHERE id = ?`).run(nowIso(), device.id);
    endActiveSessions(db, { orgId: ctx.orgId, deviceId: device.id, reason: 'device_transferred' });
    audit(db, { orgId: ctx.orgId, actorId: ctx.userId, action: 'device.delete', targetType: 'device', targetId: device.id, result: 'allow', requestId: ctx.requestId });
    send(res, 200, { ok: true });
  });

  router.post('/v1/orgs/:org/devices/:id/transfer', async (ctx, params, res) => {
    const device = getDeviceOr404(ctx.orgId, params.id);
    assertCan(db, ctx, 'device:provision', device.id);
    const { toOrgId } = ctx.body;
    if (!toOrgId) throw badRequest('toOrgId is required');
    const targetMembership = db.prepare(`SELECT * FROM memberships WHERE org_id = ? AND user_id = ? AND status = 'active'`).get(toOrgId, ctx.userId);
    if (!targetMembership) throw notFound();
    // device:provision required in BOTH orgs (BRIEF.md §5.1).
    const targetResolved = resolve(db, { userId: ctx.userId, orgId: toOrgId, deviceId: null });
    if (targetResolved.permissions['device:provision']?.effect !== 'allow') {
      throw forbidden('missing permission: device:provision in destination org');
    }
    db.prepare(`UPDATE devices SET org_id = ? WHERE id = ?`).run(toOrgId, device.id);
    endActiveSessions(db, { orgId: ctx.orgId, deviceId: device.id, reason: 'device_transferred' });
    audit(db, { orgId: ctx.orgId, actorId: ctx.userId, action: 'device.transfer', targetType: 'device', targetId: device.id, result: 'allow', requestId: ctx.requestId });
    send(res, 200, { ok: true });
  });

  // =====================================================================
  // GRANTS
  // =====================================================================
  router.post('/v1/orgs/:org/grants', async (ctx, params, res) => {
    assertCan(db, ctx, 'grant:create');
    const { userId, deviceId, effect, permissions, startsAt, expiresAt } = ctx.body;
    if (!userId || !effect || !Array.isArray(permissions) || permissions.length === 0) {
      throw badRequest('userId, effect, and permissions are required');
    }
    if (!['allow', 'deny'].includes(effect)) throw badRequest('effect must be allow or deny');
    if (userId === ctx.userId) throw forbidden('cannot create a grant for yourself', 'self_grant');

    // D9: no laundering — only grant authority you hold, at that scope.
    assertMayGrant(db, ctx, permissions, deviceId ?? null);

    const starts = normalizeTs(startsAt, 'startsAt');
    const expires = normalizeTs(expiresAt, 'expiresAt');
    if (expires && expires <= nowIso()) throw new HttpError(400, 'GRANT_EXPIRED', 'grant is already expired');

    const id = newId('grt');
    db.prepare(
      `INSERT INTO grants (id, org_id, user_id, device_id, effect, starts_at, expires_at, created_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
    ).run(id, ctx.orgId, userId, deviceId ?? null, effect, starts, expires, ctx.userId);
    for (const p of permissions) {
      db.prepare(`INSERT INTO grant_permissions (grant_id, permission) VALUES (?, ?)`).run(id, p);
    }
    bumpPermVersion(db, { orgId: ctx.orgId, userId });
    audit(db, { orgId: ctx.orgId, actorId: ctx.userId, action: 'grant.create', targetType: 'grant', targetId: id, result: 'allow', requestId: ctx.requestId });
    send(res, 201, { id, userId, deviceId: deviceId ?? null, effect, permissions });
  });

  router.get('/v1/orgs/:org/grants', async (ctx, params, res) => {
    assertCan(db, ctx, 'user:read');
    const rows = db.prepare(`SELECT id, user_id, device_id, effect, starts_at, expires_at FROM grants WHERE org_id = ? AND revoked_at IS NULL`).all(ctx.orgId);
    for (const g of rows) {
      g.permissions = db.prepare(`SELECT permission FROM grant_permissions WHERE grant_id = ?`).all(g.id).map(r => r.permission);
    }
    send(res, 200, { grants: rows });
  });

  router.delete('/v1/orgs/:org/grants/:id', async (ctx, params, res) => {
    assertCan(db, ctx, 'grant:revoke');
    const grant = db.prepare(`SELECT * FROM grants WHERE id = ? AND org_id = ? AND revoked_at IS NULL`).get(params.id, ctx.orgId);
    if (!grant) throw notFound();
    db.prepare(`UPDATE grants SET revoked_at = ? WHERE id = ?`).run(nowIso(), grant.id);
    bumpPermVersion(db, { orgId: ctx.orgId, userId: grant.user_id });
    audit(db, { orgId: ctx.orgId, actorId: ctx.userId, action: 'grant.revoke', targetType: 'grant', targetId: grant.id, result: 'allow', requestId: ctx.requestId });
    send(res, 200, { ok: true });
  });

  // =====================================================================
  // SESSIONS
  // =====================================================================
  router.post('/v1/orgs/:org/sessions', async (ctx, params, res) => {
    const { deviceId, mode } = ctx.body;
    if (!deviceId || !mode) throw badRequest('deviceId and mode are required');
    const device = getDeviceOr404(ctx.orgId, deviceId);

    assertCanStartSession(db, ctx, mode, device.id);

    const authorizedBy = snapshotAuthority(db, { userId: ctx.userId, orgId: ctx.orgId, deviceId: device.id });
    const id = newId('ses');
    const expiresAt = sessionExpiry(db, ctx.orgId);

    try {
      db.prepare(
        `INSERT INTO sessions (id, org_id, user_id, device_id, mode, state, authorized_by, expires_at) VALUES (?, ?, ?, ?, ?, 'active', ?, ?)`
      ).run(id, ctx.orgId, ctx.userId, device.id, mode, authorizedBy, expiresAt);
    } catch {
      // one_exclusive_session_per_device caught this race — the DB enforces D10,
      // not a check-then-insert in application code.
      throw deviceBusy();
    }

    audit(db, { orgId: ctx.orgId, actorId: ctx.userId, action: 'session.start', targetType: 'session', targetId: id, result: 'allow', requestId: ctx.requestId });
    send(res, 201, { id, deviceId: device.id, mode, state: 'active', expiresAt });
  });

  router.get('/v1/orgs/:org/sessions', async (ctx, params, res) => {
    assertCan(db, ctx, 'session:view');
    const rows = db.prepare(`SELECT * FROM sessions WHERE org_id = ?`).all(ctx.orgId);
    send(res, 200, { sessions: rows });
  });

  router.get('/v1/sessions/:id', async (ctx, params, res) => {
    const session = db.prepare(`SELECT * FROM sessions WHERE id = ?`).get(params.id);
    if (!session || session.org_id !== ctx.orgId) throw notFound();
    if (session.user_id !== ctx.userId) assertCan(db, ctx, 'session:view');
    send(res, 200, session);
  });

  router.delete('/v1/sessions/:id', async (ctx, params, res) => {
    const session = db.prepare(`SELECT * FROM sessions WHERE id = ?`).get(params.id);
    if (!session || session.org_id !== ctx.orgId) throw notFound();
    const isOwn = session.user_id === ctx.userId;
    if (!isOwn) assertCan(db, ctx, 'session:terminate');
    db.prepare(`UPDATE sessions SET state = 'ended', end_reason = ?, ended_at = ? WHERE id = ?`)
      .run(isOwn ? 'user_stopped' : 'admin_terminated', nowIso(), session.id);
    audit(db, { orgId: ctx.orgId, actorId: ctx.userId, action: 'session.end', targetType: 'session', targetId: session.id, result: 'allow', requestId: ctx.requestId });
    send(res, 200, { ok: true });
  });

  // =====================================================================
  // EFFECTIVE PERMISSIONS & AUDIT
  // =====================================================================
  router.get('/v1/orgs/:org/users/:userId/effective', async (ctx, params, res) => {
    if (params.userId !== ctx.userId) assertCan(db, ctx, 'user:read');
    const membership = db.prepare(`SELECT * FROM memberships WHERE org_id = ? AND user_id = ?`).get(ctx.orgId, params.userId);
    if (!membership) throw notFound();
    const resolved = resolve(db, { userId: params.userId, orgId: ctx.orgId, deviceId: null });
    send(res, 200, { role: resolved.role, permissions: resolved.permissions });
  });

  router.get('/v1/orgs/:org/audit', async (ctx, params, res) => {
    assertCan(db, ctx, 'audit:read');
    const rows = db.prepare(`SELECT * FROM audit_events WHERE org_id = ? ORDER BY at DESC LIMIT 200`).all(ctx.orgId);
    send(res, 200, { events: rows });
  });
}