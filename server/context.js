import { verifyAccessToken, assertFresh } from './auth.js';
import { unauthenticated, notFound } from './http.js';

// authenticate(db, secret) returns (req, params) => caller.
// This is the ONE place tenant isolation is enforced (see the note below) — every
// route that goes through this gets isolation for free, rather than trusting each
// route handler to remember to check it.
export function authenticate(db, secret) {
  const getMembership = db.prepare(
    `SELECT * FROM memberships WHERE org_id = ? AND user_id = ?`
  );
  const getOrg = db.prepare(`SELECT * FROM organizations WHERE id = ?`);

  return function buildContext(req, params) {
    const header = req.headers.authorization;
    if (!header || !header.startsWith('Bearer ')) {
      throw unauthenticated('missing bearer token');
    }
    const token = header.slice('Bearer '.length).trim();

    const claims = verifyAccessToken(token, secret);

    const membership = getMembership.get(claims.org, claims.sub);

    // assertFresh (in auth.js) already handles two cases for us:
    //   - no membership row at all -> unauthenticated
    //   - membership.perm_version !== claims.pv -> TOKEN_STALE (401)
    assertFresh(claims, membership);

    // Identity first (PERMISSIONS.md §3.1): a suspended or removed member has no
    // permissions anywhere, full stop -- doesn't matter if their token is still
    // technically unexpired.
    if (membership.status !== 'active') {
      throw unauthenticated('membership is not active');
    }

    const org = getOrg.get(claims.org);
    if (!org || org.deleted_at) {
      throw unauthenticated('organization no longer exists');
    }

    // STRUCTURAL ISOLATION: the token's org claim is the only org this caller may
    // ever address. If the URL names a different org, that org doesn't exist as far
    // as this caller is concerned -- 404, never 403 (PERMISSIONS.md §6). Checking it
    // here, once, means no individual route can forget to check it.
    if (params && params.org !== undefined && params.org !== claims.org) {
      throw notFound();
    }

    return {
      userId: claims.sub,
      orgId: claims.org,
      role: membership.role,
      membership,
      claims,
    };
  };
}