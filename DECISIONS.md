# DECISIONS

One section per decision that a reviewer might reasonably have made differently. Every section has
the same four parts, and the third and fourth are the ones we weigh most.

Rules, from `DISCOVERY-BRIEF.md`:

- cite something real in `Why` — a commit, a test, an error string, a file and line
- do not restate what a document says; describe what you did when the documents ran out
- six to twelve decisions is the expected range

---

### Default active org at login is the alphabetically-first org by name

**What I chose:** when a user has active memberships in more than one org and logs in without specifying which one, the org that becomes active is the alphabetically first by `organizations.name`.
**Why:** `check-api.js` requires a deterministic outcome ("dana is owner in Acme") for a user who is owner in one org and viewer in another, but neither `BRIEF.md` nor `PERMISSIONS.md` specifies how to pick the default org. Without an explicit `ORDER BY`, SQLite's row order is not guaranteed, and the test failed intermittently with `role: undefined` until I added ordering.
**What I rejected:** ordering by `memberships.created_at` first — it looked more "natural" (first org joined), but seed-data timestamps can tie or be ambiguous, and the test only cares that the result is deterministic and specifically resolves to Acme for this fixture. Alphabetical-by-name is simpler to state and verify than an insertion-order assumption I can't fully control from the seed script.
**What would change my mind:** if the API were extended to let the client explicitly request a `orgId` at login (the test's `login()` helper already has an unused hook for this) and that became the primary path — the default-selection rule would then only matter as a fallback.

---

### Unknown permissions are validated before any grant row is written

**What I chose:** `POST /orgs/:org/grants` checks every permission string against `permission_patterns` up front and throws a `400` with `reason: "unknown_permission"` before inserting anything, rather than letting the database's foreign key reject it.
**Why:** the schema's own comment on `grant_permissions` says an unknown permission should be "a DB error, not a silent deny" (D19), but `check-api.js` expects a specific, controlled `400`/`unknown_permission` response — not an uncaught SQLite constraint exception, which would otherwise crash the request with a raw 500.
**What I rejected:** relying solely on the FK constraint and catching the resulting SQLite error generically in the grants route. This works but loses the specific `reason` code the API contract requires, and risks leaving a partially-inserted `grants` row if the failure happens partway through the `grant_permissions` insert loop.
**What would change my mind:** if grants could ever be created in bulk across a transaction boundary where "reject the whole batch atomically" mattered more than "tell the client which permission was invalid" — then the DB-level rejection alone might be preferable.

---

### Role modification authority uses >=, not >, on rank

**What I chose:** `assertCanModify` allows a caller to modify a target whose rank is less than OR EQUAL to the caller's own rank (`callerRank >= targetRank`), not strictly less.
**Why:** `node scripts/check-api.js` failed "demoting a NON-last owner is allowed" (got 403, wanted 200) under a strict `>` comparison. Acme's seed data has two owners, and with owner being the highest rank (50), no `>` comparison can ever let one owner modify another, since nothing outranks owner. Fixed in commit `d5e6e5e`.
**What I rejected:** a strict `>` comparison, which is what I originally wrote based on an assumption about rank direction I never checked against `db/reference.sql`. The same file also caught an earlier, more basic error: I had assumed lower rank numbers meant higher authority, which `check-api.js`'s "owner demotes Sam to viewer" failure (commit `806f790`) disproved first — the real values are owner=50 down to viewer=10.
**What would change my mind:** if a future spec explicitly said co-owners can never modify each other, since self-modification is already blocked by a separate, earlier check (`selfRoleChange`) that can't double as "self vs. peer" logic — a different mechanism would be needed entirely.

---

### Invite state is split into three distinct failure codes, not one

**What I chose:** a raw invite token that hashes to no row at all returns `404`; a token found but already accepted returns `409 CONFLICT`; a token found but revoked or expired returns `410 GONE`.
**Why:** my first version collapsed all three into a single `410 GONE`. `check-api.js`'s "unknown token -> 404" and "reuse -> 409" tests both failed against that single-code version — a nonexistent token and a spent one are different facts a client needs to act on differently (retry vs. tell the user the invite is used).
**What I rejected:** keeping everything as `410 GONE` for simplicity, on the reasoning that "the invite isn't usable" is the only fact that matters. The tests show the API contract disagrees: which of the three states it's in is itself information worth exposing.
**What would change my mind:** if the invite flow were reworked so revoked and expired also needed to be told apart from each other — right now both collapse to `410`, and nothing in `BRIEF.md`, `PERMISSIONS.md`, or the tests asks for a fourth code, so I stopped at three.

---

### Audit pagination rejects out-of-range values instead of clamping them

**What I chose:** `GET /orgs/:org/audit` returns `400` for `limit=0`, `limit=-1`, `limit=99999`, and `offset=-1`, rather than silently clamping them to the nearest valid value.
**Why:** `check-api.js`'s pagination boundary tests explicitly expect `400` for all four of those, and `200` for `offset=99999` (a large but valid offset that just returns an empty page) and `limit=1`. My first pass had no validation at all — every query param was accepted and only the SQL `LIMIT`/`OFFSET` silently did whatever SQLite does with them, which isn't a defined 400 anywhere.
**What I rejected:** clamping (e.g. `limit=99999` silently becomes `limit=200`) — it's friendlier in some APIs, but it hides a caller's mistake instead of surfacing it, and the tests specifically want it surfaced as an error.
**What would change my mind:** if a real client needed forgiving behavior for user-typed URLs (e.g. a browser address bar), clamping might be worth the tradeoff — but this is a JSON API, not a page a person edits by hand.

---

### A session's authority is a frozen snapshot, not a live re-resolution

**What I chose:** `snapshotAuthority` (in `lifecycle.js`) resolves the caller's permissions once, at the moment a session starts, and stores that result as JSON in `sessions.authorized_by`. The session's authority never changes again for the life of that session, even if the underlying role or grants change.
**Why:** `PERMISSIONS.md` §7.1 states this explicitly as "grandfathering," and `check-api.js`'s "the live session SURVIVES" / "end_reason is still null" test confirms it: after `dana` demotes `sam` mid-session, `sam`'s already-running control session on `dev_lab_win_01` stays active and unaffected, while a *new* session attempt for `sam` is blocked immediately (401 `TOKEN_STALE`, since his `perm_version` changed).
**What I rejected:** re-resolving permissions live on every session action (e.g. checking `device:control` again on each input event) — this would make a permission change take effect mid-session, which is exactly what §7.1 says NOT to do, and would also require a permissions check on every single session interaction rather than once at session start.
**What would change my mind:** an explicit requirement to force-terminate sessions immediately on any permission change, rather than letting them run until they naturally end or expire (which the `expires_at` / `max_session_minutes` bound already guarantees happens within the hour).

---

## Where this repo argues with itself

`lifecycle.js`'s own comment on `assertCanModify` originally described the rule as "modify a strictly-lower role -> allowed," implying a strict inequality. But `PERMISSIONS.md` D8 and `check-api.js`'s "demoting a NON-last owner is allowed" test require peers (two owners) to be able to modify each other, which only works with `>=`, not `>`. I built against the test's actual behavior (`>=`) rather than the stricter wording in my own original comment, since the test is the authoritative contract and self-modification is already blocked by a separate, more specific rule (`selfRoleChange`).

## Deliberately not built

- Real-time device online/offline status: `online` is static seed data with no live socket or polling; a device's status only changes if `PATCH`'d explicitly.
- A working file-transfer mechanism behind the "Files" button: the button exists and is gated by `device:file_transfer` per `UI-INVENTORY.md`'s contract, but clicking it shows a placeholder rather than actually moving files, since no protocol for that was specified in the brief.
- A live permission-catalogue endpoint: the grant-creation form's permission checkboxes are a hardcoded list of the 19 documented permissions rather than fetched from the `permissions` table, so a personalisation overlay's extra permission (e.g. `device:reboot`) can't be granted through the UI, even though `resolve()` itself handles it correctly if granted directly via the API.