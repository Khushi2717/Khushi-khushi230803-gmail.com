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

<!-- Copy the block above per decision. The two stubs below show the required shape and contain no
     engineering content — replace or delete them. -->

---

### Stub — the shape of a weak "Why"

**What I chose:** the obvious thing.
**Why:** it is what the brief says to do.
**What I rejected:** nothing, the alternative seemed worse.
**What would change my mind:** I do not know.

_Reads as a memory of the document, not a model of the system. Scores nothing._

---

### Stub — the shape of a strong "Why"

**What I chose:** X.
**Why:** I implemented Y first, because Y is the intuitive precedence rule. `node scripts/check-
permissions.js` reported `<the actual reason string it reported>` on the case where the two grants
disagree. That is only reachable if the two are evaluated in a different order than Y assumes.
Moved to X in `<commit>` and the case passed. Logged in `BUILD-LOG.md` under Phase 2.
**What I rejected:** Y, and also "resolve the narrower one last" — both fail the same case for the
same reason.
**What would change my mind:** a case where a narrower grant is expected to survive a broader
refusal. I could not construct one, which is itself evidence for X.

_Shows what you believed, what disproved it, and what you did next._

---

## Where this repo argues with itself

The documents contradict each other, or contradict the schema, in at least one place. Name each
one you found. For each: quote both statements, say which you built against, and say why.

Building against the written rule and arguing in writing is a **full-marks** answer. Silently
working around it, or quietly picking one and saying nothing, scores zero on the section — we
cannot tell the difference between a decision and an oversight.

## Deliberately not built

What you chose not to build, and the reason. A scope cut with a stated reason is a senior
judgement. An unmentioned gap is a gap.