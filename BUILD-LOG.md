# BUILD-LOG

Append to this as you go. Commit it with the code it describes — the timestamps are part of the
evidence, and a log that arrives in one commit at the end reads as what it is.

Five lines is a real entry. Short and dated is better than long and reconstructed.

The categories we look for are listed in `DISCOVERY-BRIEF.md`. The example below shows the
*shape* of a good entry; it is a recreation of something already printed in `README.md`, so it
gives nothing away.

---

<!-- EXAMPLE — delete this block, keep the shape.

## 2026-03-04 · Phase 0 — orientation

Expected the unknown-permission test to fail on my validation code.
Observed: it passed, with foreign_keys ON, and *also* passed with the pragma removed — so the
check was never running, and the "pass" was the schema loading fine while enforcing nothing.
Changed: moved `foreign_keys = ON` to connection open and re-ran; now it raises
`FOREIGN KEY constraint failed` as the README said it would.
Note: this is the failure mode where a passing test is worse than a failing one.

-->

## Phase 0 — orientation

_Installed, reset the database, read the documents, ran the suites against the untouched skeleton.
What did the starting line actually look like, and which failure surprised you?_

## Phase 1 — token verification

_What did you expect each failure mode to look like before you ran it? Which one behaved
differently from your expectation, and what did that tell you?_
### 2026-09-26

Expected verifyAccessToken to need a few debugging passes, especially around
the algorithm-confusion cases (alg: none, HS512/RS256 substitution). Wrote all
7 checks from AUTH-DATA-MODEL.md §10 in order — malformed shape, invalid JSON,
untrusted alg/typ, constant-time signature check, exp <= now (not <), iss/aud,
jti. Ran check-jwt.js: 43/43 passed on the first try.

One thing I had to get right that isn't spelled out in the TODO comment:
node's timingSafeEqual throws (doesn't return false) if the two buffers it's
comparing have different lengths. So I check
providedSig.length !== expectedSig.length before calling it — otherwise a
token with a truncated or malformed signature would crash the request with
an uncaught exception instead of cleanly returning 401 UNAUTHENTICATED.

## Phase 2 — caller context and the resolution engine

_This is where most people's first model is wrong. Write down the model you started with, the
observation that broke it, and the model you moved to. Be specific about the observation._
### 2026-09-26 (cont.)

Expected resolve() to pass most tests once the deny/allow/wildcard logic was
right. First run: 31/35 passed, 4 failed, all around reason codes — I was
returning "implicit" for every kind of deny, but the spec distinguishes them:
no membership at all -> "not_a_member", suspended membership -> "suspended",
and the session-start compound check needs its own fixed codes
("missing_permission" for session:start, "missing_device_permission" for the
mode permission) rather than whatever resolve() says internally. Fixed by
branching on membership existence/status before falling into the grant/role
logic, and hardcoding the two session-check reason codes rather than reusing
resolve()'s reason field. Second run: 35/35.

Also caught earlier (before this): resolve() originally returned the flat
permission map directly; check-permissions.js expects it wrapped as
{ role, permissions: {...} }, matching the API shape in PERMISSIONS.md §8.
Fixed by wrapping the return and updating every caller (can, assertCan,
assertMayGrant, assertCanStartSession) to read resolved.permissions[key].

## Phase 3 — orgs, members, invites

_Anything you had to work out that no document states. Invite lifecycle states are a common
source of this._

## Phase 4 — devices and grants

_What happens at the boundary where two grants disagree, or where a grant's scope and the
question's scope differ? Say what you predicted and what you got._

## Phase 5 — sessions

_Two permissions, one device. What did you have to resolve, and in what order, to keep the two
failure reasons distinguishable?_

## Phase 6 — audit

_What did you decide counts as an auditable event, and what pushed you to that line?_

## Phase 7 — the console

_Where did the server's answer and your instinct disagree about what should be on screen?_

## Phase 8 — hardening

_What did you measure, what did you fix, and what did you deliberately leave alone? Anything you
chose not to build belongs here with its reason._

## Open threads

_Things you know are wrong, unfinished, or that you would do differently with another day. Listing
these honestly is worth more than pretending they do not exist — we will find them anyway._
