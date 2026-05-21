# Arbor online auth hardening plan

## Scope and assumptions

- Arbor is exposed to the public Internet.
- Security is evaluated at the **application/domain boundary**.
- Cross-user visibility of jobs, logs, and approvals is **accepted by design** and is **not** treated as a security issue for this plan.
- The goal is to harden **authentication, session handling, authorization defaults, and approval integrity** without changing the current product model more than necessary.

## Hardening priorities

### P0 — must fix before Internet exposure

1. **Add login throttling and lockout controls**
   - Protect `POST /api/auth/login` against brute force and password spraying.
   - Track failures by:
     - source IP
     - username
     - combined `(username, IP)` tuple
   - Apply progressive backoff after repeated failures.
   - Add a short-lived hard block after threshold breaches.
   - Return the same outward-facing error for invalid user, invalid password, disabled user, and throttled user when possible.
   - Files:
     - `backend/arbor/main.py`
     - `backend/arbor/local_auth.py`
     - possibly new helper module such as `backend/arbor/login_throttle.py`

2. **Remove fail-open owner fallback**
   - `current_principal()` must not default to `owner` when no principal is present.
   - Missing principal should raise authorization failure or map to an explicit unauthenticated principal with no privileges.
   - Audit all daemon calls and websocket entry points to ensure they set principal explicitly before policy checks.
   - Files:
     - `backend/arbor/authorization.py`
     - `backend/arbor/auth.py`
     - `backend/arbor/main.py`
     - tests covering all HTTP and WS entry points

3. **Bind approval execution to authenticated web actor**
   - Today approval consumption is effectively driven by `approval_request_id` + request hash; harden it so approval use is tied to the web principal/session that requested it.
   - Recommended model:
     - store requester identity on approval creation (`user_id`, `username`, role snapshot, session id if available)
     - require the same authenticated principal to consume the approved action
     - reject consumption by a different principal even if the request id is known
   - If a separate approval token is kept, it must be **generated, stored, and validated**, not just passed through the API.
   - Files:
     - `backend/arbor/main.py`
     - `backend/arbor/authorization.py`
     - `backend/daemon/main.py`

4. **Equalize login timing**
   - Prevent easy username enumeration via timing differences.
   - For unknown users, run a dummy password verification path using a fixed scrypt hash.
   - Keep response body and status identical across all failed auth cases.
   - Files:
     - `backend/arbor/main.py`
     - `backend/arbor/local_auth.py`

### P1 — strongly recommended

5. **Enforce password policy in core, not only in CLI**
   - Move password requirements into `create_local_user()` and any future password-change path.
   - Minimum baseline:
     - min length >= 12 for Internet exposure
     - reject trivially weak passwords if a strength checker is already acceptable in project scope
   - Ensure tests cover both CLI and direct function calls.
   - Files:
     - `backend/arbor/local_auth.py`
     - `backend/arbor/local_auth_cli.py`

6. **Add session rotation on login and privileged state changes**
   - Issue a fresh session id at login.
   - Revoke prior sessions for the same account if policy requires single-session or low-session-count behavior.
   - Rotate session after role change, disable, or password change.
   - Add explicit password/session invalidation semantics tied to `password_changed_at`.
   - Files:
     - `backend/arbor/session.py`
     - `backend/arbor/local_auth.py`
     - role-management code paths

7. **Add session garbage collection**
   - Expired and revoked sessions should be cleaned from the DB periodically or opportunistically.
   - Keep retention short for revoked sessions unless audit requirements demand otherwise.
   - Files:
     - `backend/arbor/session.py`

8. **Harden websocket auth failure behavior**
   - Keep first-frame auth design.
   - Ensure every websocket endpoint fails closed if principal is absent.
   - Add coverage for invalid cookie, expired session, disabled user, and origin mismatch.
   - Files:
     - `backend/arbor/main.py`
     - websocket auth tests

### P2 — defense in depth

9. **Improve auth event quality**
   - Replace manual JSON construction in `record_login_failure()` with `json.dumps()`.
   - Record structured metadata consistently:
     - source IP
     - user agent
     - username attempted
     - throttle/lockout reason
   - Files:
     - `backend/arbor/local_auth.py`
     - `backend/arbor/main.py`

10. **Define operational safeguards via configuration**
   - Add environment knobs for:
     - login failure window
     - per-IP threshold
     - per-user threshold
     - lock duration
     - max concurrent sessions per user
   - Keep secure defaults for online deployments.
   - Files:
     - `backend/arbor/config_env.py`
     - auth/session modules
     - documentation

11. **Audit approval modes**
   - `ARBOR_AUTH_MODE=none` should remain visibly dangerous.
   - For Internet exposure, recommend:
     - disable `none` in production documentation
     - prefer TOTP or CLI approval only
   - Consider startup refusal or loud warning when running public-facing config with approval mode `none`.
   - Files:
     - `backend/arbor/server.py`
     - `backend/arbor/approval_mode.py`
     - docs

## Proposed implementation order

### Phase 1 — block obvious attacks

- implement login throttling
- remove owner fallback
- equalize login timing
- add tests for brute-force controls and missing-principal denial

### Phase 2 — fix approval integrity

- attach requester identity to approval request records
- validate same principal on approval consumption
- either remove fake `approval_token` plumbing or implement real token validation
- add regression tests for cross-principal approval reuse

### Phase 3 — strengthen account/session lifecycle

- enforce password policy in core
- rotate/invalidate sessions on sensitive account changes
- add session cleanup
- extend auth event metadata

### Phase 4 — documentation and deployment guardrails

- document secure Internet-facing defaults
- document forbidden production modes
- update operator docs for lockout recovery and TOTP/approval setup

## Data model changes

### Approval records

Extend `approval_requests` with fields equivalent to:

- `requested_by_user_id`
- `requested_by_username`
- `requested_by_role`
- `requested_by_session_id`

Optional if real approval token is implemented:

- `consumption_token_hash`
- `consumption_token_expires_at`

### Session/auth telemetry

Consider adding:

- throttling state table keyed by IP / username / tuple
- or reuse `auth_events` plus derived queries if performance is acceptable

For Internet-facing auth, a dedicated throttle table is preferable to scanning event history on every login.

## Test plan

Add or extend tests for:

1. invalid username and invalid password have materially similar code path behavior
2. repeated failures trigger backoff / lock
3. lockout expires correctly
4. missing principal can never authorize owner-only actions
5. approval created by user A cannot be consumed by user B
6. password change invalidates existing sessions
7. disabled user sessions stop working immediately
8. websocket auth denies expired/disabled sessions consistently

## Recommended acceptance criteria

- sustained brute-force attempts are throttled automatically
- no code path can reach owner privileges without an explicit authenticated principal
- approval reuse across different authenticated principals is rejected
- password policy is enforced at the API/core layer, not just CLI UX
- session invalidation semantics are explicit and covered by tests
- docs clearly distinguish safe Internet-facing config from dev-only config

## Non-goals for this hardening pass

- hiding cross-user operational activity inside the app
- redesigning the global job/approval visibility model
- replacing SQLite with another datastore
- changing the frontend architecture
