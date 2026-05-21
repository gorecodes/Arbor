# Phase 1 Progress

## Scope

Phase 1 target:

- local auth foundation
- session foundation
- backend auth switch `token|local`
- minimal auth endpoints
- test coverage for foundation

## Status

### Completed

1. Local auth store module added
   - file: `backend/arbor/local_auth.py`
   - includes:
     - SQLite bootstrap for `local_user` + `auth_events`
     - password hashing + verification
     - local user create/find helpers
     - login success/failure audit hooks

2. Session store module added
   - file: `backend/arbor/session.py`
   - includes:
     - SQLite bootstrap for `sessions`
     - create/get/revoke session
     - idle + hard expiry checks
     - cookie helpers (`set`, `clear`, parse from header)

3. Auth backend switch integrated
   - file: `backend/arbor/auth.py`
   - behavior:
     - `ARBOR_AUTH_BACKEND=token` -> legacy bearer flow
     - `ARBOR_AUTH_BACKEND=local` -> session-cookie flow
   - websocket auth helper updated for backend-aware validation

4. Minimal phase1 auth endpoints added
   - file: `backend/arbor/main.py`
   - new routes:
     - `GET /api/auth/backend`
     - `GET /api/auth/session`
     - `POST /api/auth/login`
     - `POST /api/auth/logout`

5. Tests added/updated
   - updated:
     - `backend/tests/test_phase0_characterization.py`
     - `backend/tests/test_phase35_ws_auth_surface.py`
   - new:
    - `backend/tests/test_phase7_local_auth_foundation.py`

6. Local owner bootstrap CLI added
   - file: `backend/arbor/local_auth_cli.py`
   - command:
     - `arbor-auth status`
     - `arbor-auth create-owner --username <name> [--password ...]`
   - behavior:
     - root check for system DB usage
     - owner creation guard unless `--force`
     - interactive password confirmation when password flag omitted

7. Packaging/wrapper integration updated
   - files:
     - `backend/pyproject.toml`
     - `install.sh`
     - `sync_installed_dev.sh`
   - includes:
     - new script entrypoint `arbor-auth`
     - install symlink `/usr/bin/arbor-auth`
     - dev sync wrapper install for `arbor-auth`

## Validation

Executed:

```bash
PYTHONPATH=/home/paolo/dev/arbor/backend:/home/paolo/dev/arbor/backend/tests \
python3 -m unittest \
  /home/paolo/dev/arbor/backend/tests/test_phase0_characterization.py \
  /home/paolo/dev/arbor/backend/tests/test_phase35_ws_auth_surface.py \
  /home/paolo/dev/arbor/backend/tests/test_phase6_hardening.py \
  /home/paolo/dev/arbor/backend/tests/test_phase7_local_auth_foundation.py
```

Result:

- `Ran 40 tests`
- `OK`

## Notes

- Hash profile adjusted from `scrypt n=2^15` to `n=2^14` due OpenSSL memory
  limit failures in CI/runtime-constrained env.
- Token backend compatibility intentionally preserved during transition.

## Next Natural Steps

1. Frontend phase1 hookup
   - local username/password login UI path behind backend mode check

2. Setup script integration
   - optional: add first-owner bootstrap into `config/setup.sh` flow

3. Authorization layer (phase2)
   - central action policy map
   - deny-by-default checks before daemon calls

## Incremental Progress (Current Session)

Completed:

1. Frontend phase1 login path completed
   - file: `frontend/alpine/index.html`
   - added backend-aware login form:
     - `local` backend -> username/password form
     - `token` backend -> token form
   - app shell/login gated on `$store.auth.ready` to avoid startup flicker

2. Setup integration completed
   - file: `config/setup.sh`
   - when `ARBOR_AUTH_BACKEND=local`:
     - detects auth store status with `arbor-auth status`
     - bootstraps first owner with `arbor-auth create-owner`
     - supports env-driven bootstrap:
       - `ARBOR_BOOTSTRAP_OWNER_USERNAME`
       - `ARBOR_BOOTSTRAP_OWNER_PASSWORD`
     - supports interactive prompt on TTY if env vars are absent
   - file: `config/arbor.env.example`
     - documented `ARBOR_AUTH_BACKEND`

3. Phase2 central authorization gate started and integrated
   - new file: `backend/arbor/authorization.py`
   - deny-by-default behavior:
     - rejects daemon commands not in web policy allowlist
     - role-based command class enforcement (`owner`, `operator`, `viewer`)
   - file: `backend/arbor/daemon_client.py`
     - authorization check now runs before opening daemon socket
   - file: `backend/arbor/auth.py`
     - principal context set during REST auth
     - websocket principal resolver added for local/token backends
   - file: `backend/arbor/main.py`
     - `AuthorizationError` mapped to HTTP 403
     - websocket auth now sets principal context
   - endpoint-level role checks applied (fine-grained):
     - `operator+`: `POST /api/approval-requests`
     - `owner-only`: approve/cancel approval request, job cancel, history delete/purge,
       etc-update resolve, overlay add/remove
   - tests:
     - `backend/tests/test_phase8_authorization_gate.py`
     - `backend/tests/test_phase8_endpoint_roles.py`

4. Frontend role-aware action gating (UI)
   - files:
     - `frontend/alpine/app.js`
     - `frontend/alpine/index.html`
   - added auth role capabilities in store:
     - `role`
     - `can(requiredRole)`
     - `canOperate` (operator+)
     - `canOwner` (owner-only)
   - sensitive actions are now hidden client-side for insufficient role:
     - approval submit/cancel (owner)
     - install/uninstall mutating actions (operator+)
     - etc-update resolve buttons (owner)
     - jobs kill / history purge / history delete (owner)
     - overlay add (owner), overlay sync (operator+)
   - note:
     - backend authorization remains the source of truth; UI gating is defense-in-depth and UX clarity.

5. Packaging/runtime safety fix for local auth DB permissions
   - files:
     - `config/setup.sh`
     - `backend/arbor/local_auth.py`
   - improvements:
     - setup now always creates `/var/lib/arbor` as `arbor:arbor` with mode `750`
     - setup realigns `/var/lib/arbor/auth.db` to `arbor:arbor` mode `640` when present
     - local auth bootstrap code now auto-heals system DB ownership/permissions when run as root on default path
   - goal:
     - avoid `500` on login caused by root-owned auth DB after owner bootstrap.

6. Role visibility UX (next-phase natural step)
   - files:
     - `frontend/alpine/app.js`
     - `frontend/alpine/index.html`
   - improvement:
     - added an explicit role pill in the top status strip (`Role: viewer|operator|owner`)
     - role value is derived from session auth store (`local`) or defaults to owner in legacy token mode
   - goal:
     - make action availability changes obvious to the user without trial/error clicks.

7. Auth mode simplification: local-only
   - files:
     - `backend/arbor/auth.py`
     - `backend/arbor/main.py`
     - `frontend/alpine/app.js`
     - `frontend/alpine/index.html`
     - `config/setup.sh`
     - `config/arbor.env.example`
     - `README.md`
   - changes:
     - removed runtime token-mode branching; backend auth mode is local-only
     - login UI is username/password only (no token input path)
     - websocket auth now validates session cookie only
     - setup explicitly enforces `ARBOR_AUTH_BACKEND=local` on every run

## Open Points

1. Auth DB auto-heal hardening
   - status: completed (phase scope)
   - implemented:
     - reject auto-heal on symlinked DB parent/path before `chown/chmod`
     - structured warning logs for ownership transitions (`from_uid/from_gid` -> target)
     - explicit kill switch for runtime auto-heal: `ARBOR_AUTH_AUTOHEAL_PERMS=0`
   - decision:
     - keep runtime self-heal enabled by default as safety net; allow operators to disable and rely on setup/package hooks only.
