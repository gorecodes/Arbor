# Arbor Root Call Hardening — Implementation Plan v2

## Goal

Harden every root-capable or root-triggering path in Arbor so that:
- the web process remains unprivileged and cannot directly cause privileged side effects without explicit approval,
- the daemon remains the only component that performs Portage operations as root,
- destructive or trust-heavy operations require a separate shell-side approval step,
- the current Arbor user experience remains usable and mostly compatible, with a staged rollout rather than a flag day.

This plan is specifically about hardening root calls and approval flows, not about redesigning Arbor into a different product.

## Non-negotiable invariants

1. The web process must stay unprivileged.
2. The daemon must remain the only process that executes Portage operations as root.
3. No privileged action may run solely because the browser UI clicked a button.
4. Approval for dangerous actions must come from a shell-side or local trusted channel, not from the browser alone.
5. Existing routes, job IDs, and websocket message shapes should remain stable unless a compatibility shim is provided.
6. Any tightening must fail explicitly, not silently.
7. Prefer additive changes, staged enforcement, and explicit migration notes.
8. Do not weaken the current non-root read-only flows.

## Threat model

Assume:
- the web process may be compromised,
- a browser session may be hijacked,
- a user may click through a UI confirmation accidentally,
- a malicious local user may try to trigger privileged actions through existing APIs,
- Arbor may be used in a local-first setup, but the machine itself should still be protected from unnecessary escalation paths.

Design the solution so that a compromised non-privileged web process cannot directly turn into arbitrary root execution through Arbor.

---

# Phase 0 — Baseline and tests

## Scope
- Freeze current behavior for root-capable paths before changing them.
- Add or extend tests for:
  - pretend install flow,
  - pretend uninstall flow,
  - autounmask flow,
  - overlay add/remove,
  - etc-update resolve,
  - job recovery and job attach behavior,
  - auth and websocket message flow.
- Capture current route contracts and payload shapes.
- Add fixtures for “read-only”, “pretend”, “pending approval”, and “approved execution” states.
- Document current constraints around `frontend/index.html` being ignored and the Alpine app living in `frontend/alpine/`.

## Output
- No runtime behavior changes in this phase.
- Only tests, fixtures, and documentation.
- Keep all tests runnable without requiring a real Portage mutation.

## Exit criteria
- The current behavior of root-triggering flows is captured in tests.
- Future changes can be validated against a stable baseline.

---

# Phase 1 — Classify all privileged actions

## Scope
Create a server-side action taxonomy for every route and daemon command that can lead to privileged side effects.

## Action classes
Use at least these classes:
- `readonly`
- `pretend`
- `approval_required`
- `privileged_mutation`
- `destructive`
- `trust_heavy`

## Required mapping
Map every relevant action into one of these classes:
- package search, package metadata, status, history list: `readonly`
- pretend install / uninstall / autounmask scan: `pretend`
- install, uninstall, autounmask write, overlay add, overlay remove, depclean, etc-update apply, preserved-rebuild, world update: `approval_required` or stronger
- operations that modify `/etc`, add overlays, or may change many packages: `destructive` or `trust_heavy`

## Implementation details
- Keep the classification server-side.
- Do not trust the frontend to decide what is safe.
- Make the daemon reject any privileged mutation that does not carry an approval context.
- Keep existing read-only endpoints untouched as much as possible.

## Exit criteria
- Every command path has a documented privilege class.
- It is clear which actions are only pretend and which require approval.

---

# Phase 2 — Introduce shell-side approval

## Scope
Add a trusted approval channel from shell/CLI for privileged actions.

## Design target
The browser may initiate a request, but the final approval for root-capable execution must come from a shell-side helper or another local trusted mechanism.

## Recommended model
Implement a small CLI helper such as:
- `arbor-approve`
- or `arborctl approve`
- or a clearly named local approval command

The helper should:
1. list pending privileged requests,
2. show the exact plan, target, and danger class,
3. require explicit user confirmation on the shell,
4. mint a short-lived approval token or signed approval record,
5. bind approval to a specific request ID, target, and plan hash.

## Approval token requirements
- single-use,
- short TTL,
- bound to the exact request hash,
- bound to the privilege class,
- useless for any other target,
- rejected if the plan changes between pretend and execute.

## User experience
- The browser should be able to create a pending request.
- The shell helper should approve that request locally.
- The browser can then continue only if the approval token is present.

## Security requirements
- The approval token must not be generated by the browser.
- The approval token must not be reusable.
- The approval token must be validated only by the backend/daemon.
- If approval is missing or stale, execution must fail explicitly.

## Exit criteria
- A user can approve a privileged request from shell.
- A compromised web process cannot forge that approval.

---

# Phase 3 — Separate request creation from execution

## Scope
Refactor privileged flows so the browser can only create requests and preview plans, not directly execute root actions.

## Required behavior
For each mutating flow:
- browser creates a pending request,
- daemon calculates or receives the pretend result,
- shell approval is obtained,
- daemon executes the approved plan only after approval.

## Important principle
The browser may still initiate the workflow, but it is not the authority that turns a request into execution.

## Candidate flows
- install / uninstall,
- autounmask write,
- overlay add,
- overlay remove,
- etc-update apply,
- depclean,
- world update,
- preserved-rebuild.

## Compatibility
- Keep route names if possible.
- If new fields are required, add them in an additive way.
- Preserve existing websocket message shape unless a shim is necessary.
- Prefer server-side compatibility over frontend-only gating.

## Exit criteria
- No mutating root action can run without a server-validated approval token.
- Pending requests are distinct from executed jobs.

---

# Phase 4 — Dangerous operations policy

## Scope
Define a stricter policy for operations that are especially risky even with approval.

## Must cover
- overlay add,
- overlay remove,
- purge remove,
- autounmask write,
- etc-update write/replace,
- depclean,
- world update.

## Policy rules
- Add a second confirmation tier for truly destructive actions.
- Require a more explicit approval phrase for dangerous operations.
- Example:
  - `ADD <name> <uri>`
  - `REMOVE <name>`
  - `PURGE <name>`
  - `APPLY ETC-UPDATE <cfg-file>`
- If purge or config overwrite is involved, require a stronger phrase than a normal install.
- Keep destructive operations behind a stricter approval class than plain installs.

## Example policy
- install: approval required
- overlay add: approval required + explicit phrase
- overlay remove: approval required + explicit phrase
- purge overlay: approval required + stronger phrase
- etc-update replace: approval required + explicit phrase
- depclean: approval required + explicit phrase + preview of affected packages
- world update: approval required + preview + explicit acknowledgment of breadth

## Exit criteria
- Dangerous actions are distinguishable from ordinary installs.
- More dangerous operations require more explicit approval.

---

# Phase 5 — Daemon-side enforcement

## Scope
Implement backend/daemon checks so the approval model cannot be bypassed by a modified frontend or raw client.

## Requirements
- Every privileged action must verify:
  - request ID,
  - plan hash,
  - approval token,
  - TTL,
  - target/command scope,
  - single-use state.
- Approval must be checked in the daemon, not only in the web layer.
- If approval validation fails, return a clear error and do not start root work.
- Do not silently downgrade to a pretend or partial execution when approval is missing.

## State management
- Store pending approvals in a durable or at least process-safe structure.
- Mark approvals as consumed once used.
- Expire stale approvals.
- Keep failed validation visible in logs and UI.

## Compatibility
- Preserve current job IDs where possible.
- If a request is rejected for missing approval, make the error explicit and actionable.

## Exit criteria
- Raw API calls cannot bypass approval.
- A modified frontend cannot trick the daemon into executing root actions.

---

# Phase 6 — Browser and UI hardening

## Scope
Update the UI so it reflects the new approval model without becoming the source of truth.

## Required UI behavior
- Distinguish clearly between:
  - preview,
  - pending approval,
  - approved for execution,
  - running job,
  - completed job,
  - rejected / expired approval.
- Show the exact target and danger class.
- Show whether the action still needs shell approval.
- Avoid using a simple modal confirmation as the only safety barrier.

## UX constraints
- Preserve current job attach and live output behavior where possible.
- Preserve existing websocket-based output streaming.
- Do not change the overall install flow layout more than necessary.
- Keep button labels understandable and explicit.

## Recommended UI changes
- Add “Pending approval” badges.
- Add a “Copy approval command” action for shell approval.
- Add a “Refresh approval status” action.
- If a request expires, show that the plan must be recreated.
- Make it visually obvious when an action is blocked by missing approval.

## Exit criteria
- The UI makes the approval boundary obvious.
- The UI does not pretend a browser click alone is sufficient for root execution.

---

# Phase 7 — Read-only and pretend flows stay usable

## Scope
Ensure the new model does not break non-mutating and low-risk flows.

## Must remain functional
- package search,
- package details,
- USE flag inspection,
- dependency graph,
- pretend install,
- pretend uninstall,
- pretend autounmask,
- jobs list,
- history list,
- live output for already-approved jobs.

## Constraints
- Keep the read-only experience fast.
- Pretend flows should still work without requiring root execution.
- Approval should be required only for actual mutation, not for read-only inspection.

## Exit criteria
- Arbor remains useful as a browser-based control plane for inspection and planning.
- Only the execution boundary becomes stricter.

---

# Phase 8 — Operational hardening around approvals

## Scope
Add supporting hardening so the approval model is safe in practice.

## Items
- Add audit logs for:
  - request creation,
  - shell approval,
  - approval expiry,
  - approval consumption,
  - rejected execution attempts.
- Add replay protection.
- Add request hashing and plan versioning.
- Add clear error messages when approval state is missing or stale.
- Consider separating “operator” and “admin” approvals if needed.
- Ensure logs do not leak secrets or tokens.

## Exit criteria
- Approval lifecycle is auditable.
- Reuse and replay are blocked.
- Operators can understand why a privileged action was rejected.

---

# Suggested implementation order

1. Phase 0
2. Phase 1
3. Phase 2
4. Phase 3
5. Phase 5
6. Phase 6
7. Phase 4
8. Phase 7
9. Phase 8

## Rationale
- First lock behavior with tests.
- Then classify privileged paths.
- Then introduce shell approval.
- Then separate request creation from execution.
- Then enforce on the daemon.
- Then update UI.
- Then add stricter dangerous-operation policy where needed.
- Finally preserve usability and harden the operational details.

---

# Rollback strategy

- Keep each phase in separate commits or PRs.
- Never remove the old execution path until the approval-backed path is proven.
- If a request type changes schema, accept both old and new forms temporarily.
- Preserve existing websocket message shapes where possible.
- Prefer explicit rejection over fallback behavior.
- If a phase proves too invasive, keep the server-side approval gate and postpone the UX polish.

---

# Definition of done

The hardening work is done when:
- no root-capable operation can execute solely because the browser asked for it,
- every privileged action requires server-validated shell approval,
- the browser remains useful for planning and inspection,
- existing flows stay stable or have compatibility shims,
- destructive operations have stronger confirmation than ordinary installs,
- Arbor still feels like Arbor, but the root boundary is explicit and enforced.

