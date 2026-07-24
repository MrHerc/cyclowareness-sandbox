# Summary

<!-- What does this change do, and why? Link any related issue. -->

## Changes

<!-- Bullet the notable changes. Keep it to what a reviewer needs. -->

-

## Testing

<!-- How was this verified? Commands run, cases covered, screenshots for UI. -->

- [ ] `pytest` passes in `backend/` (or new tests added and passing)
- [ ] `npm run build` succeeds in `frontend/`
- [ ] Manually exercised the affected path

## Security checklist

- [ ] **No code path executes a sample in the web service.** Detonation stays off-host in the worker, inside isolation or emulation.
- [ ] Untrusted bytes are only ever written to the quarantine path (never executed, never run through a shell).
- [ ] No new dependency parses untrusted input by running it; new parsers are pure-static.
- [ ] Every report still states plainly whether the sample was actually detonated.
- [ ] No secrets, sample bytes, or databases are committed; new config has safe demo defaults and refuses unsafe production values.
- [ ] User- or sample-controlled input is not passed unsanitised into subprocess, filesystem, SQL, or outbound requests (SSRF guard intact for URL fetches).

## Notes for the reviewer

<!-- Anything out of scope, follow-ups, or decisions you want a second opinion on. -->
