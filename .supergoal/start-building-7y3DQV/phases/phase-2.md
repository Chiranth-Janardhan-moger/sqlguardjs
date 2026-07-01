SUPERGOAL_PHASE_START
Phase: 2 of 5 — Header Scanning & Text Body Parsing (NPM)
Task: Ensure User-Agent, Referer, X-Forwarded-For are scanned, and Content-Type text/plain payloads are properly analyzed.
Mandatory commands: cd npm && npm test
Acceptance criteria: 5
Evidence required: Test output demonstrating successful blocking of SQLi/XSS in the specified headers and raw text bodies.
Depends on phases: 1

## Why
Attackers often bypass input validation by injecting payloads into headers or using non-JSON body types.

## Work
- Modified `expressMiddleware` in `npm/src/detector.js`.
- Tests targeting headers and raw text bodies in `npm/__tests__/detector.test.js`.

## Acceptance criteria (all must pass — verify each in transcript)
- Code must pass linting.
- Tests must run without warnings.
1. `User-Agent`, `Referer`, `X-Forwarded-For`, and `Cookie` headers are deep-scanned.
2. The scanner must safely handle undefined headers or headers that are arrays (X-Forwarded-For).
3. If `req.body` is a string (e.g., from `express.text()`), it must be scanned directly instead of skipping it.
4. If `req.body` is a Buffer (e.g., from `express.raw()`), it must be converted to a string and scanned.
5. All existing and new tests in `npm test` pass.

## Mandatory commands

- cd npm && npm test

## Evidence required in transcript
Print `npm test` output demonstrating that a malicious payload in a header and a raw text body both get intercepted and blocked.

[Agent will print SUPERGOAL_PHASE_VERIFY and SUPERGOAL_PHASE_DONE here during execution]
