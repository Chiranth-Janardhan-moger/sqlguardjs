SUPERGOAL_PHASE_START
Phase: 1 of 5 — Rate Limiting & Sliding Window Memory (NPM)
Task: Implement an IP-based sliding window rate-limiter in the Express middleware to track and escalate repeated malicious probes.
Mandatory commands: cd npm && npm test
Acceptance criteria: 5
Evidence required: Test results showing that multiple ambiguous requests from the same IP cause the score to escalate and trigger a 403.
Depends on phases: none

## Why
Attackers send hundreds of variations to bypass a WAF. Tracking IP reputation temporarily allows the middleware to block brute-force bypass attempts.

## Work
- A new file `npm/src/rateLimiter.js` (or integrated logic in `detector.js`).
- Tests verifying the sliding window limits in `npm/__tests__/rateLimiter.test.js` or `detector.test.js`.

## Acceptance criteria (all must pass — verify each in transcript)
- Code must pass linting.
- Tests must run without warnings.
1. The middleware must log IPs that submit payloads scoring between 0.2 - 0.7.
2. If the same IP submits 3+ ambiguous payloads within a time window (e.g., 5 minutes), subsequent requests escalate their score past the blocking threshold (0.7).
3. The sliding window must have a cleanup mechanism or map size limit to prevent OOM (Out Of Memory) issues.
4. The rate limiting is configurable (enabled by default, but threshold/window configurable via WAF initialization).
5. All tests in `npm test` pass.

## Mandatory commands

- cd npm && npm test

## Evidence required in transcript
Print `npm test` output showing the rate limiter tests passing, including an IP being blocked after repeated probes.

[Agent will print SUPERGOAL_PHASE_VERIFY and SUPERGOAL_PHASE_DONE here during execution]
