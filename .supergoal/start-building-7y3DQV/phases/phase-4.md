SUPERGOAL_PHASE_START
Phase: 4 of 5 — Adversarial Test Suite & Benchmarking
Task: Write a proper adversarial test suite with deliberate bypass attempts, and benchmark false positives on benign traffic.
Mandatory commands: cd npm && npm test
Acceptance criteria: 3
Evidence required: Output showing the adversarial tests running and passing, and a script successfully evaluating a benign dataset.
Depends on phases: 1, 2

## Why
A security product is only as good as its resistance to deliberate evasion. Adding an adversarial suite hardens the regexes against mutations.

## Work
- `npm/__tests__/adversarial.test.js` covering evasion techniques (fragmented keywords, weird encodings, bypassing).
- `npm/__tests__/benign.test.js` or a benchmark script that runs a dataset of real-world benign text to measure the false positive rate.

## Acceptance criteria (all must pass — verify each in transcript)
- Code must pass linting.
- Tests must run without warnings.
1. Adversarial tests must include payloads that try to bypass `req.body` using raw strings, headers, and encoding obfuscation.
2. The benchmark must test at least 20 real-world, non-malicious text inputs (e.g., standard prose containing "select", "union", names like "O'Brien", etc.).
3. All tests must pass, ensuring no false positives on the benign suite.

## Mandatory commands

- cd npm && npm test

## Evidence required in transcript
Print output from the Jest test runner showing the adversarial bypass attempts being successfully blocked and the benign dataset being permitted without false positives.

[Agent will print SUPERGOAL_PHASE_VERIFY and SUPERGOAL_PHASE_DONE here during execution]
