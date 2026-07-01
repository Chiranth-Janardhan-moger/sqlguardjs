# Supergoal Roadmap

## Task
Address security and architectural gaps in `sqli_xss_detection` (Rate limiting, header scanning, plain-text body, ML stub, adversarial tests, doc rewrite).

## Target Environment
- Express/Node (npm package) for middleware.
- Python FastAPI (python/) for the ML stub.

## Dependencies & Sequence
Phase 1: Rate Limiting & Sliding Window Memory (NPM)
Phase 2: Header Scanning & Text Body Parsing (NPM)
Phase 3: Python FastAPI ML Stub implementation
Phase 4: Adversarial Test Suite & Benchmarking
Phase 5: Polish & Harden (Documentation cleanup and final verifications)

## Success Condition
All gaps addressed securely. The tests pass. The FastAPI server runs correctly, and the documentation drops the zero-day claims.
