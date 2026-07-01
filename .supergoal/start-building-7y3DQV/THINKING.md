# Supergoal Thinking: sqli_xss_detection Remediation Plan

## Goals
- Address the critical architecture and security gaps listed in `security_remediation_plan.md`.
- Implement IP-based rate limiting to escalate threat scores upon repeated probes.
- Deep scan `User-Agent`, `Referer`, and `X-Forwarded-For` headers exactly like the body.
- Process `Content-Type: text/plain` requests without skipping raw text payload inspection.
- Replace the missing ML model claim with a legitimate, runnable Python FastAPI stub serving a simple Logistic Regression (or similar) model.
- Write an adversarial test suite to proactively test for bypasses.
- Update `README.md` to truthfully reflect the project's state.

## Constraints
- **Performance**: The rate limiter and header scanning shouldn't significantly degrade request latency.
- **Contract Compatibility**: The newly added Python ML stub must accept the exact POST payload format expected by the `npm/src/detector.js` bridge.

## Top 3 Risks
1. **Rate Limiter Memory Leak**: If we track IPs in memory without size caps or cleanup, a distributed scan could OOM the Node server. Mitigation: Implement a lightweight Map with a maximum size or a LRU approach/timestamp expiration.
2. **Crash on Unexpected Headers/Body**: Parsing raw text or checking headers that might be arrays (like `X-Forwarded-For`) might throw errors. Mitigation: Strict type checking (`typeof value === 'string'`) before scanning.
3. **ML Stub Integration Failure**: If the FastAPI ML model requires scikit-learn but the Node process assumes a deep neural net structure, it will crash. Mitigation: Carefully map the JSON input and output (e.g., `is_malicious`, `confidence`) between the Express middleware and FastAPI response.

## Dependencies
- The Python ML script needs `fastapi`, `uvicorn`, and `scikit-learn`.
- The adversarial test suite requires the WAF patches to be completed first to verify they are blocked.

## Memory Hits Applied
- `project_memory.md`: We are working on the pending tasks to publish `sqlguard-ml@1.1.4` fixes. The fixes are explicitly listed there.

## Tools & Skills
- `write_to_file`, `replace_file_content` for JS and Python logic.
- `run_command` for validating Python dependencies, running Jest, and typechecking.
