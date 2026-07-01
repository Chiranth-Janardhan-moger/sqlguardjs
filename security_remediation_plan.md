# Security Remediation Plan: Addressing Critical Gaps

This plan addresses the identified security and architecture gaps in the current implementation of `sqlguard-ml`. 

## Gap Analysis & Remediation Steps

### 1. No Rate Limiting / Repeated Probe Detection
**Problem:** The middleware treats each request independently. Attackers can send hundreds of slightly mutated payloads without penalty, allowing them to brute-force a bypass.
**Solution:** Implement a sliding window request log per IP that escalates the confidence score of malicious activity when repeated suspicious probes are detected.
*   **Action 1:** Add an in-memory (or Redis-backed, if configured) rate-limiter in the Express middleware (`npm/src/detector.js` or a new `rateLimiter.js` module).
*   **Action 2:** Track IP addresses and baseline score. If an IP repeatedly triggers a low-confidence score (e.g., `0.2 - 0.5` range), escalate the aggregate score past the blocking threshold (e.g., `> 0.7`).
*   **Action 3:** Export configuration options for the sliding window (e.g., `windowMs`, `maxSuspiciousRequests`).

### 2. Header Deep Scanning
**Problem:** Although `req.headers` are intercepted, attacks via `User-Agent`, `Referer`, and `X-Forwarded-For` often bypass middleware if they aren't subjected to the exact same rigorous decoding and heuristics as the body and query string.
**Solution:** Ensure all critical headers are deep-scanned.
*   **Action 1:** Update `expressMiddleware` to iterate specifically through high-risk headers (`User-Agent`, `Referer`, `X-Forwarded-For`, `Cookie`).
*   **Action 2:** Ensure `decodeDeeply` is applied to these header values.
*   **Action 3:** Write explicit Jest tests injecting payloads into these headers to guarantee they are blocked.

### 3. Content-Type: text/plain Bypass
**Problem:** Express skips parsing raw bodies into `req.body` if the content-type isn't JSON/URL-encoded (unless specifically configured), leaving it as a Buffer or undefined. The middleware currently skips this.
**Solution:** Ensure the middleware can inspect raw text bodies.
*   **Action 1:** Update the middleware to detect unparsed raw bodies, or recommend/enforce the use of `express.text()` and `express.raw()` before the WAF middleware.
*   **Action 2:** If `req.body` is a Buffer or raw string, process it directly instead of assuming it's an object.
*   **Action 3:** Add an adversarial test sending a malicious string via `Content-Type: text/plain` to ensure it is blocked.

### 4. No Second-Opinion ML Service
**Problem:** The hybrid bridge points to a user-supplied endpoint that doesn't exist by default. Requests in the ambiguous confidence zone fall through.
**Solution:** Publish a trainable, runnable Python FastAPI stub that acts as the "second opinion."
*   **Action 1:** Create a simple, legitimate ML model (e.g., Logistic Regression on character n-grams using `scikit-learn`) in the `python/` directory. This is more honest and functional than an empty CNN-LSTM promise.
*   **Action 2:** Wrap this model in a FastAPI endpoint that the NPM package can communicate with by default.
*   **Action 3:** Update the `README.md` to document how users can train this model on their own data or run it alongside their Node app.

### 5. Adversarial Test Suite & False Positive Benchmarking
**Problem:** Tests only cover known payloads, not deliberate bypass attempts or real-world benign traffic (leading to unknown false-positive rates).
**Solution:** Expand the test suite and benchmark the heuristics.
*   **Action 1:** Create `__tests__/adversarial.test.js` with deliberate bypass techniques (e.g., weird encodings, fragmented SQL comments, non-standard whitespaces).
*   **Action 2:** Create a benchmark suite using a dataset of benign traffic (e.g., large blocks of text, names like O'Brien, normal JSON payloads) to measure the false positive rate.
*   **Action 3:** Make the adversarial suite easily extensible so the community can contribute new bypass vectors.

### 6. Marketing and Documentation Cleanup
**Problem:** The project uses language implying a finished "zero-day" ML product, which security professionals will immediately scrutinize and debunk.
**Solution:** Be honest about the project's current state.
*   **Action 1:** Remove "zero-day" and "impenetrable" language from the `README.md`.
*   **Action 2:** Document the dual-architecture pattern as a *framework* for ML integration, and highlight the heuristics/rate-limiting as the current primary defense.
*   **Action 3:** Update documentation to reflect the planned roadmap for more advanced ML capabilities.
