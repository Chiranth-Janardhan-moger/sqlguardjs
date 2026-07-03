# Security Policy

SQLGuard is a defense-in-depth request inspection library. Please do not treat a pass from this detector as proof that an application is safe from SQLi or XSS. Applications must still use parameterized queries, context-aware output encoding, HTML sanitization where needed, and least-privilege runtime accounts.

## Supported Versions

| Version | Supported |
| ------- | --------- |
| 1.0.x   | Yes       |
| 0.1.x   | Yes       |
| < 0.1.0 | No        |

Supported releases receive security fixes. Users should upgrade to a supported version before reporting a vulnerability.

## Reporting a Vulnerability

If you discover a security vulnerability within SQLGuard, please do not disclose it publicly. Instead, submit an issue with the label `security` or contact the maintainer directly.

When possible, include the affected version, the payload or reproduction steps, the expected result, and the actual result.
