# Contributing

Contributions are welcome, especially new bypass regressions, false-positive reductions, documentation fixes, and integration examples.

## Workflow

1. Fork the repository and create a branch from `main`.
2. Add or update tests for behavior changes.
3. Update documentation when public APIs, options, or security behavior changes.
4. Run the Node test suite before opening a pull request.

```bash
cd npm
npm test
```

## Security Payloads

When reporting or contributing bypass payloads, prefer adding a focused Jest test under `npm/__tests__`. Keep payloads minimal and explain the expected detector result.

## Pull Requests

Pull requests should be scoped, reproducible, and include a short explanation of the change. Avoid unrelated formatting changes.
