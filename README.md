# SQLGuard ML

SQLGuard ML is a cybersecurity portfolio project that detects SQL injection (SQLi) and Cross-Site Scripting (XSS) payloads.
It comes in two flavors:
1. **Python Machine Learning Package:** A robust TensorFlow-based detector leveraging a custom CNN-LSTM with attention mechanism. Includes a CLI, FastAPI server, and a lightweight web dashboard.
2. **Node.js NPM Package:** A fast, lightweight heuristic-based scanner designed as an NPM package for easy integration and fast CLI scanning.

## Python ML Package

Located in the `python/` directory.

### Installation

```bash
cd python
python -m venv .venv
source .venv/bin/activate  # On Windows: .\.venv\Scripts\Activate.ps1
pip install -e .
```

### Usage

**CLI Tool:**
```bash
sqlguard detect "' OR 1=1"
sqlguard scan-file payloads.txt
```

**FastAPI & Dashboard:**
```bash
uvicorn sqlguard_ml.api:app --reload
```
Then visit `http://127.0.0.1:8000` to view the interactive dashboard.

## Node.js NPM Package

Located in the `npm/` directory.

### Installation

```bash
cd npm
npm install
npm link
```

### Usage

**CLI Scanner:**
```bash
sqlguard-ml scan "<script>alert(1)</script>"
sqlguard-ml scan-file payloads.txt --format csv
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md)

## Security

See [SECURITY.md](SECURITY.md)

## License

MIT License. See [LICENSE](LICENSE)
