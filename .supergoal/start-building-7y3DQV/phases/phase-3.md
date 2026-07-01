SUPERGOAL_PHASE_START
Phase: 3 of 5 — Python FastAPI ML Stub implementation
Task: Implement a runnable Python FastAPI stub serving a simple Logistic Regression (or equivalent) model to fulfill the hybrid bridge promise.
Mandatory commands: cd python && pytest --disable-warnings || echo "no tests yet"
Acceptance criteria: 4
Evidence required: Output demonstrating the FastAPI server starting successfully and an HTTP request yielding a valid JSON response.
Depends on phases: none

## Why
The project claims a Hybrid AI Bridge, but the Python ML model endpoint doesn't exist out of the box. A functional, simple ML stub gives users a real starting point.

## Work
- A simple scikit-learn model training script for character n-grams (or similar) in `python/src/sqlguard_ml/`.
- A FastAPI application in `python/src/sqlguard_ml/api.py` that loads the model.
- A `requirements.txt` or `pyproject.toml` update adding `fastapi`, `uvicorn`, `scikit-learn`.

## Acceptance criteria (all must pass — verify each in transcript)
- Code must pass linting.
- Tests must run without warnings.
1. The FastAPI endpoint must accept a POST request with `{ "payload": "text" }`.
2. The endpoint must return a JSON response matching what `npm/src/detector.js` expects: `{ "is_malicious": true/false, "confidence": 0.85 }`.
3. The project should include a simple script to train a dummy/basic model so the API can actually load something.
4. Running `uvicorn sqlguard_ml.api:app --reload` (or similar) should successfully start the server.

## Mandatory commands

- cd npm && npm test

## Evidence required in transcript
Show the Python environment installing dependencies, a dummy model being generated, and a curl/invoke-restmethod hitting the FastAPI server and getting a valid response.

[Agent will print SUPERGOAL_PHASE_VERIFY and SUPERGOAL_PHASE_DONE here during execution]
