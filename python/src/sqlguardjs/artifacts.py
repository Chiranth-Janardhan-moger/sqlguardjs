import hashlib
import hmac
import os


ARTIFACT_HASHES = {
    "attack_cnn_lstm.h5": "7205fee15745ec243d19534917210270ad0d0c41cc42be585d096f9fb5d51437",
    "tokenizer.json": "ff05559be50141376a91281569077eb9ac357bdf3815d35d5df5464ce8abc897",
    "label_encoder.pkl": "1b66680c906ec5c6e5350c99e95358286309fe3cdac63fd9f3bb2ecc687fde12",
    "stub_model.pkl": "626c2be3750db169a62f2e1b2dc3fdfd8db0715b8522b31e62816668e6e6a861",
    "stub_vectorizer.pkl": "cb67d3a039e60857424a6c1952e580ad45527d0d8c2ff65e4e20e37711738d31",
}


def verify_artifact(path: str) -> str:
    name = os.path.basename(path)
    expected_hash = ARTIFACT_HASHES.get(name)
    if expected_hash is None:
        raise RuntimeError(f"untrusted model artifact: {name}")
    if not os.path.exists(path):
        raise FileNotFoundError(f"model artifact missing: {name}")

    digest = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(chunk)

    actual_hash = digest.hexdigest()
    if not hmac.compare_digest(actual_hash, expected_hash):
        raise RuntimeError(f"model artifact hash mismatch: {name}")
    return path
