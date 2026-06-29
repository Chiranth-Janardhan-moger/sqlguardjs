import pytest
from sqlguard_ml.detector import PayloadDetector

def test_detector_initialization():
    detector = PayloadDetector()
    assert detector.model is None
    assert detector.tokenizer is None
    assert detector.le is None

def test_detector_predict():
    detector = PayloadDetector()
    result = detector.predict("' OR '1'='1")
    assert "label" in result
    assert "confidence" in result
    assert "probabilities" in result
    assert isinstance(result["confidence"], float)
    assert isinstance(result["label"], str)
