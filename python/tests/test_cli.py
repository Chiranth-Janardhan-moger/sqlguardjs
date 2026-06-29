import subprocess
import json
import os

def test_cli_help():
    result = subprocess.run(["sqlguard", "--help"], capture_output=True, text=True)
    assert result.returncode == 0
    assert "SQLGuard ML CLI" in result.stdout

def test_cli_detect():
    result = subprocess.run(["sqlguard", "detect", "' OR 1=1"], capture_output=True, text=True)
    assert result.returncode == 0
    data = json.loads(result.stdout)
    assert "label" in data
    assert "confidence" in data

def test_cli_scan_file(tmp_path):
    f = tmp_path / "payloads.txt"
    f.write_text("' OR 1=1\n<script>alert(1)</script>")
    result = subprocess.run(["sqlguard", "scan-file", str(f)], capture_output=True, text=True)
    assert result.returncode == 0
    data = json.loads(result.stdout)
    assert len(data) == 2
    assert "result" in data[0]
