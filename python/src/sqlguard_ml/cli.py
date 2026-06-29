import argparse
import sys
import json
from .detector import PayloadDetector

def main():
    parser = argparse.ArgumentParser(description="SQLGuard ML CLI")
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # detect
    detect_parser = subparsers.add_parser("detect", help="Detect attack in a single payload")
    detect_parser.add_argument("payload", type=str, help="The payload string to check")

    # scan-file
    scan_parser = subparsers.add_parser("scan-file", help="Scan a file containing payloads (one per line)")
    scan_parser.add_argument("filepath", type=str, help="Path to the file")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    if args.command == "detect":
        detector = PayloadDetector()
        res = detector.predict(args.payload)
        print(json.dumps(res, indent=2))

    elif args.command == "scan-file":
        detector = PayloadDetector()
        try:
            with open(args.filepath, "r", encoding="utf-8") as f:
                payloads = f.read().splitlines()
            results = [{"payload": p, "result": detector.predict(p)} for p in payloads if p.strip()]
            print(json.dumps(results, indent=2))
        except Exception as e:
            print(f"Error scanning file: {e}")
            sys.exit(1)

if __name__ == "__main__":
    main()
