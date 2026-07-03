import argparse
import sys
import json
from .detector import PayloadDetector

def main():
    parser = argparse.ArgumentParser(description="SQLGuardJS CLI")
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    detect_parser = subparsers.add_parser("detect", help="Detect attack in a single payload")
    detect_parser.add_argument("payload", type=str, help="The payload string to check")

    args = parser.parse_args()

    if not args.command:
        parser.print_help()
        sys.exit(1)

    if args.command == "detect":
        detector = PayloadDetector()
        res = detector.predict(args.payload)
        print(json.dumps(res, indent=2))

if __name__ == "__main__":
    main()
