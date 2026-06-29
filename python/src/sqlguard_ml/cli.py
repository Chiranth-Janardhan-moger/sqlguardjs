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

    # train
    train_parser = subparsers.add_parser("train", help="Train the model (placeholder)")
    
    # evaluate
    evaluate_parser = subparsers.add_parser("evaluate", help="Evaluate the model (placeholder)")

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
            
            results = []
            for p in payloads:
                if p.strip():
                    results.append({"payload": p, "result": detector.predict(p)})
            print(json.dumps(results, indent=2))
        except Exception as e:
            print(f"Error scanning file: {e}")
            sys.exit(1)
            
    elif args.command == "train":
        print("Training functionality not implemented yet in CLI.")
        
    elif args.command == "evaluate":
        print("Evaluation functionality not implemented yet in CLI.")

if __name__ == "__main__":
    main()
