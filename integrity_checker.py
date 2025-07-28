import os
import hashlib
import json
import argparse
from datetime import datetime

def hash_file(filepath):
    """Calculates the SHA-256 hash of a file."""
    sha256_hash = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            # Read the file in chunks to handle large files
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except IOError:
        print(f"[!] Could not read file: {filepath}")
        return None

def generate_baseline(directory, output_file):
    """Generates a baseline JSON file of file hashes for a directory."""
    baseline = {}
    print(f"Generating baseline for directory: '{directory}'")
    for root, _, files in os.walk(directory):
        for filename in files:
            # Ignore the baseline file itself if it's in the directory
            if filename == output_file:
                continue
            filepath = os.path.join(root, filename)
            file_hash = hash_file(filepath)
            if file_hash:
                # Store path relative to the monitored directory
                relative_path = os.path.relpath(filepath, directory)
                baseline[relative_path] = file_hash
    
    baseline_report = {
        "metadata": {
            "directory": os.path.abspath(directory),
            "timestamp": datetime.now().isoformat()
        },
        "hashes": baseline
    }

    with open(output_file, 'w') as f:
        json.dump(baseline_report, f, indent=4)
    print(f"\n[+] Baseline generated successfully and saved to '{output_file}'")

def check_integrity(baseline_file):
    """Checks the integrity of a directory against a baseline file."""
    try:
        with open(baseline_file, 'r') as f:
            baseline_report = json.load(f)
    except FileNotFoundError:
        print(f"[!] Baseline file not found: '{baseline_file}'")
        return

    baseline_hashes = baseline_report['hashes']
    directory = baseline_report['metadata']['directory']
    
    print("-" * 50)
    print(f"Checking integrity of: {directory}")
    print(f"Using baseline from: {baseline_report['metadata']['timestamp']}")
    print("-" * 50)
    
    altered_files = []
    new_files = []
    missing_files = list(baseline_hashes.keys())
    issues_found = False
    
    # Check for altered or new files
    for root, _, files in os.walk(directory):
        for filename in files:
            if filename == os.path.basename(baseline_file):
                continue
            filepath = os.path.join(root, filename)
            relative_path = os.path.relpath(filepath, directory)
            current_hash = hash_file(filepath)
            
            if relative_path in baseline_hashes:
                if current_hash != baseline_hashes[relative_path]:
                    print(f"[!] ALTERED: {relative_path}")
                    altered_files.append(relative_path)
                    issues_found = True
                # File is present and unchanged, so remove it from the missing list
                if relative_path in missing_files:
                    missing_files.remove(relative_path)
            else:
                print(f"[+] NEW:     {relative_path}")
                new_files.append(relative_path)
                issues_found = True

    # Any files left in missing_files were not found in the scan
    for f in missing_files:
        print(f"[-] MISSING: {f}")
        issues_found = True
        
    print("-" * 50)
    if not issues_found:
        print("✅ Integrity Check Passed: No changes detected.")
    else:
        print("❌ Integrity Check Failed: Changes were detected.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="A File Integrity Checker tool.")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Command to generate a baseline
    gen_parser = subparsers.add_parser("generate", help="Generate a new hash baseline for a directory.")
    gen_parser.add_argument("directory", help="The directory to monitor.")
    gen_parser.add_argument("-o", "--output", default="baseline.json", help="Name for the output baseline file (default: baseline.json).")

    # Command to check integrity
    check_parser = subparsers.add_parser("check", help="Check directory integrity against a baseline file.")
    check_parser.add_argument("baseline_file", default="baseline.json", nargs="?", help="The baseline file to check against (default: baseline.json).")

    args = parser.parse_args()

    if args.command == "generate":
        generate_baseline(args.directory, args.output)
    elif args.command == "check":
        check_integrity(args.baseline_file)