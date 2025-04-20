import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import queue
import os
import time

from scan_file.check_file_info import FileInformationEngine
from scan_file.check_Suspicious_Content import SuspiciousContentEngine
from scan_file.check_virustotal import VirusTotalEngine
from scan_file.file_selector import FileSelector
from scan_file.signiture_verification import SignatureVerificationEngine


class FileScanner:
    """Unified file scanner that combines file information, suspicious content detection, signature verification, and VirusTotal scanning."""

    def __init__(self):
        """Initialize all scanner engines."""
        self.file_info_engine = FileInformationEngine()
        self.suspicious_content_engine = SuspiciousContentEngine()
        self.virustotal_engine = VirusTotalEngine()
        self.signature_engine = SignatureVerificationEngine()
        self.vt_semaphore = threading.Semaphore(4)
        self.results_queue = queue.Queue()

    def scan_file(self, file_path):
        """
        Scan a single file using all available security engines.

        Args:
            file_path: Path to the file to scan

        Returns:
            Dictionary with comprehensive scan results
        """
        try:
            with self.vt_semaphore:
                # Validate file exists
                path = Path(file_path)
                if not path.exists() or not path.is_file():
                    return {"error": "Invalid file path", "file_path": file_path}

                # Initialize scan results structure
                scan_results = self._initialize_scan_results(path)

                # Collect file information
                self._gather_file_info(path, scan_results)

                # Check for suspicious content
                self._check_suspicious_content(path, scan_results)

                # Verify digital signature
                self._verify_signature(path, scan_results)

                # Check with VirusTotal
                self._check_virustotal(path, scan_results)

                return scan_results

        except Exception as e:
            return {"error": str(e), "file_path": file_path}

    def _initialize_scan_results(self, path):
        """Create the initial scan results dictionary structure."""
        return {
            "error": None,
            "file_path": str(path),
            "file_name": path.name,
            "file_size": path.stat().st_size,
            "detections": {
                "suspicious_content": False,
                "malicious_content": False,
                "suspicious_extension": False
            },
            "details": {
                "file_info": {},
                "suspicious_findings": [],
                "virustotal_results": None,
                "signature_info": None
            }
        }

    def _gather_file_info(self, path, scan_results):
        """Gather basic file information and hashes."""
        file_info = self.file_info_engine.get_file_info(str(path))
        file_hashes = self.file_info_engine.calculate_file_hashes(str(path))
        scan_results["details"]["file_info"] = {
            "mime_type": file_info.get('mime_type', 'unknown'),
            "file_type": file_info.get('file_type', 'unknown'),
            "hashes": file_hashes
        }

    def _check_suspicious_content(self, path, scan_results):
        """Check for suspicious content patterns and file extensions."""
        suspicious_content = self.suspicious_content_engine.detect_suspicious_content(path)

        # Check suspicious extensions
        if suspicious_content.get('file_extensions'):
            scan_results["detections"]["suspicious_extension"] = True
            scan_results["details"]["suspicious_findings"].extend(
                [f"Suspicious extension: {ext}" for ext in suspicious_content['file_extensions']]
            )

        # Check security risks
        if suspicious_content.get('security_risks'):
            scan_results["detections"]["suspicious_content"] = True
            scan_results["details"]["suspicious_findings"].extend(suspicious_content['security_risks'])

    def _verify_signature(self, path, scan_results):
        """Verify digital signature of the file."""
        signature_info = self.signature_engine.verify_signature(str(path))
        scan_results["details"]["signature_info"] = signature_info

    def _check_virustotal(self, path, scan_results):
        """Check file against VirusTotal database."""
        file_hashes = scan_results["details"]["file_info"]["hashes"]
        if file_hashes.get('sha256'):
            virustotal_results = self.virustotal_engine.scan_with_virustotal(path, file_hashes['sha256'])
            scan_results["details"]["virustotal_results"] = virustotal_results
            if virustotal_results and virustotal_results.get('malware_detected'):
                scan_results["detections"]["malicious_content"] = True


def print_scan_results(results):
    """Print the scan results in a formatted way."""
    if results.get("error"):
        print(f"\nError scanning file: {results['file_path']}")
        print(f"Error message: {results['error']}")
        return

    print(f"\nScan Results for: {results['file_name']}")
    print(f"File Path: {results['file_path']}")
    print(f"File Size: {results['file_size']} bytes")

    print("\nDetections:")
    for detection_type, detected in results['detections'].items():
        print(f"{detection_type.replace('_', ' ').title()}: {'Detected' if detected else 'Not Detected'}")

    print("\nDetailed Findings:")
    if results['details']['suspicious_findings']:
        print("\nSuspicious Findings:")
        for finding in results['details']['suspicious_findings']:
            print(f"- {finding}")

    if results['details']['virustotal_results']:
        print("\nVirusTotal Results:")
        print(results['details']['virustotal_results'])

    print("\nFile Information:")
    file_info = results['details']['file_info']
    print(f"MIME Type: {file_info.get('mime_type')}")
    print(f"File Type: {file_info.get('file_type')}")
    print("\nFile Hashes:")
    for hash_type, hash_value in file_info['hashes'].items():
        print(f"{hash_type.upper()}: {hash_value}")


# ===== File Security Scoring Functions =====

def scan_and_score_files(file_paths):
    """
    Scan and score multiple files, providing security ratings and removal recommendations.
    This function uses all available scanner engines to assess file security.

    Args:
        file_paths: List of file paths to scan and score

    Returns:
        List of dictionaries containing scores and recommendations for each file
    """
    results = []
    scanner = FileScanner()
    print_lock = threading.Lock()

    # Process files in parallel
    with ThreadPoolExecutor(max_workers=min(len(file_paths), 5)) as executor:
        futures = [executor.submit(_process_single_file, file_path, scanner, print_lock)
                   for file_path in file_paths]

        for future in futures:
            try:
                result = future.result()
                if result:
                    results.append(result)
            except Exception as e:
                print(f"Error getting result: {str(e)}")

    return results


def _process_single_file(file_path, scanner, print_lock):
    """Process a single file for scoring."""
    try:
        print(f"Scanning and scoring: {file_path}")
        # Get full scan results
        scan_results = scanner.scan_file(file_path)

        # Skip files that couldn't be scanned
        if scan_results.get("error"):
            return {
                "file_path": file_path,
                "file_name": Path(file_path).name,
                "score": None,
                "recommendation": f"Could not be scanned: {scan_results['error']}",
                "scan_results": scan_results
            }

        # Score the file based on scan results
        score, recommendation = _calculate_security_score(scan_results)

        result = {
            "file_path": file_path,
            "file_name": Path(file_path).name,
            "score": score,
            "recommendation": recommendation,
            "scan_results": scan_results
        }

        with print_lock:
            print(f"File: {result['file_name']}")
            print(f"Security Score: {result['score']}/10")
            print(f"Recommendation: {result['recommendation']}")
            print("-" * 50)

        return result

    except Exception as e:
        print(f"Error processing {file_path}: {str(e)}")
        return {
            "file_path": file_path,
            "file_name": Path(file_path).name,
            "score": None,
            "recommendation": f"Could not be scanned: {str(e)}",
            "scan_results": None
        }


def _calculate_security_score(scan_results):
    """
    Calculate a security score and recommendation based on scan results.

    Args:
        scan_results: Results from scanning the file

    Returns:
        Tuple of (score, recommendation)
    """
    # Initialize score (10 is safest, 1 is definitely malware)
    score = 10
    recommendation = "SAFE: No security concerns detected"

    # Get detection results
    detections = scan_results.get("detections", {})
    details = scan_results.get("details", {})

    # VirusTotal detection = automatic score of 1 (definitely malware)
    if detections.get("malicious_content"):
        return 1, "REMOVE IMMEDIATELY: Detected as malware by VirusTotal"

    # Check if VirusTotal scan failed or timed out
    virustotal_results = details.get("virustotal_results", {})
    virustotal_failed = not virustotal_results or virustotal_results.get("status") in ["Error", "Timeout"]

    # Apply signature verification factors
    score = _apply_signature_factors(score, detections, details, virustotal_failed)

    # Ensure score stays within 1-10 range
    score = max(1, min(10, score))

    # Generate recommendation based on score
    if score <= 3:
        recommendation = "REMOVE: High security risk detected"
    elif score <= 5:
        recommendation = "CAUTION: Moderate security risk, review before using"
    elif score <= 7:
        recommendation = "ACCEPTABLE: Some concerns but likely safe"
    # else keep the default "SAFE" recommendation

    return score, recommendation


def _apply_signature_factors(score, detections, details, virustotal_failed):
    """Apply signature verification factors to the security score."""
    # Check signature verification
    signature_info = details.get("signature_info", {})

    # If the file is signed and verified, it's a positive signal
    if signature_info and signature_info.get("is_signed") and signature_info.get("is_verified"):
        # If VirusTotal failed but signature is good, rely on signature
        if virustotal_failed:
            score = max(score, 8)  # Set minimum score of 8 in this case

        # If suspicious content but properly signed, signature validates it
        if detections.get("suspicious_content") or detections.get("suspicious_extension"):
            score -= 1  # Only small penalty
    else:
        # File is not signed or signature is invalid
        if virustotal_failed:
            score -= 1  # Slight penalty for VirusTotal failure

        # Found signature but couldn't verify it (possible tampering)
        if signature_info and signature_info.get("is_signed") and not signature_info.get("is_verified"):
            score -= 3

        # Suspicious content but not properly signed
        if detections.get("suspicious_content"):
            score -= 2

        # Suspicious extension but not properly signed
        if detections.get("suspicious_extension"):
            score -= 1

    return score


# ===== Main Function =====

def main():
    """Main function to run the file scanner."""
    file_selector = FileSelector()

    print("Welcome to the File Scanner")
    print("==========================")
    print("1. Scan files (detailed analysis)")
    print("2. Score files (security rating)")

    choice = input("Enter your choice (1 or 2): ")

    print("\nSelect files to process...")
    selected_files = file_selector.select_files()

    if not selected_files:
        print("No files were selected. Exiting.")
        return

    print(f"\nSelected {len(selected_files)} file(s).")
    start_time = time.time()

    if choice == "2":
        print("Starting security scoring...")
        scan_and_score_files(selected_files)
    else:
        # Default to regular scanning
        scanner = FileScanner()
        print("Starting detailed scan process...")
        print_lock = threading.Lock()

        def scan_file_thread(file_path):
            print(f"Scanning: {file_path}")
            results = scanner.scan_file(file_path)
            with print_lock:
                print_scan_results(results)
                print("\n" + "=" * 50 + "\n")

        # Use thread pool to scan files concurrently
        with ThreadPoolExecutor(max_workers=min(len(selected_files), 5)) as executor:
            executor.map(scan_file_thread, selected_files)

    elapsed_time = time.time() - start_time
    print(f"All scans completed in {elapsed_time:.2f} seconds.")


if __name__ == "__main__":
    main()