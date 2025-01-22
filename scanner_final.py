from pathlib import Path
from typing import Dict, Any
from scan_file.check_file_info import FileInformationEngine
from scan_file.check_Suspicious_Content import SuspiciousContentEngine
from scan_file.check_virustotal import VirusTotalEngine
from scan_file.file_selector import FileSelector  # Import the FileSelector class


class FileScanner:
    """Unified file scanner that combines file information, suspicious content detection, and VirusTotal scanning."""

    def __init__(self, virustotal_api_key: str):
        """Initialize the file scanner with necessary engines."""
        self.file_info_engine = FileInformationEngine()
        self.suspicious_content_engine = SuspiciousContentEngine()
        self.virustotal_engine = VirusTotalEngine(virustotal_api_key)

    def scan_file(self, file_path: str) -> Dict[str, Any]:
        """
        Perform a comprehensive scan of the file using all available engines.
        """
        try:
            path = Path(file_path)
            if not path.exists():
                return {"error": "File not found", "file_path": file_path}
            if not path.is_file():
                return {"error": "Path is not a file", "file_path": file_path}

            scan_results = {
                "error": None,
                "file_path": str(path),
                "file_name": path.name,
                "file_size": path.stat().st_size,
                "file_info": {},
                "detections": {
                    "suspicious_content": False,
                    "malicious_content": False,
                    "suspicious_extension": False
                },
                "details": {
                    "file_info": {},
                    "suspicious_findings": [],
                    "virustotal_results": None
                }
            }

            # Get file information
            file_info = self.file_info_engine.get_file_info(str(path))
            file_hashes = self.file_info_engine.calculate_file_hashes(str(path))
            scan_results["details"]["file_info"] = {
                "mime_type": file_info.get('mime_type', 'unknown'),
                "file_type": file_info.get('file_type', 'unknown'),
                "hashes": file_hashes}

            # Check for suspicious content
            suspicious_content = self.suspicious_content_engine.detect_suspicious_content(path)

            # Update detections based on suspicious content
            if suspicious_content.get('file_extensions'):
                scan_results["detections"]["suspicious_extension"] = True
                scan_results["details"]["suspicious_findings"].extend(
                    [f"Suspicious extension: {ext}" for ext in suspicious_content['file_extensions']]
                )

            if suspicious_content.get('security_risks'):
                scan_results["detections"]["suspicious_content"] = True
                scan_results["details"]["suspicious_findings"].extend(suspicious_content['security_risks'])

            # Scan with VirusTotal using SHA256 hash
            if file_hashes.get('sha256'):
                virustotal_results = self.virustotal_engine.scan_with_virustotal(
                    path,
                    file_hashes['sha256']
                )
                scan_results["details"]["virustotal_results"] = virustotal_results

                if virustotal_results and virustotal_results.get('malware_detected'):
                    scan_results["detections"]["malicious_content"] = True

            return scan_results

        except Exception as e:
            return {
                "error": str(e),
                "file_path": file_path
            }


def print_scan_results(results):
    """Print the scan results in a formatted way"""
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


def main():
    # Initialize the file selector
    file_selector = FileSelector()

    # Initialize scanner with your VirusTotal API key
    scanner = FileScanner("your_virustotal_api_key")

    print("Select files to scan...")
    selected_files = file_selector.select_files()

    if not selected_files:
        print("No files were selected.")
        return

    # Scan each selected file
    for file_path in selected_files:
        results = scanner.scan_file(file_path)
        print_scan_results(results)
        print("\n" + "=" * 50 + "\n")  # Separator between file results


if __name__ == "__main__":
    main()