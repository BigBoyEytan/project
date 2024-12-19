import hashlib
import argparse
import concurrent.futures
import time
import pathlib
import requests
import re
import magic
import logging
from typing import List, Dict, Optional, Union

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Configuration constants
CONFIG = {
    'API_KEY': "70f9b90c35cb48d962a3bd27eb549977ca52e3400a6046250cc8a4780dabff09",
    'VIRUSTOTAL_API_URL': "https://www.virustotal.com/api/v3/files",
    'RATE_LIMIT_WAIT': 60,
    'ANALYSIS_POLL_INTERVAL': 20,
    'MAX_FILE_SIZE_MB': 32,
}

# Suspicious file extensions and patterns
SUSPICIOUS_INDICATORS = {
    'EXTENSIONS': {
        # Executable and script files
        '.exe', '.bat', '.cmd', '.com', '.scr', '.pif', '.vbs',
        '.vbe', '.js', '.jse', '.wsf', '.wsh', '.ps1', '.psm1',
        '.psd1', '.msi', '.msp', '.mst', '.jar', '.deb', '.rpm',
        # Additional suspicious extensions
        '.dll', '.sys', '.drv', '.bin', '.pyc', '.pyo',
        '.sh', '.bash', '.ksh', '.csh', '.pl', '.php'
    },
    'PATTERNS': [
        # Command execution
        r'cmd\.exe', r'powershell\.exe', r'bash\.exe', r'sh\.exe',
        # Code execution
        r'base64_decode', r'system\(\)', r'eval\(', r'exec\(',
        r'\bshell_exec\b', r'CreateObject\(',
        # Network activity
        r'urllib\.(request|parse)', r'requests\.',
        r'socket\.(connect|bind|listen)',
        # File operations
        r'os\.(system|popen|exec)', r'subprocess\.(Popen|call|run)',
        r'chmod.*\+x', r'icacls.*\/grant',
        # Encoding/Encryption
        r'base64\.(encode|decode)', r'crypto', r'cipher',
        # Registry operations
        r'RegCreateKey', r'RegSetValue', r'Registry\.'
    ]
}


class FileScanner:
    def __init__(self, api_key: str = CONFIG['API_KEY']):
        """
        Initialize FileScanner with VirusTotal API key.

        :param api_key: VirusTotal API key
        """
        self.api_key = api_key
        self.headers = {"x-apikey": self.api_key}

    def _get_mime_type(self, file_path: pathlib.Path) -> Optional[str]:
        """
        Detect MIME type of a file.

        :param file_path: Path to the file
        :return: MIME type or None if detection fails
        """
        try:
            mime = magic.Magic(mime=True)
            return mime.from_file(str(file_path))
        except Exception as e:
            logger.warning(f"MIME type detection failed for {file_path}: {e}")
            return None

    def _check_suspicious_indicators(self, file_path: pathlib.Path) -> Dict[str, List[str]]:
        """
        Perform static content analysis for suspicious indicators, supporting both binary and text files.

        :param file_path: Path to the file
        :return: Dictionary of detected suspicious indicators
        """
        detected_indicators = {
            'extensions': [],
            'patterns': [],
            'characteristics': []  # New category for binary-specific indicators
        }

        # Check file extension
        if file_path.suffix.lower() in SUSPICIOUS_INDICATORS['EXTENSIONS']:
            detected_indicators['extensions'].append(file_path.suffix.lower())

        try:
            # First, try to read file as binary
            with open(file_path, 'rb') as f:
                content = f.read()

                # Check for binary file characteristics
                # Look for executable headers
                if content.startswith(b'MZ'):  # DOS/PE executable
                    detected_indicators['characteristics'].append('DOS/Windows executable header')
                elif content.startswith(b'\x7fELF'):  # ELF executable
                    detected_indicators['characteristics'].append('ELF executable header')
                elif content.startswith(b'#!'):  # Shell script
                    detected_indicators['characteristics'].append('Shell script header')

                # Check for encoded/compressed content indicators
                if b'base64' in content:
                    detected_indicators['characteristics'].append('Contains base64 encoding')

                # Try to decode as text for pattern matching
                try:
                    text_content = content.decode('utf-8', errors='ignore')

                    # Check for suspicious patterns in text content
                    for pattern in SUSPICIOUS_INDICATORS['PATTERNS']:
                        matches = re.findall(pattern, text_content, re.IGNORECASE)
                        if matches:
                            detected_indicators['patterns'].extend(matches)

                    # Additional checks for script-like content
                    if any(keyword in text_content.lower() for keyword in [
                        'import os', 'import sys', 'subprocess', 'shell=True',
                        'eval(', 'exec(', 'os.system', 'chmod +x'
                    ]):
                        detected_indicators['patterns'].append('Suspicious script commands')

                except UnicodeDecodeError:
                    # File is purely binary, which is fine - we've already checked binary characteristics
                    pass

        except Exception as e:
            logger.error(f"Content analysis failed for {file_path}: {e}")
            detected_indicators['characteristics'].append(f'Analysis error: {str(e)}')

        return detected_indicators

    def _hash_file(self, file_path: pathlib.Path, algorithm: str = 'sha256') -> Optional[str]:
        """
        Calculate file hash using specified algorithm.

        :param file_path: Path to the file
        :param algorithm: Hashing algorithm (sha256, sha1, or md5)
        :return: File hash or None if hashing fails
        """
        hash_algorithms = {
            'sha256': hashlib.sha256(),
            'sha1': hashlib.sha1(),
            'md5': hashlib.md5()
        }

        hasher = hash_algorithms.get(algorithm)
        if not hasher:
            raise ValueError(f"Unsupported hash algorithm: {algorithm}")

        try:
            with open(file_path, 'rb') as f:
                for chunk in iter(lambda: f.read(4096), b""):
                    hasher.update(chunk)
            return hasher.hexdigest()
        except PermissionError:
            logger.warning(f"Permission denied for file: {file_path}")
            return None
        except Exception as e:
            logger.error(f"Hashing failed for {file_path}: {e}")
            return None

    def _virustotal_request(self, method: str, url: str, **kwargs) -> Optional[requests.Response]:
        """
        Handle VirusTotal API requests with error handling.

        :param method: HTTP method (get or post)
        :param url: API endpoint URL
        :param kwargs: Additional request parameters
        :return: Response object or None
        """
        try:
            request_method = getattr(requests, method)
            response = request_method(url, headers=self.headers, **kwargs)

            # Handle rate limiting
            while response.status_code == 429:
                logger.info("Rate limited. Waiting before retrying...")
                time.sleep(CONFIG['RATE_LIMIT_WAIT'])
                response = request_method(url, headers=self.headers, **kwargs)

            response.raise_for_status()
            return response
        except requests.RequestException as e:
            logger.error(f"API request failed: {e}")
            return None

    def scan_file(self, file_path: pathlib.Path) -> Dict[str, Union[str, List[str], None]]:
        """
        Comprehensively scan a single file.

        :param file_path: Path to the file
        :return: Scan results dictionary
        """
        # Initialize scan results
        scan_result = {
            'file_path': str(file_path),
            'mime_type': None,
            'suspicious_indicators': None,
            'virustotal_status': None,
            'overall_risk': 'low'
        }

        if not file_path.exists():
            scan_result['overall_risk'] = 'unknown'
            scan_result['virustotal_status'] = "File not found"
            return scan_result

        # MIME Type and Suspicious Indicators Check
        scan_result['mime_type'] = self._get_mime_type(file_path)
        suspicious_indicators = self._check_suspicious_indicators(file_path)

        if suspicious_indicators['extensions'] or suspicious_indicators['patterns']:
            scan_result['suspicious_indicators'] = suspicious_indicators
            scan_result['overall_risk'] = 'high' if suspicious_indicators['patterns'] else 'medium'

        # Hash and VirusTotal Scan
        f_hash = self._hash_file(file_path)
        if not f_hash:
            scan_result['virustotal_status'] = 'Unable to hash'
            return scan_result

        # Perform VirusTotal analysis
        vt_url = f"{CONFIG['VIRUSTOTAL_API_URL']}/{f_hash}"
        response = self._virustotal_request('get', vt_url)

        if not response or response.status_code == 404:
            # Upload file for analysis if not found
            file_size = file_path.stat().st_size
            upload_url = CONFIG['VIRUSTOTAL_API_URL'] + (
                '/upload_url' if file_size > CONFIG['MAX_FILE_SIZE_MB'] * 1000000 else '')

            with open(file_path, "rb") as f:
                files = {"file": (file_path.name, f)}
                upload_response = self._virustotal_request('post', upload_url, files=files)

            if upload_response:
                # Wait for analysis and get results
                analysis_id = upload_response.json().get("data", {}).get("id")
                analysis_url = f"{CONFIG['VIRUSTOTAL_API_URL']}/analyses/{analysis_id}"

                while True:
                    time.sleep(CONFIG['ANALYSIS_POLL_INTERVAL'])
                    analysis_response = self._virustotal_request('get', analysis_url)

                    if not analysis_response:
                        break

                    status = analysis_response.json().get("data", {}).get("attributes", {}).get("status")
                    if status == "completed":
                        f_hash = analysis_response.json().get("meta", {}).get("file_info", {}).get("sha256")
                        break

        # Check VirusTotal results
        if response and response.status_code == 200:
            parsed_response = response.json().get("data", {}).get("attributes", {})
            engine_detected = parsed_response.get("last_analysis_stats", {}).get("malicious", 0) > 0

            scan_result['virustotal_status'] = 'bad' if engine_detected else 'good'
            if engine_detected:
                scan_result['overall_risk'] = 'high'

        return scan_result


def get_files(path: Union[str, pathlib.Path]) -> List[pathlib.Path]:
    """
    Returns a list of files from the directory (path can be a folder or single file).

    :param path: Path to file or directory
    :return: List of file paths
    """
    path = pathlib.Path(path)
    if path.is_dir():
        # Skip system and hidden files
        return [file for file in path.iterdir() if file.is_file() and not file.name.startswith('.')]
    elif path.is_file():
        return [path]
    else:
        raise ValueError(f"{path} is not a valid file or directory")


def scan_file(file_path: pathlib.Path) -> Dict[str, Union[str, List[str], None]]:
    """
    Wrapper function to use FileScanner class for compatibility with map() and multiprocessing.

    :param file_path: Path to the file
    :return: Scan results dictionary
    """
    scanner = FileScanner()
    return scanner.scan_file(file_path)


def main():
    """
    Main function to scan files or directories.
    """
    # Ask user for file or folder path
    path = input("Enter a file path or folder path to scan: ")

    # Get list of files
    try:
        files_list = get_files(path)
    except ValueError as e:
        print(e)
        return

    if not files_list:
        print("No files found to scan.")
        return

    print(f"Found {len(files_list)} files to scan.")

    # Thread pool executor to scan files concurrently
    with concurrent.futures.ThreadPoolExecutor() as executor:
        results = list(executor.map(scan_file, files_list))

    # Print the final results
    print("\nComprehensive Scan Results:")
    for result in results:
        print(f"\nFile: {result['file_path']}")
        print(f"Overall Risk: {result['overall_risk'].upper()}")

        if result.get('mime_type'):
            print(f"  - MIME Type: {result['mime_type']}")

        # Safely handle suspicious indicators
        if result.get('suspicious_indicators'):
            if result['suspicious_indicators'].get('extensions'):
                print("  - Suspicious File Extensions Detected:")
                for ext in result['suspicious_indicators']['extensions']:
                    print(f"    * {ext}")

            if result['suspicious_indicators'].get('patterns'):
                print("  - Suspicious Patterns Found:")
                for pattern in result['suspicious_indicators']['patterns']:
                    print(f"    * {pattern}")

        if result.get('virustotal_status'):
            print(f"  - VirusTotal Status: {result['virustotal_status']}")


if __name__ == "__main__":
    main()
