import hashlib
import concurrent.futures
import time
import pathlib
import requests
import re
import magic
from typing import List, Dict, Optional, Union
from io import BytesIO

# Configuration constants
CONFIG = {
    'API_KEY': "70f9b90c35cb48d962a3bd27eb549977ca52e3400a6046250cc8a4780dabff09",
    'VIRUSTOTAL_API_URL': "https://www.virustotal.com/api/v3/files",
    'RATE_LIMIT_WAIT': 60,
    'ANALYSIS_POLL_INTERVAL': 20,
    'MAX_FILE_SIZE_MB': 32,
    'CHUNK_SIZE': 8192  # Optimal chunk size for file reading
}

# Enhanced suspicious indicators
SUSPICIOUS_INDICATORS = {
    'EXTENSIONS': {
        # Executable and script files
        '.exe', '.bat', '.cmd', '.com', '.scr', '.pif', '.vbs',
        '.vbe', '.js', '.jse', '.wsf', '.wsh', '.ps1', '.psm1',
        '.psd1', '.msi', '.msp', '.mst', '.jar', '.deb', '.rpm',
        # Additional suspicious extensions
        '.dll', '.sys', '.drv', '.bin', '.pyc', '.pyo',
        '.sh', '.bash', '.ksh', '.csh', '.pl', '.php',
        # Archive extensions that might contain malware
        '.zip', '.rar', '.7z', '.tar', '.gz', '.iso',
        # Office documents that might contain macros
        '.doc', '.docm', '.xls', '.xlsm', '.ppt', '.pptm'
    },
    'PATTERNS': [
        # Enhanced command execution patterns
        r'cmd\.exe', r'powershell\.exe', r'bash\.exe', r'sh\.exe',
        r'rundll32\.exe', r'regsvr32\.exe', r'mshta\.exe',
        # Enhanced code execution patterns
        r'base64_decode', r'system\(\)', r'eval\(', r'exec\(',
        r'\bshell_exec\b', r'CreateObject\(', r'WScript.Shell',
        r'ActiveXObject', r'Process.Start', r'Runtime.getRuntime\(',
        # Network activity patterns
        r'urllib\.(request|parse)', r'requests\.', r'wget\.',
        r'socket\.(connect|bind|listen)', r'http[s]?://',
        r'ftp://', r'ssh://', r'telnet://',
        # Enhanced file operations
        r'os\.(system|popen|exec)', r'subprocess\.',
        r'chmod.*\+x', r'icacls.*\/grant', r'cacls', r'attrib',
        # Registry and system modifications
        r'RegCreateKey', r'RegSetValue', r'Registry\.',
        r'HKEY_LOCAL_MACHINE', r'HKEY_CURRENT_USER',
        # Encryption and encoding patterns
        r'base64\.(encode|decode)', r'crypto', r'cipher',
        r'password', r'encrypt', r'decrypt'
    ]
}


class FileScanner:
    def __init__(self, api_key: str = CONFIG['API_KEY']):
        self.api_key = api_key
        self.headers = {"x-apikey": self.api_key}
        self.mime = magic.Magic(mime=True)
        self.raw = magic.Magic()

    def _read_file_safely(self, file_path: pathlib.Path) -> Optional[bytes]:
        """
        Safely read file content with multiple encoding attempts.

        :param file_path: Path to the file
        :return: File content as bytes or None if reading fails
        """
        try:
            with open(file_path, 'rb') as f:
                return f.read()
        except Exception:
            return None

    def _get_file_info(self, file_path: pathlib.Path) -> Dict[str, str]:
        """
        Get comprehensive file information.

        :param file_path: Path to the file
        :return: Dictionary containing file information
        """
        content = self._read_file_safely(file_path)
        if not content:
            return {'mime_type': 'unknown', 'file_type': 'unknown'}

        return {
            'mime_type': self.mime.from_buffer(content),
            'file_type': self.raw.from_buffer(content)
        }

    def _deep_content_analysis(self, content: bytes, file_info: Dict[str, str]) -> List[str]:
        """
        Perform deep content analysis of file bytes.

        :param content: File content as bytes
        :param file_info: File information dictionary
        :return: List of suspicious indicators found
        """
        indicators = []

        # Check for executable headers
        if content.startswith(b'MZ'):
            indicators.append('DOS/Windows executable header')
        elif content.startswith(b'\x7fELF'):
            indicators.append('ELF executable header')
        elif content.startswith(b'#!'):
            indicators.append('Shell script header')

        # Check for Office document markers
        if b'Microsoft Office Word' in content or b'Microsoft Office Excel' in content:
            indicators.append('Microsoft Office document')
            # Check for macro indicators
            if b'VBA' in content or b'macro' in content.lower():
                indicators.append('Contains macros')

        # Check for script content
        try:
            text_content = content.decode('utf-8', errors='ignore')

            # Check for suspicious patterns
            for pattern in SUSPICIOUS_INDICATORS['PATTERNS']:
                if re.search(pattern, text_content, re.IGNORECASE):
                    indicators.append(f'Suspicious pattern: {pattern}')

            # Additional script checks
            script_indicators = [
                ('import os', 'OS module usage'),
                ('import sys', 'System module usage'),
                ('subprocess', 'Subprocess usage'),
                ('shell=True', 'Shell execution'),
                ('eval(', 'Evaluation of strings'),
                ('exec(', 'Code execution'),
                ('chmod +x', 'Permission modification')
            ]

            for indicator, description in script_indicators:
                if indicator in text_content:
                    indicators.append(description)

        except UnicodeDecodeError:
            # Binary file analysis
            if b'PK\x03\x04' in content[:4]:  # ZIP signature
                indicators.append('ZIP archive')
            elif b'Rar!' in content[:4]:  # RAR signature
                indicators.append('RAR archive')

        return indicators

    def _check_suspicious_indicators(self, file_path: pathlib.Path) -> Dict[str, List[str]]:
        """
        Enhanced suspicious indicator checking.

        :param file_path: Path to the file
        :return: Dictionary of detected suspicious indicators
        """
        detected = {
            'extensions': [],
            'patterns': [],
            'characteristics': []
        }

        # Check extension
        if file_path.suffix.lower() in SUSPICIOUS_INDICATORS['EXTENSIONS']:
            detected['extensions'].append(file_path.suffix.lower())

        # Read and analyze file content
        content = self._read_file_safely(file_path)
        if content:
            file_info = self._get_file_info(file_path)
            detected['characteristics'].extend(
                self._deep_content_analysis(content, file_info)
            )

        return detected

    def _hash_file(self, file_path: pathlib.Path) -> Dict[str, str]:
        """
        Calculate multiple hash types for a file.

        :param file_path: Path to the file
        :return: Dictionary of hash values
        """
        hashes = {
            'md5': hashlib.md5(),
            'sha1': hashlib.sha1(),
            'sha256': hashlib.sha256()
        }

        try:
            with open(file_path, 'rb') as f:
                while chunk := f.read(CONFIG['CHUNK_SIZE']):
                    for hasher in hashes.values():
                        hasher.update(chunk)

            return {
                name: hasher.hexdigest()
                for name, hasher in hashes.items()
            }
        except Exception:
            return {name: None for name in hashes.keys()}

    def scan_file(self, file_path: pathlib.Path) -> Dict[str, Union[str, List[str], None]]:
        """
        Enhanced file scanning with comprehensive analysis.

        :param file_path: Path to the file
        :return: Scan results dictionary
        """
        if not file_path.exists():
            return {
                'file_path': str(file_path),
                'status': 'error',
                'error': 'File not found'
            }

        result = {
            'file_path': str(file_path),
            'file_info': self._get_file_info(file_path),
            'hashes': self._hash_file(file_path),
            'suspicious_indicators': self._check_suspicious_indicators(file_path),
            'virustotal_status': None,
            'risk_level': 'low'
        }

        # Assess risk level
        if result['suspicious_indicators']['extensions'] or \
                result['suspicious_indicators']['characteristics']:
            result['risk_level'] = 'high'
        elif result['suspicious_indicators']['patterns']:
            result['risk_level'] = 'medium'

        # VirusTotal scan
        if result['hashes']['sha256']:
            vt_result = self._virustotal_scan(file_path, result['hashes']['sha256'])
            result['virustotal_status'] = vt_result
            if vt_result and vt_result.get('detected', False):
                result['risk_level'] = 'high'

        return result

    def _virustotal_scan(self, file_path: pathlib.Path, file_hash: str) -> Optional[Dict]:
        """
        Enhanced VirusTotal scanning with better error handling and rate limiting.

        :param file_path: Path to the file
        :param file_hash: SHA256 hash of the file
        :return: Scan results dictionary or None
        """
        try:
            # Check if file has been previously analyzed
            response = requests.get(
                f"{CONFIG['VIRUSTOTAL_API_URL']}/{file_hash}",
                headers=self.headers
            )

            if response.status_code == 200:
                return self._parse_vt_response(response.json())

            elif response.status_code == 404:
                # File hasn't been analyzed before, upload it
                upload_url = CONFIG['VIRUSTOTAL_API_URL']
                if file_path.stat().st_size > CONFIG['MAX_FILE_SIZE_MB'] * 1024 * 1024:
                    upload_url += '/upload_url'

                with open(file_path, 'rb') as f:
                    files = {'file': (file_path.name, f)}
                    upload_response = requests.post(
                        upload_url,
                        headers=self.headers,
                        files=files
                    )

                if upload_response.status_code == 200:
                    analysis_id = upload_response.json()['data']['id']
                    return self._poll_analysis(analysis_id)

            elif response.status_code == 429:
                # Rate limited
                time.sleep(CONFIG['RATE_LIMIT_WAIT'])
                return self._virustotal_scan(file_path, file_hash)

        except Exception:
            return None

    def _poll_analysis(self, analysis_id: str) -> Optional[Dict]:
        """
        Poll VirusTotal for analysis results.

        :param analysis_id: Analysis ID from VirusTotal
        :return: Analysis results dictionary or None
        """
        max_attempts = 10
        for _ in range(max_attempts):
            try:
                response = requests.get(
                    f"{CONFIG['VIRUSTOTAL_API_URL']}/analyses/{analysis_id}",
                    headers=self.headers
                )

                if response.status_code == 200:
                    data = response.json()['data']
                    if data['attributes']['status'] == 'completed':
                        return self._parse_vt_response(data)

                time.sleep(CONFIG['ANALYSIS_POLL_INTERVAL'])

            except Exception:
                return None

        return None

    @staticmethod
    def _parse_vt_response(response_data: Dict) -> Dict:
        """
        Parse VirusTotal response data.

        :param response_data: Response data from VirusTotal
        :return: Parsed results dictionary
        """
        stats = response_data.get('attributes', {}).get('last_analysis_stats', {})
        return {
            'detected': stats.get('malicious', 0) > 0,
            'total_scans': sum(stats.values()),
            'malicious': stats.get('malicious', 0),
            'suspicious': stats.get('suspicious', 0),
            'undetected': stats.get('undetected', 0)
        }


def get_files(path: Union[str, pathlib.Path]) -> List[pathlib.Path]:
    """
    Get list of files to scan.

    :param path: Path to file or directory
    :return: List of file paths
    """
    path = pathlib.Path(path)
    if path.is_dir():
        return [f for f in path.rglob('*') if f.is_file() and not f.name.startswith('.')]
    elif path.is_file():
        return [path]
    else:
        raise ValueError(f"Invalid path: {path}")


def main():
    """Main function to run the file scanner."""
    try:
        path = input("Enter a file path or folder path to scan: ").strip()
        files = get_files(path)

        if not files:
            print("No files found to scan.")
            return

        print(f"Found {len(files)} files to scan.")
        scanner = FileScanner()

        with concurrent.futures.ThreadPoolExecutor() as executor:
            future_to_file = {
                executor.submit(scanner.scan_file, file_path): file_path
                for file_path in files
            }

            for future in concurrent.futures.as_completed(future_to_file):
                result = future.result()
                file_path = future_to_file[future]

                print(f"\nResults for: {result['file_path']}")
                print(f"Risk Level: {result['risk_level'].upper()}")
                print(f"File Type: {result['file_info']['file_type']}")

                if result['suspicious_indicators']['characteristics']:
                    print("Suspicious Characteristics:")
                    for char in result['suspicious_indicators']['characteristics']:
                        print(f"  - {char}")

                if result['virustotal_status']:
                    print("VirusTotal Results:")
                    print(f"  - Detected: {result['virustotal_status']['detected']}")
                    print(f"  - Malicious Engines: {result['virustotal_status']['malicious']}")
                    print(f"  - Total Scans: {result['virustotal_status']['total_scans']}")

    except KeyboardInterrupt:
        print("\nScan interrupted by user.")
    except Exception as e:
        print(f"An error occurred: {str(e)}")


if __name__ == "__main__":
    main()
