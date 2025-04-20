import time
import requests
import threading
from pathlib import Path
from urllib3.util import Retry
from requests.adapters import HTTPAdapter


class VirusTotalEngine:
    def __init__(self):
        self.api_key = "859514a9fdf21fdfe3928d40b0a114c0bb76b626785d8847ef2adbb8f5c4e036"
        self.headers = {
            "x-apikey": self.api_key,
            "User-Agent": "VirusTotal Scanner v1.0",
            "Accept-Charset": "UTF-8"
        }
        # Fixed the typo in the URL from "htstps" to "https"
        self.virustotal_api_url = "https://www.virustotal.com/api/v3/files"
        self.max_file_size = 32 * 1024 * 1024
        self.session = self._create_session()
        self.request_semaphore = threading.Semaphore(4)

    def _create_session(self):
        session = requests.Session()
        retry = Retry(total=3, backoff_factor=1)
        adapter = HTTPAdapter(max_retries=retry)
        session.mount("https://", adapter)
        return session

    def scan_with_virustotal(self, file_path, file_hash):
        with self.request_semaphore:
            try:
                print(f"\nChecking VirusTotal for {Path(file_path).name}...", end='', flush=True)
                response = self.session.get(
                    f"{self.virustotal_api_url}/{file_hash}",
                    headers=self.headers,
                    timeout=30
                )

                if response.status_code == 200:
                    result = response.json()
                    stats = result.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                    print("\rVirusTotal scan complete!")
                    return self._process_results(stats)

                if Path(file_path).stat().st_size <= self.max_file_size:
                    print("\rUploading to VirusTotal...", end='', flush=True)
                    upload_response = self._upload_file(file_path)

                    if upload_response and 'data' in upload_response:
                        return self._poll_analysis(upload_response['data']['id'])

                time.sleep(1)  # Rate limiting
                return {'status': 'Error', 'message': 'File size exceeds limit'}

            except KeyboardInterrupt:
                print("\nScan interrupted by user")
                return {'status': 'Interrupted'}
            except Exception as e:
                print(f"\nError during scan: {e}")
                return {'status': 'Error', 'message': str(e)}

    def _upload_file(self, file_path):
        try:
            with open(file_path, 'rb') as f:
                files = {'file': (Path(file_path).name.encode('utf-8'), f)}
                response = self.session.post(
                    self.virustotal_api_url,
                    headers=self.headers,
                    files=files,
                    timeout=60
                )
            time.sleep(1)
            return response.json() if response.status_code == 200 else None
        except Exception:
            return None

    def _poll_analysis(self, analysis_id):
        try:
            for i in range(60):
                print(f"\rWaiting for results ({i + 1}/60)...", end='', flush=True)
                response = self.session.get(
                    f"https://www.virustotal.com/api/v3/analyses/{analysis_id}",
                    headers=self.headers,
                    timeout=30
                )

                if response.status_code == 200:
                    result = response.json()
                    if result['data']['attributes']['status'] == 'completed':
                        print("\rVirusTotal scan complete!")
                        return self._process_results(result['data']['attributes']['stats'])
                time.sleep(5)
            return {'status': 'Timeout'}
        except KeyboardInterrupt:
            raise
        except Exception:
            return {'status': 'Error during analysis'}

    def _process_results(self, stats):
        malicious = stats.get('malicious', 0)
        total = sum(stats.values()) if stats else 0
        return {
            'malware_detected': malicious > 0,
            'detection_rate': (malicious / total * 100) if total > 0 else 0
        }