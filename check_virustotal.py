import requests

class VirusTotalEngine:
    """Engine to integrate with VirusTotal API for file hash scanning."""

    def __init__(self, api_key):
        self.api_key = api_key
        self.headers = {"x-apikey": api_key}
        self.virustotal_api_url = "https://www.virustotal.com/api/v3/files"
        self.max_file_size = 32 * 1024 * 1024  # 32 MB

    def scan_with_virustotal(self, file_path, file_hash):
        """Submit file to VirusTotal for scanning."""
        try:
            # Check if file was previously scanned
            response = requests.get(
                f"{self.virustotal_api_url}/{file_hash}",
                headers=self.headers
            )

            if response.status_code == 200:
                result = response.json()
                stats = result.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
                return {
                    'malware_detected': stats.get('malicious', 0) > 0,
                    'detection_rate': (stats.get('malicious', 0) / sum(stats.values())) * 100 if sum(
                        stats.values()) > 0 else 0
                }

            # If file hasn't been scanned before
            if file_path.stat().st_size <= self.max_file_size:
                with open(file_path, 'rb') as f:
                    files = {'file': (file_path.name, f)}
                    response = requests.post(
                        self.virustotal_api_url,
                        headers=self.headers,
                        files=files
                    )
                if response.status_code == 200:
                    return {'status': 'File submitted for scanning'}

        except Exception as e:
            print(f"Error during VirusTotal scan: {e}")
            return None
