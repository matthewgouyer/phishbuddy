"""
External phishing database checkers.

Integrates with VirusTotal and other phishing databases.
"""

import requests
from .logger import get_logger
from .config import EXTERNAL_DBS

logger = get_logger()


class VirusTotalChecker:
    """Check URLs against VirusTotal database."""

    def __init__(self, api_key=None):
        self.api_key = api_key or EXTERNAL_DBS.get('virustotal_api_key')
        self.enabled = bool(self.api_key)
        self.base_url = "https://www.virustotal.com/api/v3/urls"

    def check(self, url):
        if not self.enabled:
            return {'detected': False, 'score': 0, 'details': 'VirusTotal disabled', 'error': None}

        try:
            headers = {"x-apikey": self.api_key}
            payload = {"url": url}

            # url submission
            response = requests.post(
                self.base_url,
                data=payload,
                headers=headers,
                timeout=10
            )

            if response.status_code == 401:
                return {'detected': False, 'score': 0, 'details': '', 'error': 'Invalid VirusTotal API key'}

            if response.status_code != 200:
                logger.warning(f"VirusTotal API error: {response.status_code}")
                return {'detected': False, 'score': 0, 'details': '', 'error': None}

            data = response.json()
            url_id = data.get('data', {}).get('id')

            if not url_id:
                return {'detected': False, 'score': 0, 'details': '', 'error': None}

            # get analysis results
            analysis_response = requests.get(
                f"{self.base_url}/{url_id}",
                headers=headers,
                timeout=10
            )

            if analysis_response.status_code != 200:
                return {'detected': False, 'score': 0, 'details': '', 'error': None}

            analysis_data = analysis_response.json()
            stats = analysis_data.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})

            malicious_count = stats.get('malicious', 0)
            suspicious_count = stats.get('suspicious', 0)
            undetected_count = stats.get('undetected', 0)
            total = malicious_count + suspicious_count + undetected_count + stats.get('harmless', 0)

            # Calculate score (0-100)
            if total == 0:
                score = 0
            else:
                score = int(((malicious_count * 2 + suspicious_count) / total) * 100)

            detected = malicious_count > 0 or suspicious_count > 0

            return {
                'detected': detected,
                'score': score,
                'details': f"Malicious: {malicious_count}, Suspicious: {suspicious_count}",
                'error': None
            }

        except requests.Timeout:
            logger.warning(f"VirusTotal timeout for {url}")
            return {'detected': False, 'score': 0, 'details': '', 'error': 'VirusTotal timeout'}
        except Exception as e:
            logger.error(f"VirusTotal check error: {e}")
            return {'detected': False, 'score': 0, 'details': '', 'error': str(e)}

