import re
from urllib.parse import urlparse
import validators


class PhishDetector:
    """Detects potential phishing URLs using heuristics."""

    # temp list of suspicious keywords
    SUSPICIOUS_KEYWORDS = [
        'login', 'signin', 'secure', 'account', 'update', 'verify',
        'bank', 'confirm', 'password', 'ebay', 'paypal', 'appleid',
        'billing', 'wp-admin', 'auth', 'checkout'
    ]

    def __init__(self):
        pass

# steps we should be checking for url
# Normalize/Validate URL, Check for IP/HTTP use, @ symbol redirects, url length, subdomains,
# check keywords, hypens, determine and compile score and results.
    def check_url(self, url):
        """
        Analyze a URL and return risk score, verdict, and reasons.

        Returns:
            dict: {
                'risk_score': 0-100,
                'verdict': 'Low'|'Medium'|'High'|'Critical',
                'reasons': [list of strings],
                'details': {metadata}
            }
        """
        if not url.startswith(('http://', 'https://')):
            url = 'https://' + url

        if not validators.url(url):
            return {'error': 'Invalid URL format'}

        parsed = urlparse(url)
        score = 0
        reasons = []
        details = {}

        # heuristic checks go here


        # =====================================


        # scoring

        # Cap score at 100
        score = min(100, max(0, score))

        # Determine verdict
        if score <= 30:
            verdict = 'Low'
        elif score <= 60:
            verdict = 'Medium'
        elif score <= 85:
            verdict = 'High'
        else:
            verdict = 'Critical'

        # Store parsed URL details
        domain = parsed.netloc.split(':')[0]
        details.update({
            'scheme': parsed.scheme,
            'domain': domain,
            'path': parsed.path or '/',
            'query': parsed.query or 'none'
        })

        return {
            'risk_score': score,
            'verdict': verdict,
            'reasons': reasons if reasons else ['No major phishing indicators detected'],
            'details': details
        }
