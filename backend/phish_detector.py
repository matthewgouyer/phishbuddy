import re
from urllib.parse import urlparse
import validators
from .logger import get_logger

logger = get_logger()


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

        def has_ip_in_host(parsed):
            """Check if URL host is a raw IP address."""
            host = parsed.netloc.split(":")[0]
            ip_pattern = r"^\d{1,3}(?:\.\d{1,3}){3}$"
            return bool(re.match(ip_pattern, host))

        def count_subdomains(parsed):
            """Count number of subdomain levels."""
            host = parsed.netloc.split(":")[0]
            parts = host.split(".")
            # Subtract 2 for base domain (e.g., example.com = 0 subdomains)
            return max(0, len(parts) - 2)

        def find_suspicious_keywords(parsed):
            """Find suspicious keywords in URL."""
            url_text = (parsed.netloc + parsed.path + (parsed.query or "")).lower()
            found = [k for k in self.SUSPICIOUS_KEYWORDS if k in url_text]
            return found

        if not url.startswith(("http://", "https://")):
            url = "https://" + url

        if not validators.url(url):
            return {"error": "Invalid URL format"}

        parsed = urlparse(url)
        score = 0
        reasons = []
        details = {}

        # simple info use just to keep track of palletable log output in log file
        logger.info(f"Starting phishing check for URL: {parsed.netloc}")

        # IP address check
        if has_ip_in_host(parsed):
            score += 30
            reasons.append("URL uses raw IP address instead of domain name")

        # Insecure scheme check
        if parsed.scheme != "https":
            score += 20
            reasons.append("Not using HTTPS (insecure connection)")

        # @ symbol check
        if "@" in parsed.netloc or "@" in url:
            score += 25
            reasons.append(
                'Contains "@" symbol (often used for credential-based redirects)'
            )

        # URL length check
        if len(url) > 75:
            score += 10
            reasons.append("Very long URL (may hide true destination)")

        # subdomain count check
        subdomains = count_subdomains(parsed)
        details["subdomain_count"] = subdomains
        if subdomains >= 3:
            score += 10
            reasons.append(f"Excessive subdomains ({subdomains} levels)")

        # sus keywords check
        keywords = find_suspicious_keywords(parsed)
        details["suspicious_keywords"] = keywords
        if keywords:
            score += min(40, 10 * len(keywords))
            reasons.append(f'Contains suspicious keywords: {", ".join(keywords)}')

        # Percent encoding check
        if "%" in parsed.path or "%" in (parsed.query or ""):
            score += 7
            reasons.append(
                "URL contains percent-encoded characters (may hide malicious intent)"
            )

        # multiple hyphens in domain
        domain = parsed.netloc.split(":")[0]
        if domain.count("-") >= 2:
            score += 5
            reasons.append("Multiple hyphens in domain (common in lookalike domains)")

        # Cap score at 100
        score = min(100, max(0, score))

        # Determine verdict (might need to adjust threshold discrepancies before compare to DBS)
        if score <= 30:
            verdict = "Low"
        elif score <= 60:
            verdict = "Medium"
        elif score <= 85:
            verdict = "High"
        else:
            verdict = "Critical"

        # simple info use just to keep track of palletable log output in log file
        logger.info(f"Analysis complete: {parsed.netloc} - Verdict: {verdict} (score: {score})")

        # Store parsed URL details
        domain = parsed.netloc.split(":")[0]
        details.update(
            {
                "scheme": parsed.scheme,
                "domain": domain,
                "path": parsed.path or "/",
                "query": parsed.query or "none",
            }
        )

        return {
            "risk_score": score,
            "verdict": verdict,
            "reasons": reasons
            if reasons
            else ["No major phishing indicators detected"],
            "details": details,
        }
