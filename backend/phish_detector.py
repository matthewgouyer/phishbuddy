import re
from urllib.parse import urlparse
import validators
from .logger import get_logger
from .config import SUSPICIOUS_KEYWORDS, RISK_THRESHOLDS, URL_ANALYSIS, VERDICT_THRESHOLDS

logger = get_logger()


class PhishDetector:
    """Detects potential phishing URLs using heuristics."""

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
            found = [k for k in SUSPICIOUS_KEYWORDS if k in url_text]
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
            score += RISK_THRESHOLDS['ip_address']
            reasons.append("URL uses raw IP address instead of domain name")

        # Insecure scheme check
        if parsed.scheme != "https":
            score += RISK_THRESHOLDS['insecure_scheme']
            reasons.append("Not using HTTPS (insecure connection)")

        # @ symbol check
        if "@" in parsed.netloc or "@" in url:
            score += RISK_THRESHOLDS['at_symbol']
            reasons.append(
                'Contains "@" symbol (often used for credential-based redirects)'
            )

        # URL length check
        if len(url) > URL_ANALYSIS['max_length']:
            score += RISK_THRESHOLDS['long_url']
            reasons.append("Very long URL (may hide true destination)")

        # subdomain count check
        subdomains = count_subdomains(parsed)
        details["subdomain_count"] = subdomains
        if subdomains >= URL_ANALYSIS['min_subdomains_suspicious']:
            score += RISK_THRESHOLDS['excessive_subdomains']
            reasons.append(f"Excessive subdomains ({subdomains} levels)")

        # sus keywords check
        keywords = find_suspicious_keywords(parsed)
        details["suspicious_keywords"] = keywords
        if keywords:
            score += min(40, RISK_THRESHOLDS['suspicious_keywords'] * len(keywords))
            reasons.append(f'Contains suspicious keywords: {", ".join(keywords)}')

        # Percent encoding check
        if "%" in parsed.path or "%" in (parsed.query or ""):
            score += RISK_THRESHOLDS['percent_encoding']
            reasons.append(
                "URL contains percent-encoded characters (may hide malicious intent)"
            )

        # multiple hyphens in domain
        domain = parsed.netloc.split(":")[0]
        if domain.count("-") >= URL_ANALYSIS['min_hyphens_suspicious']:
            score += RISK_THRESHOLDS['multiple_hyphens']
            reasons.append("Multiple hyphens in domain (common in lookalike domains)")

        # Cap score at 100
        score = min(100, max(0, score))

        # Determine verdict based on score thresholds
        if score <= VERDICT_THRESHOLDS['low']:
            verdict = "Low"
        elif score <= VERDICT_THRESHOLDS['medium']:
            verdict = "Medium"
        elif score <= VERDICT_THRESHOLDS['high']:
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
