import re
from urllib.parse import urlparse
from datetime import datetime
import whois
import validators
from .logger import get_logger
from .config import SUSPICIOUS_KEYWORDS, RISK_THRESHOLDS, URL_ANALYSIS, VERDICT_THRESHOLDS, EXTERNAL_DBS, DOMAIN_AGE
from .external_dbs import VirusTotalChecker

logger = get_logger()


class PhishDetector:
    """Detects potential phishing URLs using heuristics."""

    def __init__(self):
        self.vt_checker = VirusTotalChecker() if EXTERNAL_DBS.get('virustotal_enabled') else None
        self.domain_age_checker = DomainAgeChecker()

# steps we should be checking for url
# Normalize/Validate URL, Check for IP/HTTP use, @ symbol redirects, url length, subdomains,
# check keywords, hyphens, determine and compile score and results.

    def check_input(self, url):
        """
        Validate and normalize URL input.

        Args:
            url: URL string to validate

        Returns:
            tuple: (is_valid: bool, normalized_url: str or error_msg: str)
        """
        # type/empty check
        if not isinstance(url, str):
            return False, "URL must be a string"

        url = url.strip()
        if not url:
            return False, "URL cannot be empty"

        # check and or add http/https scheme
        if "://" in url:
            scheme = url.split("://")[0].lower()
            if scheme not in ("http", "https"):
                return False, f"Invalid URL scheme: {scheme}. Only http and https are supported."
        else:
            url = "https://" + url

        # standard validation
        if validators.url(url):
            return True, url

        # temp fallback: check for @ symbol based redirection
        if "@" in url:
            scheme_end = url.find("://") + 3
            at_pos = url.find("@")
            if scheme_end < at_pos:
                base_url = url[:scheme_end] + url[at_pos + 1 :]
                if validators.url(base_url):
                    return True, url

        # basic structure for worse case
        if "://" in url and "." in url:
            return True, url

        return False, "Invalid URL format"

    def check_url(self, url):
        """
        Analyze a URL and return risk score, verdict, and reasons.

        Args:
            url: URL string to analyze

        Returns:
            dict: {
                'risk_score': 0-100,
                'verdict': 'Low'|'Medium'|'High'|'Critical',
                'reasons': [list of strings],
                'details': {metadata}
            }
            or
            dict: {'error': 'error message'} on invalid input
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

        # check input call
        is_valid, result = self.check_input(url)
        if not is_valid:
            return {"error": result}

        url = result
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
        at_in_netloc = "@" in parsed.netloc
        at_in_url = "@" in url
        logger.info(f"@ symbol check - in netloc: {at_in_netloc}, in url: {at_in_url}")
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

        # Domain age check
        domain_age_info = self.domain_age_checker.get_domain_age(url)
        details["domain_age"] = domain_age_info

        if domain_age_info.get('age_days') is not None:
            age_days = domain_age_info['age_days']
            is_suspicious, severity = self.domain_age_checker.is_suspicious_age(age_days)

            if is_suspicious:
                if severity == 'very_new':
                    score += RISK_THRESHOLDS['very_new_domain']
                    reasons.append(f"Domain registered very recently ({age_days} days ago)")
                elif severity == 'new':
                    score += RISK_THRESHOLDS['new_domain']
                    reasons.append(f"Domain registered recently ({age_days} days ago)")

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

        # simple info use just to keep track of palatable log output in log file
        logger.info(f"Analysis complete: {parsed.netloc} - Verdict: {verdict} (score: {score})")

        # Check external phishing databases
        ext_db_details = {"virustotal": None}
        if self.vt_checker and self.vt_checker.enabled:
            vt_result = self.vt_checker.check(url)
            ext_db_details["virustotal"] = vt_result

            if vt_result.get('detected'):
                # External DB detected phishing - boost score significantly
                vt_score = vt_result.get('score', 0)
                score += min(40, vt_score // 2)  # Add half of VT score (max 40 points)
                reasons.insert(0, f"⚠️  Flagged by VirusTotal: {vt_result.get('details', '')}")
                logger.warning(f"VirusTotal detected phishing for {url}: {vt_result.get('details')}")

        # Cap score at 100 after external DB boost
        score = min(100, max(0, score))

        # Recalculate verdict based on updated score
        if score <= VERDICT_THRESHOLDS['low']:
            verdict = "Low"
        elif score <= VERDICT_THRESHOLDS['medium']:
            verdict = "Medium"
        elif score <= VERDICT_THRESHOLDS['high']:
            verdict = "High"
        else:
            verdict = "Critical"

        # Store parsed URL details
        domain = parsed.netloc.split(":")[0]
        details.update(
            {
                "scheme": parsed.scheme,
                "domain": domain,
                "path": parsed.path or "/",
                "query": parsed.query or "none",
                "external_dbs": ext_db_details,
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

class DomainAgeChecker:
    """Check domain age and registration details."""

    @staticmethod
    def get_domain_age(url):
        """
        Calculate domain age in days.

        Args:
            url: Full URL to check

        Returns:
            dict: {
                'age_days': int or None,
                'creation_date': str or None,
                'error': str or None
            }
        """
        try:
            parsed = urlparse(url)
            domain = parsed.netloc.split(":")[0]

            # query WHOIS data
            whois_data = whois.whois(domain)

            # isolate date
            creation_date = whois_data.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]

            if not creation_date:
                return {'age_days': None, 'creation_date': None, 'error': 'No creation date found'}

            # calc age
            now = datetime.now()
            if creation_date.tzinfo is not None:
                now = datetime.now(creation_date.tzinfo)

            age_days = (now - creation_date).days

            return {
                'age_days': age_days,
                'creation_date': creation_date.isoformat(),
                'error': None
            }

        except whois.parser.PywhoisError as e:
            logger.warning(f"WHOIS lookup failed for {url}: {e}")
            return {'age_days': None, 'creation_date': None, 'error': 'WHOIS lookup failed'}
        except Exception as e:
            logger.error(f"Domain age check error for {url}: {e}")
            return {'age_days': None, 'creation_date': None, 'error': str(e)}

    @staticmethod
    def is_suspicious_age(age_days):
        """
        Check if domain age is suspiciously young.

        Args:
            age_days: Domain age in days

        Returns:
            tuple: (is_suspicious: bool, severity: str)
                severity: 'very_new' or 'new' or None
        """
        if age_days is None:
            return False, None

        if age_days <= DOMAIN_AGE['max_days_very_suspicious']:
            return True, 'very_new'
        elif age_days <= DOMAIN_AGE['max_days_suspicious']:
            return True, 'new'

        return False, None

