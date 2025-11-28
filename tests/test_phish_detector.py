import unittest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from backend.phish_detector import PhishDetector


class TestPhishDetectorBasics(unittest.TestCase):
    """Test basic URL validation and error handling."""

    def setUp(self):
        self.detector = PhishDetector()

    def test_invalid_url_format(self):
        """Test that invalid URLs return error."""
        invalid_urls = [
            "not a url",
            "htp://example.com",  # typo in scheme
            "example",  # no scheme or TLD
        ]
        for url in invalid_urls:
            result = self.detector.check_url(url)
            self.assertIn("error", result, f"Should error on: {url}")

    def test_url_auto_scheme(self):
        """Test that URLs without scheme get https:// prepended."""
        # These should NOT error
        result = self.detector.check_url("google.com")
        self.assertNotIn("error", result)
        self.assertIn("verdict", result)

    def test_empty_and_whitespace_urls(self):
        """Test handling of empty and whitespace URLs."""
        invalid_urls = ["", "   ", "\t", "\n"]
        for url in invalid_urls:
            result = self.detector.check_url(url)
            self.assertIn("error", result, f"Should error on whitespace: {repr(url)}")


class TestIPAddressDetection(unittest.TestCase):
    """Test IP address detection heuristic."""

    def setUp(self):
        self.detector = PhishDetector()

    def test_ip_addresses_flagged(self):
        """Test that URLs with IP addresses are flagged."""
        ip_urls = [
            "http://192.168.1.1",
            "https://10.0.0.1",
            "http://172.16.0.1",
        ]
        for url in ip_urls:
            result = self.detector.check_url(url)
            self.assertGreater(result["risk_score"], 0, f"Should flag IP URL: {url}")
            self.assertIn("IP address", result["reasons"][0])

    def test_domains_not_flagged_as_ip(self):
        """Test that normal domains are not flagged as IP."""
        domain_urls = [
            "https://google.com",
            "https://example.co.uk",
        ]
        for url in domain_urls:
            result = self.detector.check_url(url)
            # ip address check should not be in reasons
            ip_reasons = [r for r in result["reasons"] if "IP address" in r]
            self.assertEqual(len(ip_reasons), 0, f"Should not flag domain: {url}")


class TestHTTPSDetection(unittest.TestCase):
    """Test HTTPS/HTTP detection heuristic."""

    def setUp(self):
        self.detector = PhishDetector()

    def test_http_flagged_as_insecure(self):
        """Test that HTTP URLs are flagged."""
        result = self.detector.check_url("http://google.com")
        self.assertGreater(result["risk_score"], 0)
        self.assertIn("HTTPS", result["reasons"][0])

    def test_https_not_flagged(self):
        """Test that HTTPS URLs don't trigger insecure warning."""
        result = self.detector.check_url("https://google.com")
        https_reasons = [r for r in result["reasons"] if "HTTPS" in r]
        self.assertEqual(len(https_reasons), 0)


class TestAtSymbolDetection(unittest.TestCase):
    """Test @ symbol (credential redirect) detection."""

    def setUp(self):
        self.detector = PhishDetector()

    def test_at_symbol_in_url(self):
        """Test that @ symbol is detected."""
        result = self.detector.check_url("https://user@example.com")
        self.assertGreater(result["risk_score"], 0)
        self.assertIn("@", result["reasons"][0])

    def test_at_symbol_not_in_normal_url(self):
        """Test that normal URLs don't trigger @ symbol warning."""
        result = self.detector.check_url("https://google.com")
        at_reasons = [r for r in result["reasons"] if "@" in r]
        self.assertEqual(len(at_reasons), 0)


class TestURLLengthDetection(unittest.TestCase):
    """Test URL length heuristic."""

    def setUp(self):
        self.detector = PhishDetector()

    def test_very_long_url_flagged(self):
        """Test that very long URLs are flagged."""
        long_url = "https://example.com/" + "a" * 100
        result = self.detector.check_url(long_url)
        self.assertGreater(result["risk_score"], 0)
        self.assertIn("long", result["reasons"][0].lower())

    def test_normal_length_url_not_flagged(self):
        """Test that normal URLs aren't flagged for length."""
        result = self.detector.check_url("https://google.com")
        length_reasons = [r for r in result["reasons"] if "long" in r.lower()]
        self.assertEqual(len(length_reasons), 0)


class TestSubdomainDetection(unittest.TestCase):
    """Test excessive subdomain detection."""

    def setUp(self):
        self.detector = PhishDetector()

    def test_excessive_subdomains_flagged(self):
        """Test that excessive subdomains are flagged."""
        result = self.detector.check_url(
            "https://sub1.sub2.sub3.example.com"
        )
        self.assertGreater(result["risk_score"], 0)
        self.assertIn("subdomain", result["reasons"][0].lower())

    def test_normal_subdomains_not_flagged(self):
        """Test that normal subdomains (www, mail) aren't flagged."""
        result = self.detector.check_url("https://www.google.com")
        subdomain_reasons = [r for r in result["reasons"] if "subdomain" in r.lower()]
        self.assertEqual(len(subdomain_reasons), 0)


class TestSuspiciousKeywords(unittest.TestCase):
    """Test suspicious keyword detection."""

    def setUp(self):
        self.detector = PhishDetector()

    def test_suspicious_keywords_flagged(self):
        """Test that URLs with suspicious keywords are flagged."""
        result = self.detector.check_url("https://verify-account-login.com")
        self.assertGreater(result["risk_score"], 0)
        self.assertIn("keyword", result["reasons"][0].lower())

    def test_legitimate_keywords_not_flagged(self):
        """Test that legitimate keywords don't trigger warning."""
        result = self.detector.check_url("https://google.com")
        keyword_reasons = [r for r in result["reasons"] if "keyword" in r.lower()]
        self.assertEqual(len(keyword_reasons), 0)


class TestVerdictThresholds(unittest.TestCase):
    """Test that verdicts are assigned correctly based on score."""

    def setUp(self):
        self.detector = PhishDetector()

    def test_low_risk_verdict(self):
        """Test Low verdict assignment."""
        result = self.detector.check_url("https://google.com")
        # google.com should be Low risk
        self.assertEqual(result["verdict"], "Low")

    def test_verdict_consistency(self):
        """Test that verdict is one of the valid options."""
        urls = [
            "https://google.com",
            "http://example.com",
            "https://user@malicious.com",
            "https://192.168.1.1",
        ]
        valid_verdicts = ["Low", "Medium", "High", "Critical"]
        for url in urls:
            result = self.detector.check_url(url)
            self.assertIn(result["verdict"], valid_verdicts)

    def test_score_in_valid_range(self):
        """Test that risk_score is always 0-100."""
        urls = [
            "https://google.com",
            "http://192.168.1.1",
            "https://verify-login-secure-account.com",
        ]
        for url in urls:
            result = self.detector.check_url(url)
            self.assertGreaterEqual(result["risk_score"], 0)
            self.assertLessEqual(result["risk_score"], 100)


class TestResponseFormat(unittest.TestCase):
    """Test response format consistency."""

    def setUp(self):
        self.detector = PhishDetector()

    def test_success_response_has_required_fields(self):
        """Test that successful response has all required fields."""
        result = self.detector.check_url("https://google.com")
        required_fields = ["risk_score", "verdict", "reasons", "details"]
        for field in required_fields:
            self.assertIn(field, result, f"Missing field: {field}")

    def test_error_response_has_error_field(self):
        """Test that error response has error field."""
        result = self.detector.check_url("invalid")
        self.assertIn("error", result)

    def test_details_contains_url_info(self):
        """Test that details object contains URL components."""
        result = self.detector.check_url("https://example.com/path?query=1")
        details = result.get("details", {})
        expected_keys = ["scheme", "domain", "path", "query"]
        for key in expected_keys:
            self.assertIn(key, details, f"Missing detail: {key}")


class TestRealWorldURLs(unittest.TestCase):
    """Test with realistic URLs to ensure reasonable verdicts."""

    def setUp(self):
        self.detector = PhishDetector()

    def test_legitimate_urls_low_risk(self):
        """Test that known legitimate sites get Low risk."""
        legit_urls = [
            "https://google.com",
            "https://github.com",
            "https://stackoverflow.com",
        ]
        for url in legit_urls:
            result = self.detector.check_url(url)
            self.assertIn(
                result["verdict"],
                ["Low", "Medium"],
                f"Legitimate URL got too high verdict: {url}",
            )

    def test_suspicious_urls_higher_risk(self):
        """Test that obviously suspicious URLs get flagged."""
        suspicious_urls = [
            "http://192.168.1.1:8080/update",
            "https://verify-paypal-account-confirm.com",
            "https://user:pass@example.com",
        ]
        for url in suspicious_urls:
            result = self.detector.check_url(url)
            # These should be at least Medium or higher
            self.assertNotEqual(
                result["verdict"], "Low", f"Suspicious URL not flagged: {url}"
            )


if __name__ == "__main__":
    unittest.main()
