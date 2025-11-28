# simple backend CLI entry point for testing

# type in terminal to test: python -m backend "https://example.com"

import sys
import json
from .phish_detector import PhishDetector
from .logger import get_logger

logger = get_logger()


def main(argv=None):
    argv = argv if argv is not None else sys.argv[1:]
    if not argv:
        logger.error("No URL inputted")
        print("Usage: python -m backend <url>", file=sys.stderr)
        sys.exit(2)
    url = argv[0].strip()
    logger.info(f"CLI check initiated for URL: {url}")
    detector = PhishDetector()
    result = detector.check_url(url)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
