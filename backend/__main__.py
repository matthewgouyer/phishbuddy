# simple backend CLI entry point for API testing atm

# to test api functionality and or multiple urls at once: python -m backend --api "url1" "url2" "url3"

import sys
import json
from .logger import get_logger

logger = get_logger()

def main(argv=None):
    # parse cl args
    argv = argv if argv is not None else sys.argv[1:]

    if not argv:
        print("Usage: python -m backend <url> [url2] [url3] ...", file=sys.stderr)
        sys.exit(2)

    # import our app for testing
    from app import app

    # test each URL through the API
    with app.test_client() as client:
        for url in argv:
            print(f"Testing: {url}")
            print("-" * 70)
            try:
                # send POST request to /api/check endpoint
                response = client.post('/api/check', json={'url': url}, content_type='application/json')
                print(f"Status: {response.status_code}")
                print(json.dumps(response.get_json(), indent=2))
                print()
            except Exception as e:
                logger.error(f"Error testing {url}: {e}")
                print(f"Error: {e}\n")


if __name__ == "__main__":
    main()
