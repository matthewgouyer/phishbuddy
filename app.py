from flask import Flask, render_template, request, jsonify
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from backend.phish_detector import PhishDetector
from backend.logger import get_logger
from backend.config import FLASK, RATE_LIMITING
from dotenv import load_dotenv

load_dotenv()

logger = get_logger()

# laying down ground work for eventual frontend work
app = Flask(__name__, template_folder='frontend/templates', static_folder='frontend/static')
detector = PhishDetector()

# init rate limiter
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=[RATE_LIMITING['limit']] if RATE_LIMITING['enabled'] else [],
)


@app.route('/')
def index():
    # serve main page for when we have frontend
    return render_template('index.html')


@app.route('/api/check', methods=['POST'])
@limiter.limit(RATE_LIMITING['limit']) if RATE_LIMITING['enabled'] else lambda f: f
def check_url():
    # api endpoint to check a url
    data = request.get_json()

    if not data or not data.get('url'):
        return jsonify({'error': 'Missing "url" field'}), 400

    url = data['url'].strip()
    logger.info(f"API request from {request.remote_addr}: {url}")
    result = detector.check_url(url)

    if 'error' in result:
        logger.warning(f"Invalid URL: {url}")
        return jsonify(result), 400

    # add URL to result for response
    result['url'] = url
    logger.info(f"Analysis result for {url}: {result['verdict']}")
    return jsonify(result), 200


if __name__ == '__main__':
    host = FLASK['host']
    port = FLASK['port']
    logger.info(f"Starting PhishBuddy @ http://{host}:{port}")
    app.run(host=host, port=port, debug=FLASK['debug'])
