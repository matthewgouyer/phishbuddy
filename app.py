from flask import Flask, render_template, request, jsonify
from backend.phish_detector import PhishDetector
from backend.logger import get_logger
import os
from dotenv import load_dotenv

load_dotenv()

logger = get_logger()

# laying down ground work for eventual frontend work
app = Flask(__name__, template_folder='frontend/templates', static_folder='frontend/static')
detector = PhishDetector()


@app.route('/')
def index():
    # serve main page for when we have frontend
    return render_template('index.html')


@app.route('/api/check', methods=['POST'])
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
    host = '127.0.0.1'
    port = 5000
    logger.info(f"Starting PhishBuddy @ http://{host}:{port}")
    app.run(host=host, port=port, debug=True)
