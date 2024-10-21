from flask import Flask, request, jsonify
import os
import requests
import validators
import logging
from functools import wraps
from time import time
import signal
import sys
import re
import redis
from datetime import datetime

# Flask app setup
app = Flask(__name__)

# Setup logging for detailed and secure info
logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] - %(message)s')

# Load sensitive configuration from environment variables securely
VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY')
WHATSAPP_API_URL = os.getenv('WHATSAPP_API_URL')
REDIS_HOST = os.getenv('REDIS_HOST', 'localhost')  # Default to localhost if not set
REDIS_PORT = os.getenv('REDIS_PORT', 6379)        # Default to 6379 if not set
REDIS_DB = os.getenv('REDIS_DB', 0)               # Default to DB 0 if not set

# Validate environment variables
if not VIRUSTOTAL_API_KEY or not WHATSAPP_API_URL:
    logging.critical("Missing necessary environment variables: VIRUSTOTAL_API_KEY or WHATSAPP_API_URL")
    sys.exit(1)

# Initialize Redis connection
try:
    redis_client = redis.StrictRedis(host=REDIS_HOST, port=REDIS_PORT, db=REDIS_DB, decode_responses=True)
    logging.info(f"Connected to Redis at {REDIS_HOST}:{REDIS_PORT}")
except redis.ConnectionError as e:
    logging.critical(f"Failed to connect to Redis: {e}")
    sys.exit(1)

# Rate limiting setup (with Redis)
API_CALLS_LIMIT = 100  # Example limit
CALLS_RESET_TIME = 60  # Time in seconds to reset the limit
RATE_LIMIT_KEY_PREFIX = "api_rate_limit:"  # Redis key prefix for rate limit data

# Decorator for rate limiting
def rate_limit(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        user_ip = request.remote_addr
        current_time = time()

        # Use Redis to store rate limiting information
        rate_limit_key = f"{RATE_LIMIT_KEY_PREFIX}{user_ip}"
        user_data = redis_client.hgetall(rate_limit_key)

        if user_data:
            last_timestamp = float(user_data.get("timestamp", 0))
            call_count = int(user_data.get("count", 0))
        else:
            last_timestamp = current_time
            call_count = 0

        # Reset count if the reset time has passed
        if current_time - last_timestamp > CALLS_RESET_TIME:
            call_count = 0
            redis_client.hset(rate_limit_key, mapping={"count": 0, "timestamp": current_time})

        # Check if user exceeded the API limit
        if call_count >= API_CALLS_LIMIT:
            logging.warning(f"Rate limit exceeded for IP: {user_ip}")
            return jsonify({"error": "API rate limit exceeded. Please try again later."}), 429

        # Increment API usage count
        redis_client.hincrby(rate_limit_key, "count", 1)
        redis_client.hset(rate_limit_key, "timestamp", current_time)

        return func(*args, **kwargs)

    return wrapper

# Helper functions (same as before)
def check_url_with_virustotal(url):
    headers = {'x-apikey': VIRUSTOTAL_API_KEY}
    try:
        logging.info(f"Checking URL: {url} with VirusTotal API")
        response = requests.get(f'https://www.virustotal.com/api/v3/urls/{url}', headers=headers, timeout=10)
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        logging.error(f"Error checking URL with VirusTotal: {e}")
        return None

def format_response(result):
    if result and 'data' in result:
        attributes = result['data']['attributes']
        return {
            'malicious': attributes['last_analysis_stats']['malicious'],
            'safe': attributes['last_analysis_stats']['harmless'],
            'detection_ratio': f"{attributes['last_analysis_stats']['malicious']}/{attributes['last_analysis_stats']['total']}",
            'threat_types': attributes['last_analysis_results'],
        }
    return None

def send_whatsapp_message(user_id, message):
    payload = {"to": user_id, "body": message}
    try:
        logging.info(f"Sending message to user {user_id} on WhatsApp.")
        response = requests.post(WHATSAPP_API_URL, json=payload, timeout=10)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        logging.error(f"Error sending message to WhatsApp: {e}")
        return False
    return True

# Webhook route with rate limiting and input validation
@app.route('/webhook', methods=['POST'])
@rate_limit
def webhook():
    incoming_msg = request.get_json()

    # Validate incoming data
    if not incoming_msg or 'from' not in incoming_msg or 'text' not in incoming_msg:
        logging.warning(f"Invalid message format: {incoming_msg}")
        return jsonify({"error": "Invalid message format."}), 400

    user_id = incoming_msg['from']
    text = incoming_msg['text']

    # Check if the message contains a valid URL
    if not validators.url(text):
        send_whatsapp_message(user_id, "Please send a valid URL.")
        return '', 200

    # Sanitize URL (encode it to avoid issues with special characters)
    sanitized_url = validators.url(text).split("?")[0]  # Strip query parameters for VirusTotal URL

    # Generate URL hash for VirusTotal API (base64 encoded URL hash)
    url_hash = re.sub(r'[^A-Za-z0-9]', '', sanitized_url)  # Only alphanumeric characters
    result = check_url_with_virustotal(url_hash)

    if result:
        response_message = format_response(result)
        if response_message:
            send_whatsapp_message(user_id, f"Verification result: {response_message}")
        else:
            send_whatsapp_message(user_id, "Could not retrieve analysis results.")
    else:
        send_whatsapp_message(user_id, "Failed to check the URL with VirusTotal.")

    return '', 200

# Graceful shutdown handling
def graceful_shutdown(sig, frame):
    logging.info("Shutting down gracefully...")
    sys.exit(0)

signal.signal(signal.SIGINT, graceful_shutdown)
signal.signal(signal.SIGTERM, graceful_shutdown)

if __name__ == '__main__':
    # In production, use HTTPS by specifying cert and key files for SSL/TLS encryption
    app.run(port=5000, debug=False, threaded=True, ssl_context=('cert.pem', 'key.pem'))  # SSL context for HTTPS
