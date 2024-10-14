from flask import Flask, request, jsonify
import os
import requests
import validators
import logging
from functools import wraps
from time import time

# Flask app setup
app = Flask(__name__)

# Setup logging for detailed info
logging.basicConfig(level=logging.INFO)

# Load sensitive configuration from environment variables
VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY')
WHATSAPP_API_URL = os.getenv('WHATSAPP_API_URL')

# Validate environment variables
if not VIRUSTOTAL_API_KEY or not WHATSAPP_API_URL:
    raise ValueError("Missing necessary environment variables: VIRUSTOTAL_API_KEY or WHATSAPP_API_URL")

# Rate limiting setup (basic)
API_CALLS_LIMIT = 100  # Example limit
CALLS_RESET_TIME = 60  # Time in seconds to reset the limit
user_api_calls = {}

# Decorator for rate limiting
def rate_limit(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        user_ip = request.remote_addr
        current_time = time()

        # Reset count if the reset time has passed
        if user_ip in user_api_calls and current_time - user_api_calls[user_ip]["timestamp"] > CALLS_RESET_TIME:
            user_api_calls[user_ip] = {"count": 0, "timestamp": current_time}

        # Check if user exceeded the API limit
        if user_ip not in user_api_calls:
            user_api_calls[user_ip] = {"count": 0, "timestamp": current_time}

        if user_api_calls[user_ip]["count"] >= API_CALLS_LIMIT:
            logging.warning(f"Rate limit exceeded for IP: {user_ip}")
            return jsonify({"error": "API rate limit exceeded. Please try again later."}), 429
        
        # Increment API usage count
        user_api_calls[user_ip]["count"] += 1

        return func(*args, **kwargs)
    
    return wrapper

# Helper functions
def check_url_with_virustotal(url):
    headers = {'x-apikey': VIRUSTOTAL_API_KEY}
    try:
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
    url = validators.url(text).split("?")[0]  # Strip query parameters for VirusTotal URL

    result = check_url_with_virustotal(url)

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
import signal
import sys
def graceful_shutdown(sig, frame):
    logging.info("Shutting down gracefully...")
    sys.exit(0)

signal.signal(signal.SIGINT, graceful_shutdown)
signal.signal(signal.SIGTERM, graceful_shutdown)

if __name__ == '__main__':
    app.run(port=5000, debug=True, threaded=True)
