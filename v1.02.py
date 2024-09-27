from flask import Flask, request, jsonify
import os
import requests
import validators
import logging

app = Flask(__name__)

# Setup logging
logging.basicConfig(level=logging.INFO)

# Load sensitive configuration from environment variables
VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY')
WHATSAPP_API_URL = os.getenv('WHATSAPP_API_URL')

def check_url_with_virustotal(url):
    headers = {
        'x-apikey': VIRUSTOTAL_API_KEY,
    }
    try:
        response = requests.get(f'https://www.virustotal.com/api/v3/urls/{url}', headers=headers)
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

@app.route('/webhook', methods=['POST'])
def webhook():
    incoming_msg = request.json
    user_id = incoming_msg.get('from')
    text = incoming_msg.get('text')

    if not user_id or not text:
        return jsonify({"error": "Invalid message format."}), 400

    if validators.url(text):  # Validate the URL
        url = text
        result = check_url_with_virustotal(url)

        if result:
            response_message = format_response(result)
            if response_message:
                send_whatsapp_message(user_id, f"Verification result: {response_message}")
            else:
                send_whatsapp_message(user_id, "Could not retrieve analysis results.")
        else:
            send_whatsapp_message(user_id, "Failed to check the URL with VirusTotal.")
    else:
        send_whatsapp_message(user_id, "Please send a valid URL.")

    return '', 200

def send_whatsapp_message(user_id, message):
    payload = {
        "to": user_id,
        "body": message,
    }
    try:
        response = requests.post(WHATSAPP_API_URL, json=payload)
        response.raise_for_status()
    except requests.exceptions.RequestException as e:
        logging.error(f"Error sending message to WhatsApp: {e}")

if __name__ == '__main__':
    app.run(port=5000)
