from flask import Flask, request
import requests

app = Flask(__name__)

VIRUSTOTAL_API_KEY = 'your_virustotal_api_key'
WHATSAPP_API_URL = 'https://api.twilio.com/...'

def check_url_with_virustotal(url):
    headers = {
        'x-apikey': VIRUSTOTAL_API_KEY,
    }
    response = requests.get(f'https://www.virustotal.com/api/v3/urls/{url}', headers=headers)
    return response.json()

def format_response(result):
    if result.get('data'):
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
    user_id = incoming_msg['from']
    text = incoming_msg['text']

    if text.startswith('http'):
        url = text
        result = check_url_with_virustotal(url)
        response_message = format_response(result)
        # Send response back to user
        send_whatsapp_message(user_id, response_message)
    else:
        # Handle invalid input
        send_whatsapp_message(user_id, "Please send a valid URL.")

    return '', 200

def send_whatsapp_message(user_id, response_message):
    message = f"Verification result: {response_message}"
    # Twilio API call to send message
    requests.post(WHATSAPP_API_URL, data={"to": user_id, "body": message})

if __name__ == '__main__':
    app.run(port=5000)
