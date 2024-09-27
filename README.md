# WhatsApp Malicious Link Detection Bot:

## Overview
This is a Flask application that serves as a WhatsApp bot to check URLs against the VirusTotal API for potential malicious content. It sends the analysis results back to users via WhatsApp.

## Features
- Validates incoming URLs.
- Checks URLs against VirusTotal for malicious content.
- Sends analysis results back to users through WhatsApp.

## Requirements
- Python 3.x
- Flask
- requests
- validators

## Setup

1. **Clone the repository:**
   ```bash
   git clone https://github.com/your-repo/whatsapp-malicious-link-bot.git
   cd whatsapp-malicious-link-bot

Additional Notes:

    Make sure to install the validators package if you haven't done so:

    bash

pip install validators

Set the environment variables VIRUSTOTAL_API_KEY and WHATSAPP_API_URL before running the app. You can do this in your terminal like so:

bash

export VIRUSTOTAL_API_KEY='your_virustotal_api_key'
export WHATSAPP_API_URL='https://api.twilio.com/...'
Install dependencies:

bash

pip install Flask requests validators

Set up environment variables: Create a .env file or set the environment variables in your terminal:

bash

export VIRUSTOTAL_API_KEY='your_virustotal_api_key'
export WHATSAPP_API_URL='https://api.twilio.com/...'

Run the application:

bash

    python app.py

Usage

    Deploy the bot on a server with a public URL to receive webhook requests.
    Connect your WhatsApp account to the bot.
    Send a URL to the bot in WhatsApp to receive a malicious link check.

Error Handling

    The bot logs errors for both VirusTotal and WhatsApp API calls. Check logs for troubleshooting.

Contributing

If you would like to contribute, please fork the repository and submit a pull request.
License

This project is licensed under the MIT License.

Ensure your Flask app is running in an environment that can access the internet for API calls.
