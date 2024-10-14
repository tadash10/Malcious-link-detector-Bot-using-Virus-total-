# WhatsApp Malicious Link Detection Bot:

## Overview 
This is a Flask application that serves as a WhatsApp bot to check URLs against the VirusTotal API for potential malicious content. It sends the analysis results back to users via WhatsApp.This is a test script use under your own risk  and discretion :

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
Explanation of Improvements:
1. Rate Limiting:

    The rate_limit decorator has been implemented to prevent abuse of the API. It limits the number of requests per user (based on their IP address). If the user exceeds the limit, they get a 429 Too Many Requests response.
    The limit can be configured via API_CALLS_LIMIT and the reset time can be adjusted with CALLS_RESET_TIME.
    You can adapt this rate limiting to a more advanced solution (e.g., using a Redis cache for better persistence and scalability).

2. API Key and Environment Variable Validation:

    We added a check to ensure that VIRUSTOTAL_API_KEY and WHATSAPP_API_URL are present in the environment variables at the start. If they are missing, the script will raise an exception.

3. Input Validation and Sanitization:

    The incoming webhook data is validated to ensure that both from (user ID) and text (message) fields exist.
    The URL is sanitized by stripping query parameters before sending it to the VirusTotal API, which helps avoid issues with special characters.

4. Error Handling:

    Proper exception handling with requests.exceptions.RequestException ensures that if any HTTP request fails (for VirusTotal or WhatsApp), an error message is logged, and the user is informed accordingly.
    Timeouts are applied to both external API calls (requests.get and requests.post) to avoid long delays.

5. Graceful Shutdown:

    We added a signal handler (graceful_shutdown) to handle termination signals (SIGINT, SIGTERM), ensuring the application shuts down gracefully, logging the shutdown process.

6. Logging Enhancements:

    Logging has been improved with detailed information, especially for error scenarios like invalid messages or failed API requests.

7. Concurrency with Flask:

    The app is configured to handle concurrent requests using threaded=True in Flask. This ensures that multiple requests can be processed simultaneously.

Deployment Considerations:

    Production Server: To deploy this app in a production environment, use a robust WSGI server like Gunicorn:

    bash

gunicorn -w 4 app:app

This runs the app with 4 worker processes to handle concurrent requests.

Docker: You can containerize the app for easier deployment and scaling.

Dockerfile

    FROM python:3.9-slim

    WORKDIR /app

    COPY . .

    RUN pip install -r requirements.txt

    EXPOSE 5000

    CMD ["gunicorn", "-w", "4", "app:app"]

Further Enhancements:

    Caching: Use a cache (e.g., Redis) for frequently queried URLs to reduce the number of VirusTotal requests and improve performance.
    Authentication: Implement webhook authentication to ensure that only authorized users can trigger the webhook.
    Advanced Rate Limiting: Implement distributed rate limiting using a service like Redis or a cloud provider's API gateway.



    Explanation of Improvements:
1. Rate Limiting:

    The rate_limit decorator has been implemented to prevent abuse of the API. It limits the number of requests per user (based on their IP address). If the user exceeds the limit, they get a 429 Too Many Requests response.
    The limit can be configured via API_CALLS_LIMIT and the reset time can be adjusted with CALLS_RESET_TIME.
    You can adapt this rate limiting to a more advanced solution (e.g., using a Redis cache for better persistence and scalability).

2. API Key and Environment Variable Validation:

    We added a check to ensure that VIRUSTOTAL_API_KEY and WHATSAPP_API_URL are present in the environment variables at the start. If they are missing, the script will raise an exception.

3. Input Validation and Sanitization:

    The incoming webhook data is validated to ensure that both from (user ID) and text (message) fields exist.
    The URL is sanitized by stripping query parameters before sending it to the VirusTotal API, which helps avoid issues with special characters.

4. Error Handling:

    Proper exception handling with requests.exceptions.RequestException ensures that if any HTTP request fails (for VirusTotal or WhatsApp), an error message is logged, and the user is informed accordingly.
    Timeouts are applied to both external API calls (requests.get and requests.post) to avoid long delays.

5. Graceful Shutdown:

    We added a signal handler (graceful_shutdown) to handle termination signals (SIGINT, SIGTERM), ensuring the application shuts down gracefully, logging the shutdown process.

6. Logging Enhancements:

    Logging has been improved with detailed information, especially for error scenarios like invalid messages or failed API requests.

7. Concurrency with Flask:

    The app is configured to handle concurrent requests using threaded=True in Flask. This ensures that multiple requests can be processed simultaneously.

Deployment Considerations:

    Production Server: To deploy this app in a production environment, use a robust WSGI server like Gunicorn:

    bash

gunicorn -w 4 app:app

This runs the app with 4 worker processes to handle concurrent requests.

Docker: You can containerize the app for easier deployment and scaling.

Dockerfile

    FROM python:3.9-slim

    WORKDIR /app

    COPY . .

    RUN pip install -r requirements.txt

    EXPOSE 5000

    CMD ["gunicorn", "-w", "4", "app:app"]

Further Enhancements:

    Caching: Use a cache (e.g., Redis) for frequently queried URLs to reduce the number of VirusTotal requests and improve performance.
    Authentication: Implement webhook authentication to ensure that only authorized users can trigger the webhook.
    Advanced Rate Limiting: Implement distributed rate limiting using a service like Redis or a cloud provider's API gateway.
Ensure your Flask app is running in an environment that can access the internet for API calls.
