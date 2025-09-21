import os
from flask import Flask, request, jsonify
from authenticate import WebhookAuthenticator, WebhookConfig, AuthMethod, FrameSamplingStrategy

app = Flask(__name__)

# Initialize authenticator
auth = WebhookAuthenticator()

# Get secrets from environment variables
netlify_secret = os.getenv('NETLIFY_WEBHOOK_SECRET')
github_secret = os.getenv('GITHUB_WEBHOOK_SECRET')

# Register Netlify webhook
if netlify_secret:
    netlify_config = WebhookConfig(
        secret=netlify_secret,
        auth_method=AuthMethod.SECRET_TOKEN,
        sampling_strategy=FrameSamplingStrategy.RISK_BASED
    )
    auth.register_webhook('netlify', netlify_config)
else:
    print("Warning: NETLIFY_WEBHOOK_SECRET environment variable not set. Netlify webhook will not be registered.")

# Register GitHub webhook
if github_secret:
    github_config = WebhookConfig(
        secret=github_secret,
        auth_method=AuthMethod.HMAC_SHA256,
        sampling_strategy=FrameSamplingStrategy.FULL_VERIFICATION,
        require_timestamp=False  # GitHub does not send timestamps by default
    )
    auth.register_webhook('github', github_config)
else:
    print("Warning: GITHUB_WEBHOOK_SECRET environment variable not set. GitHub webhook will not be registered.")

@app.route('/webhook/netlify', methods=['POST'])
def handle_netlify_webhook():
    """
    Handles incoming webhooks from Netlify.
    """
    headers = dict(request.headers)
    payload = request.get_data()
    source_ip = request.environ.get('REMOTE_ADDR')
    
    result = auth.authenticate_webhook('netlify', headers, payload, source_ip)
    
    if not result.is_valid:
        return {"error": result.error_message}, 401
    
    # Process webhook data
    data = request.get_json()
    print(f"Netlify webhook received: {data}")
    
    return {"status": "success"}

@app.route('/webhook/github', methods=['POST'])
def handle_github_webhook():
    """
    Handles incoming webhooks from GitHub, authenticating them
    using HMAC-SHA256 before processing the payload.
    """
    headers = dict(request.headers)
    payload = request.get_data()
    source_ip = request.environ.get('REMOTE_ADDR')
    
    result = auth.authenticate_webhook('github', headers, payload, source_ip)
    
    if not result.is_valid:
        return {"error": result.error_message}, 401
    
    # Process webhook data
    data = request.get_json()
    
    # Check for the X-GitHub-Event header to know what kind of event it is
    event = headers.get('X-GitHub-Event', 'unknown')
    print(f"GitHub webhook received for event '{event}'")
    
    # You can add specific logic here based on the event type.
    if event == 'push':
        print(f"Received push event for repository: {data.get('repository', {}).get('full_name')}")
    
    return {"status": "success"}

if __name__ == '__main__':
    app.run(debug=True, port=5000)
