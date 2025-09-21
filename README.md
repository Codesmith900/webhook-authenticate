# Webhook Authenticator

This project provides a robust and flexible Python-based webhook authentication system designed to secure incoming webhook requests. It features multiple authentication methods and an intelligent frame sampling strategy to balance security with computational cost.

## Features

* **Multiple Authentication Methods:** Supports HMAC-SHA256, HMAC-SHA1, Secret Token, and Bearer Token authentication.
* **Intelligent Frame Sampling:** Optimize performance by sampling a percentage of requests for full authentication based on different strategies:
   * `FULL_VERIFICATION`: Authenticate every request (highest security, highest cost).
   * `RANDOM_SAMPLING`: Authenticate a random subset of requests.
   * `TIME_BASED`: Adjust sampling rate based on time of day.
   * `RISK_BASED`: Increase sampling for requests with a higher risk score.
* **Replay Attack Prevention:** Optional timestamp verification to prevent malicious replay attacks.
* **Framework Integration:** Includes a decorator for easy integration with popular web frameworks like Flask.

## Quick Start

### Prerequisites

* Python 3.6+
* Flask
* ngrok

### Installation

First, ensure you have the required Python packages.

```bash
pip install Flask
```

### Running the Application

1. **Set your secret token:** Before running the application, you must set the `GITHUB_WEBHOOK_SECRET` environment variable in your terminal.
   * **macOS/Linux:** `export GITHUB_WEBHOOK_SECRET="your_secret_token"`
   * **Windows (Command Prompt):** `set GITHUB_WEBHOOK_SECRET=your_secret_token`
   * **Windows (PowerShell):** `$env:GITHUB_WEBHOOK_SECRET="your_secret_token"`

2. **Start the server:** Run the main application file.

```bash
python main.py
```

3. **Expose your local server:** Open a new terminal and use `ngrok` to create a public URL for your application.

```bash
ngrok http 5000
```

## GitHub Webhooks

The provided `main.py` is pre-configured to handle GitHub webhooks. After running your application and `ngrok`, follow these steps to set up the webhook on GitHub.

1. Copy the forwarding URL from the `ngrok` terminal output.
2. In your GitHub repository, go to **Settings > Webhooks > Add webhook**.
3. Set the **Payload URL** to your `ngrok` URL plus `/webhook/github` (e.g., `https://<your_ngrok_url>/webhook/github`).
4. Paste the **exact same** secret token from step 1 into the `Secret` field.
5. Select the events you want to receive and click **Add webhook**.

Your Flask application should now be able to receive and authenticate requests from GitHub.


<img width="970" height="580" alt="image" src="https://github.com/user-attachments/assets/0ed16e24-1f7d-40c4-b037-fd3e7ec3691c" />


## Project Structure

```
webhook-authenticator/
├── webhook_auth.py      # Main authentication system
├── main.py             # Flask application with webhook handlers
├── requirements.txt    # Python dependencies
└── README.md          # This file
```

## Supported Webhook Providers

- **GitHub:** HMAC-SHA256 signature verification
- **Stripe:** HMAC-SHA256 with endpoint secrets
- **Netlify:** Secret token authentication
- **Custom:** Configurable authentication methods

## Configuration Examples

### GitHub Webhook
```python
github_config = WebhookConfig(
    secret=os.getenv('GITHUB_WEBHOOK_SECRET'),
    auth_method=AuthMethod.HMAC_SHA256,
    sampling_strategy=FrameSamplingStrategy.RISK_BASED,
    sampling_rate=0.8
)
```

## Security Features

- **Constant-time comparison** to prevent timing attacks
- **HMAC signature verification** following industry standards
- **Timestamp validation** to prevent replay attacks
- **Risk-based sampling** for intelligent cost optimization
- **Secure secret management** through environment variables

## Testing

### Debug Mode
Enable debug logging to troubleshoot authentication issues:

```python
import logging
logging.getLogger('webhook_auth').setLevel(logging.DEBUG)
```

### Manual Testing
Test your webhook endpoint directly:

```bash
curl -X POST https://your-ngrok-url.ngrok.io/webhook/github \
  -H "Content-Type: application/json" \
  -H "X-Hub-Signature-256: sha256=your_signature" \
  -d '{"test": "data"}'
```

## Performance Metrics

The system provides built-in statistics to monitor authentication performance:

```python
stats = authenticator.get_stats()
print(f"Success rate: {stats['success_rate']:.1f}%")
print(f"Sampling rate: {stats['sampling_rate']:.1f}%")
```

## Troubleshooting

### Common Issues I came across

1. **401 Unauthorized Error**
   - Verify your secret matches between GitHub and environment variable
   - Check that the signature header is present
   - Ensure payload encoding is correct










