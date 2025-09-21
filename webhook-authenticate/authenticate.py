import hashlib
import hmac
import time
import logging
from typing import Optional, Dict, Any, List, Tuple
from dataclasses import dataclass
from enum import Enum
import json
import secrets
from functools import wraps
import os

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class AuthMethod(Enum):
    """Supported webhook authentication methods"""
    HMAC_SHA256 = "hmac_sha256"
    HMAC_SHA1 = "hmac_sha1"
    SECRET_TOKEN = "secret_token"
    BEARER_TOKEN = "bearer_token"

class FrameSamplingStrategy(Enum):
    """Frame sampling strategies for cost optimization"""
    FULL_VERIFICATION = "full"  # it has high accuracy, high cost
    RANDOM_SAMPLING = "random"  # it has medium accuracy, medium cost
    TIME_BASED = "time_based"   # it has adaptive accuracy and variable cost
    RISK_BASED = "risk_based"   # it has smart sampling based on risk assessment

@dataclass
class WebhookConfig:
    """Configuration for webhook authentication"""
    secret: str
    auth_method: AuthMethod
    sampling_strategy: FrameSamplingStrategy = FrameSamplingStrategy.FULL_VERIFICATION
    sampling_rate: float = 1.0  # 0.0 to 1.0
    timestamp_tolerance: int = 300  # 5 minutes in seconds
    require_timestamp: bool = True
    trusted_sources: List[str] = None

@dataclass
class AuthResult:
    """Result of webhook authentication"""
    is_valid: bool
    method_used: AuthMethod
    sampled: bool
    error_message: Optional[str] = None
    risk_score: float = 0.0

class WebhookAuthenticator:
    """
    Main webhook authentication class with frame sampling strategy
    for balancing security accuracy vs computational cost
    """
    
    def __init__(self):
        self.configs: Dict[str, WebhookConfig] = {}
        self.auth_stats = {
            'total_requests': 0,
            'authenticated': 0,
            'rejected': 0,
            'sampled': 0
        }
        
    def register_webhook(self, webhook_id: str, config: WebhookConfig):
        """Register a new webhook with its configuration"""
        self.configs[webhook_id] = config
        logger.info(f"Registered webhook {webhook_id} with {config.auth_method.value}")
    
    def _generate_secret(self, length: int = 32) -> str:
        """Generate a cryptographically secure secret"""
        return secrets.token_urlsafe(length)
    
    def _verify_hmac_signature(self, payload: bytes, signature: str, 
                             secret: str, algorithm: str = 'sha256') -> bool:
        """Verify HMAC signature"""
        try:
            # Handle different signature formats (GitHub, Stripe, etc.)
            if signature.startswith('sha256='):
                signature = signature[7:]
                algorithm = 'sha256'
            elif signature.startswith('sha1='):
                signature = signature[5:]
                algorithm = 'sha1'
            
            # Compute expected signature
            if algorithm == 'sha256':
                expected = hmac.new(
                    secret.encode('utf-8'),
                    payload,
                    hashlib.sha256
                ).hexdigest()
            elif algorithm == 'sha1':
                expected = hmac.new(
                    secret.encode('utf-8'),
                    payload,
                    hashlib.sha1
                ).hexdigest()
            else:
                raise ValueError(f"Unsupported algorithm: {algorithm}")
            
            # Use constant-time comparison to prevent timing attacks
            return hmac.compare_digest(expected, signature)
            
        except Exception as e:
            logger.error(f"HMAC verification failed: {e}")
            return False
    
    def _verify_secret_token(self, provided_token: str, expected_token: str) -> bool:
        """Verify secret token using constant-time comparison"""
        return hmac.compare_digest(provided_token, expected_token)
    
    def _verify_timestamp(self, timestamp: Optional[str], tolerance: int) -> bool:
        """Verify request timestamp to prevent replay attacks"""
        if not timestamp:
            return False
        
        try:
            request_time = int(timestamp)
            current_time = int(time.time())
            time_diff = abs(current_time - request_time)
            return time_diff <= tolerance
        except (ValueError, TypeError):
            return False
    
    def _calculate_risk_score(self, headers: Dict[str, str], 
                            source_ip: Optional[str] = None) -> float:
        """Calculate risk score for adaptive sampling"""
        risk_score = 0.0
        
        # Check for suspicious patterns
        user_agent = headers.get('user-agent', '').lower()
        if 'bot' in user_agent or 'crawler' in user_agent:
            risk_score += 0.3
        
        # Check content type
        content_type = headers.get('content-type', '')
        if content_type != 'application/json':
            risk_score += 0.2
        
        # IP-based risk (in production, use IP reputation service)
        if source_ip and source_ip.startswith('10.'):  # Private IP
            risk_score += 0.1
        
        # Missing standard headers
        if not headers.get('x-forwarded-for'):
            risk_score += 0.1
        
        return min(risk_score, 1.0)
    
    def _should_sample(self, config: WebhookConfig, headers: Dict[str, str], 
                      source_ip: Optional[str] = None) -> bool:
        """Determine if request should be sampled based on strategy"""
        if config.sampling_strategy == FrameSamplingStrategy.FULL_VERIFICATION:
            return True
        
        elif config.sampling_strategy == FrameSamplingStrategy.RANDOM_SAMPLING:
            return secrets.SystemRandom().random() < config.sampling_rate
        
        elif config.sampling_strategy == FrameSamplingStrategy.TIME_BASED:
            # Higher sampling during business hours
            current_hour = time.localtime().tm_hour
            if 9 <= current_hour <= 17:  # Business hours
                return secrets.SystemRandom().random() < config.sampling_rate
            else:
                return secrets.SystemRandom().random() < (config.sampling_rate * 0.5)
        
        elif config.sampling_strategy == FrameSamplingStrategy.RISK_BASED:
            risk_score = self._calculate_risk_score(headers, source_ip)
            # Higher risk = more likely to be verified
            adjusted_rate = min(config.sampling_rate + risk_score, 1.0)
            return secrets.SystemRandom().random() < adjusted_rate
        
        return True
    
    def authenticate_webhook(self, webhook_id: str, headers: Dict[str, str], 
                           payload: bytes, source_ip: Optional[str] = None) -> AuthResult:
        """
        Authenticate incoming webhook with frame sampling strategy
        """
        self.auth_stats['total_requests'] += 1
        
        config = self.configs.get(webhook_id)
        if not config:
            return AuthResult(
                is_valid=False,
                method_used=AuthMethod.SECRET_TOKEN,
                sampled=False,
                error_message=f"Webhook {webhook_id} not registered"
            )
        
        # Determine if we should sample this request
        should_sample = self._should_sample(config, headers, source_ip)
        
        if not should_sample:
            # Skip authentication for cost optimization
            self.auth_stats['sampled'] += 1
            return AuthResult(
                is_valid=True,
                method_used=config.auth_method,
                sampled=True,
                risk_score=self._calculate_risk_score(headers, source_ip)
            )
        
        # Perform full authentication
        try:
            if config.auth_method == AuthMethod.HMAC_SHA256:
                signature = headers.get('x-hub-signature-256') or headers.get('x-signature-256')
                if not signature:
                    return AuthResult(
                        is_valid=False,
                        method_used=config.auth_method,
                        sampled=False,
                        error_message="Missing HMAC signature header"
                    )
                
                is_valid = self._verify_hmac_signature(payload, signature, config.secret, 'sha256')
            
            elif config.auth_method == AuthMethod.HMAC_SHA1:
                signature = headers.get('x-hub-signature') or headers.get('x-signature')
                if not signature:
                    return AuthResult(
                        is_valid=False,
                        method_used=config.auth_method,
                        sampled=False,
                        error_message="Missing HMAC signature header"
                    )
                
                is_valid = self._verify_hmac_signature(payload, signature, config.secret, 'sha1')
            
            elif config.auth_method == AuthMethod.SECRET_TOKEN:
                token = headers.get('x-webhook-token') or headers.get('authorization')
                if token and token.startswith('Bearer '):
                    token = token[7:]  # Remove 'Bearer ' prefix
                
                if not token:
                    return AuthResult(
                        is_valid=False,
                        method_used=config.auth_method,
                        sampled=False,
                        error_message="Missing secret token"
                    )
                
                is_valid = self._verify_secret_token(token, config.secret)
            
            elif config.auth_method == AuthMethod.BEARER_TOKEN:
                auth_header = headers.get('authorization', '')
                if not auth_header.startswith('Bearer '):
                    return AuthResult(
                        is_valid=False,
                        method_used=config.auth_method,
                        sampled=False,
                        error_message="Missing or invalid Bearer token"
                    )
                
                token = auth_header[7:]  # Remove 'Bearer ' prefix
                is_valid = self._verify_secret_token(token, config.secret)
            
            else:
                return AuthResult(
                    is_valid=False,
                    method_used=config.auth_method,
                    sampled=False,
                    error_message=f"Unsupported auth method: {config.auth_method}"
                )
            
            # Verify timestamp if required
            if config.require_timestamp and is_valid:
                timestamp = headers.get('x-timestamp') or headers.get('timestamp')
                if not self._verify_timestamp(timestamp, config.timestamp_tolerance):
                    is_valid = False
                    error_msg = "Invalid or expired timestamp"
                else:
                    error_msg = None
            else:
                error_msg = None if is_valid else "Authentication failed"
            
            if is_valid:
                self.auth_stats['authenticated'] += 1
            else:
                self.auth_stats['rejected'] += 1
            
            return AuthResult(
                is_valid=is_valid,
                method_used=config.auth_method,
                sampled=False,
                error_message=error_msg,
                risk_score=self._calculate_risk_score(headers, source_ip)
            )
            
        except Exception as e:
            logger.error(f"Authentication error for webhook {webhook_id}: {e}")
            self.auth_stats['rejected'] += 1
            return AuthResult(
                is_valid=False,
                method_used=config.auth_method,
                sampled=False,
                error_message=f"Authentication error: {str(e)}"
            )
    
    def get_stats(self) -> Dict[str, Any]:
        """Get authentication statistics"""
        total = self.auth_stats['total_requests']
        if total == 0:
            return self.auth_stats
        
        return {
            **self.auth_stats,
            'success_rate': self.auth_stats['authenticated'] / total * 100,
            'sampling_rate': self.auth_stats['sampled'] / total * 100
        }

# Flask/FastAPI integration
def webhook_auth_required(webhook_id: str, authenticator: WebhookAuthenticator):
    """Decorator for webhook authentication"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            from flask import request  # example with flask
            
            headers = dict(request.headers)
            payload = request.get_data()
            source_ip = request.environ.get('REMOTE_ADDR')
            
            result = authenticator.authenticate_webhook(
                webhook_id, headers, payload, source_ip
            )
            
            if not result.is_valid:
                return {'error': result.error_message}, 401
            
            # Add auth info to kwargs
            kwargs['auth_result'] = result
            return f(*args, **kwargs)
        
        return decorated_function
    return decorator

# Example usage and configuration
if __name__ == "__main__":
    # Initialize authenticator
    auth = WebhookAuthenticator()
    
    # Example: GitHub webhook configuration
    github_config = WebhookConfig(
        secret=os.getenv('GITHUB_WEBHOOK_SECRET', 'your-github-secret'),
        auth_method=AuthMethod.HMAC_SHA256,
        sampling_strategy=FrameSamplingStrategy.RISK_BASED,
        sampling_rate=0.8,  # 80% sampling rate
        require_timestamp=False  # gitHub doesn't send timestamps
    )
    auth.register_webhook('github', github_config)
    
    # Example: Stripe webhook configuration
    stripe_config = WebhookConfig(
        secret=os.getenv('STRIPE_WEBHOOK_SECRET', 'whsec_your-stripe-secret'),
        auth_method=AuthMethod.HMAC_SHA256,
        sampling_strategy=FrameSamplingStrategy.FULL_VERIFICATION,  # high security for payments
        require_timestamp=True
    )
    auth.register_webhook('stripe', stripe_config)
    
    # Example: Custom webhook with secret token
    custom_config = WebhookConfig(
        secret=os.getenv('CUSTOM_WEBHOOK_SECRET', 'your-custom-secret'),
        auth_method=AuthMethod.SECRET_TOKEN,
        sampling_strategy=FrameSamplingStrategy.TIME_BASED,
        sampling_rate=0.6  # 60% base sampling rate
    )
    auth.register_webhook('custom', custom_config)
    
    # Example authentication test
    test_payload = b'{"test": "data"}'
    test_headers = {
        'content-type': 'application/json',
        'x-hub-signature-256': 'sha256=' + hmac.new(
            github_config.secret.encode(),
            test_payload,
            hashlib.sha256
        ).hexdigest(),
        'user-agent': 'GitHub-Hookshot/abc123'
    }
    
    result = auth.authenticate_webhook('github', test_headers, test_payload)
    print(f"Authentication result: {result}")
    print(f"Stats: {auth.get_stats()}")