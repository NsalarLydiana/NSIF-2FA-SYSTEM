# backend/utils/helpers.py
"""
Utility Functions
- Token generation
- Session ID generation
- Input validation
- Expiry time calculation
"""

import random
import string
import uuid
from datetime import datetime, timedelta
import re

# ============================================
# TOKEN GENERATION
# ============================================

def generate_otp_token():
    """
    Generate a random 4-character OTP token
    
    Characters: A-Z and 0-9
    Example: "ABC1", "XYZ9", "1234"
    
    Returns:
        str: 4-character random token
    """
    chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
    token = ''.join(random.choice(chars) for _ in range(4))
    return token


def generate_session_id():
    """
    Generate a unique session ID (UUID)
    
    Returns:
        str: Unique session ID
    """
    return str(uuid.uuid4())


def compare_tokens(token1, token2):
    """
    Compare two tokens (case-insensitive)
    
    Args:
        token1: First token
        token2: Second token
        
    Returns:
        bool: True if tokens match, False otherwise
    """
    return token1.upper() == token2.upper()


def is_token_expired(expires_at):
    """
    Check if a token has expired
    
    Args:
        expires_at: Expiry datetime
        
    Returns:
        bool: True if expired, False otherwise
    """
    return datetime.utcnow() > expires_at


def get_expiry_time(minutes=5):
    """
    Calculate expiry time (now + X minutes)
    
    Args:
        minutes: Number of minutes until expiry (default: 5)
        
    Returns:
        datetime: Expiry datetime
    """
    return datetime.utcnow() + timedelta(minutes=minutes)


# ============================================
# VALIDATION
# ============================================

def is_valid_username(username):
    """
    Validate username format
    
    Rules:
    - Required
    - 3-255 characters
    - Only: letters, numbers, dots, underscores, hyphens
    
    Args:
        username: Username to validate
        
    Returns:
        tuple: (is_valid, error_message)
    """
    if not username:
        return False, "Username is required"
    
    if len(username) < 3:
        return False, "Username must be at least 3 characters"
    
    if len(username) > 255:
        return False, "Username must be less than 255 characters"
    
    # Only allow letters, numbers, dots, underscores, hyphens
    if not re.match(r'^[a-zA-Z0-9._-]+$', username):
        return False, "Username contains invalid characters"
    
    return True, None


def is_valid_password(password):
    """
    Validate password
    
    Rules:
    - Required
    - At least 1 character
    
    Args:
        password: Password to validate
        
    Returns:
        tuple: (is_valid, error_message)
    """
    if not password:
        return False, "Password is required"
    
    if len(password) < 1:
        return False, "Password cannot be empty"
    
    return True, None


def is_valid_email(email):
    """
    Validate email format
    
    Args:
        email: Email to validate
        
    Returns:
        tuple: (is_valid, error_message)
    """
    if not email:
        return False, "Email is required"
    
    email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    
    if not re.match(email_pattern, email):
        return False, "Invalid email format"
    
    return True, None


def is_valid_otp_code(otp_code):
    """
    Validate OTP code format
    
    Rules:
    - Required
    - Exactly 4 characters
    - Only alphanumeric (A-Z, 0-9)
    
    Args:
        otp_code: OTP code to validate
        
    Returns:
        tuple: (is_valid, error_message)
    """
    if not otp_code:
        return False, "OTP code is required"
    
    if len(otp_code.upper()) != 4:
        return False, "OTP code must be exactly 4 characters"
    
    if not otp_code.upper().isalnum():
        return False, "OTP code must contain only letters and numbers"
    
    return True, None


def is_valid_app_name(app_name):
    """
    Validate application name
    
    Args:
        app_name: Application name to validate
        
    Returns:
        tuple: (is_valid, error_message)
    """
    if not app_name:
        return False, "Application name is required"
    
    if len(app_name) < 1 or len(app_name) > 255:
        return False, "Application name must be 1-255 characters"
    
    return True, None