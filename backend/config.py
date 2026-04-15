# backend/config.py
"""
Application Configuration
Loads settings from config/.env file
"""

import os
from datetime import timedelta
from dotenv import load_dotenv

# Load environment variables from config/.env file
load_dotenv(os.path.join(os.path.dirname(__file__), '..', 'config', '.env'))

class Config:
    """Base configuration"""
    
    # Flask
    SECRET_KEY = os.getenv('SECRET_KEY', 'dev-secret-key-change-in-production')
    DEBUG = os.getenv('FLASK_ENV') == 'development'
    
    # NSIF Active Directory
    AD_SERVER = os.getenv('AD_SERVER', '192.168.1.124')
    AD_DOMAIN = os.getenv('AD_DOMAIN', 'nsif-local.test')
    AD_BASE_DN = os.getenv('AD_BASE_DN', 'DC=nsif-local,DC=test')
    AD_ADMIN_DN = os.getenv('AD_ADMIN_DN', 'CN=Administrator,CN=Users,DC=nsif-local,DC=test')
    AD_ADMIN_PASSWORD = os.getenv('AD_ADMIN_PASSWORD', 'Admin123')
    
    # Email - Mailtrap
    EMAIL_PROVIDER = os.getenv('EMAIL_PROVIDER', 'mailtrap')
    MAILTRAP_HOST = os.getenv('MAILTRAP_HOST', 'sandbox.smtp.mailtrap.io')
    MAILTRAP_PORT = int(os.getenv('MAILTRAP_PORT', '2525'))
    MAILTRAP_USERNAME = os.getenv('MAILTRAP_USERNAME', '96f00da12bbbc5')
    MAILTRAP_PASSWORD = os.getenv('MAILTRAP_PASSWORD', '5e94e9b944c71c')
    EMAIL_FROM = os.getenv('EMAIL_FROM', 'noreply@nsif.cm')
    
    # Token Settings
    TOKEN_LENGTH = int(os.getenv('TOKEN_LENGTH', '4'))
    TOKEN_EXPIRY_MINUTES = int(os.getenv('TOKEN_EXPIRY_MINUTES', '5'))
    MAX_ATTEMPTS = int(os.getenv('MAX_ATTEMPTS', '3'))
    
    # Logging
    LOG_LEVEL = os.getenv('LOG_LEVEL', 'INFO')