"""
Authentication Services
- Active Directory integration (using ldap3)
- Email sending (Mailtrap for testing)
- Token and session management
"""

import smtplib
import logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta
from flask import current_app
from ldap3 import Server, Connection, ALL, SUBTREE

from backend.utils.helpers import (
    generate_otp_token,
    generate_session_id,
    get_expiry_time
)

logger = logging.getLogger(__name__)

# ============================================
# ACTIVE DIRECTORY SERVICE (Using ldap3)
# ============================================

class ActiveDirectoryService:
    """
    Connect to NSIF Active Directory and validate user credentials
    Using ldap3 library for Python 3.11 compatibility
    """
    
    @staticmethod
    def validate_credentials(username, password):
        """
        Validate username and password against NSIF Active Directory
        
        Args:
            username: Username (e.g., 'hr_user1')
            password: Password (e.g., 'NSIFHr@123!')
            
        Returns:
            dict: User info if valid, None if invalid
        """
        logger.info(f"[AD] Validating credentials for: {username}")
        
        try:
            # Get LDAP configuration
            ldap_server = current_app.config['AD_SERVER']
            base_dn = current_app.config['AD_BASE_DN']
            admin_dn = current_app.config['AD_ADMIN_DN']
            admin_password = current_app.config['AD_ADMIN_PASSWORD']
            
            logger.info(f"[AD] Connecting to LDAP server: {ldap_server}")
            
            # Step 1: Connect as admin to search for the user
            server = Server(ldap_server, get_info=ALL)
            
            admin_conn = Connection(
                server,
                user=admin_dn,
                password=admin_password,
                auto_bind=True
            )
            
            logger.info(f"[AD] ✓ Admin connection successful")
            
            # Step 2: Search for the user by sAMAccountName
            search_filter = f"(sAMAccountName={username})"
            
            logger.info(f"[AD] Searching for user: {username}")
            
            admin_conn.search(
                search_base=base_dn,
                search_filter=search_filter,
                search_scope=SUBTREE,
                attributes=['displayName', 'mail', 'sAMAccountName', 'cn']
            )
            
            if not admin_conn.entries:
                logger.warning(f"[AD] ✗ User not found in directory: {username}")
                admin_conn.unbind()
                return None
            
            # Get user's DN from search results
            user_entry = admin_conn.entries[0]
            user_dn = user_entry.entry_dn
            
            logger.info(f"[AD] ✓ User found: {user_dn}")
            
            admin_conn.unbind()
            
            # Step 3: Try to authenticate as the user with provided password
            logger.info(f"[AD] Attempting to authenticate as: {user_dn}")
            
            user_server = Server(ldap_server, get_info=ALL)
            
            user_conn = Connection(
                user_server,
                user=user_dn,
                password=password,
                auto_bind=True
            )
            
            logger.info(f"[AD] ✓ User authentication successful: {username}")
            
            user_conn.unbind()
            
            # Return user information
            user_info = {
                'username': username,
                'email': user_entry.mail.value if hasattr(user_entry, 'mail') and user_entry.mail else f"{username}@nsif.cm",
                'full_name': user_entry.displayName.value if hasattr(user_entry, 'displayName') else username
            }
            
            logger.info(f"[AD] ✓ Returning user info: {user_info}")
            
            return user_info
            
        except Exception as e:
            logger.error(f"[AD] ✗ Authentication failed: {str(e)}")
            return None


# ============================================
# EMAIL SERVICE (Mailtrap)
# ============================================

class EmailService:
    """
    Send emails via Mailtrap SMTP (for testing)
    """
    
    @staticmethod
    def send_otp(recipient_email, otp_token, username):
        """
        Send OTP code via email using Mailtrap
        
        Args:
            recipient_email: Email address to send to
            otp_token: OTP code
            username: Username
            
        Returns:
            bool: True if sent, False if failed
        """
        try:
            logger.info(f"[EMAIL] Sending OTP to {recipient_email}")
            
            # Get Mailtrap settings from config
            smtp_host = current_app.config['sandbox.smtp.mailtrap.io']
            smtp_port = current_app.config['2525']
            smtp_username = current_app.config['96f00da12bbbc5']
            smtp_password = current_app.config['5e94e9b944c71c']
            from_email = current_app.config['noreply@nsif.cm']
            
            # Create email message
            msg = MIMEMultipart()
            msg['From'] = from_email
            msg['To'] = recipient_email
            msg['Subject'] = 'NSIF Authentication Code'
            
            # Email body
            body = f"""
Hello {username},

Your NSIF authentication code is:

    {otp_token}

This code expires in 5 minutes.

If you did not request this code, please contact support immediately.

Do not share this code with anyone.

---
NSIF Authentication System
            """
            
            msg.attach(MIMEText(body, 'plain'))
            
            # Connect to Mailtrap SMTP server
            server = smtplib.SMTP(smtp_host, smtp_port)
            server.starttls()  # Secure connection
            server.login(smtp_username, smtp_password)
            
            # Send email
            server.send_message(msg)
            server.quit()
            
            logger.info(f"[EMAIL] ✓ OTP sent successfully to {recipient_email}")
            print(f"\n{'='*60}")
            print(f"✉️  EMAIL SENT (Mailtrap)")
            print(f"{'='*60}")
            print(f"To: {recipient_email}")
            print(f"OTP Code: {otp_token}")
            print(f"Username: {username}")
            print(f"{'='*60}\n")
            
            return True
            
        except Exception as e:
            logger.error(f"[EMAIL] ✗ Failed to send OTP: {str(e)}")
            print(f"\n❌ ERROR: Failed to send email: {str(e)}\n")
            return False


# ============================================
# TOKEN SERVICE
# ============================================

class TokenService:
    """
    Manage OTP tokens and sessions
    """
    
    # Store OTP sessions (in production, use database)
    _otp_sessions = {}
    
    # Store user sessions (in production, use database)
    _user_sessions = {}
    
    @staticmethod
    def create_otp_session(username, email, app_name):
        """
        Create a new OTP session
        
        Args:
            username: Username
            email: User's email
            app_name: Application requesting authentication
            
        Returns:
            dict: Session info including OTP token
        """
        # Generate token and session ID
        otp_token = generate_otp_token()
        session_id = generate_session_id()
        expires_at = get_expiry_time(current_app.config['TOKEN_EXPIRY_MINUTES'])
        
        # Store session
        TokenService._otp_sessions[session_id] = {
            'username': username,
            'email': email,
            'app_name': app_name,
            'otp_token': otp_token,
            'expires_at': expires_at,
            'failed_attempts': 0,
            'created_at': datetime.utcnow()
        }
        
        logger.info(f"[TOKEN] OTP session created: {session_id}")
        
        return {
            'session_id': session_id,
            'otp_token': otp_token,
            'expires_at': expires_at
        }
    
    @staticmethod
    def validate_otp_code(session_id, otp_code):
        """
        Validate OTP code for a session
        
        Args:
            session_id: Session ID
            otp_code: OTP code entered by user
            
        Returns:
            tuple: (is_valid, error_message, session_data)
        """
        session = TokenService._otp_sessions.get(session_id)
        
        if not session:
            return False, "Session not found", None
        
        # Check if expired
        if datetime.utcnow() > session['expires_at']:
            return False, "OTP code has expired", None
        
        # Check max attempts
        if session['failed_attempts'] >= current_app.config['MAX_ATTEMPTS']:
            return False, "Maximum attempts exceeded", None
        
        # Compare tokens
        from backend.utils.helpers import compare_tokens
        if not compare_tokens(otp_code, session['otp_token']):
            session['failed_attempts'] += 1
            remaining = current_app.config['MAX_ATTEMPTS'] - session['failed_attempts']
            return False, f"Invalid OTP code ({remaining} attempts remaining)", None
        
        # Token is valid!
        logger.info(f"[TOKEN] OTP validated successfully for: {session['username']}")
        return True, None, session
    
    @staticmethod
    def create_user_session(username, app_name):
        """
        Create a user session after successful OTP validation
        
        Args:
            username: Username
            app_name: Application name
            
        Returns:
            dict: Session token info
        """
        session_id = generate_session_id()
        session_token = generate_session_id() + generate_session_id()  # Longer token
        expires_at = get_expiry_time(minutes=480)  # 8 hours
        
        TokenService._user_sessions[session_id] = {
            'username': username,
            'app_name': app_name,
            'session_token': session_token,
            'expires_at': expires_at,
            'created_at': datetime.utcnow()
        }
        
        logger.info(f"[TOKEN] User session created for: {username}")
        
        return {
            'session_id': session_id,
            'session_token': session_token,
            'expires_at': expires_at,
            'username': username,
            'app_name': app_name
        }
    
    @staticmethod
    def validate_user_session(session_id, session_token):
        """
        Validate a user session
        
        Args:
            session_id: Session ID
            session_token: Session token
            
        Returns:
            tuple: (is_valid, error_message, session_data)
        """
        session = TokenService._user_sessions.get(session_id)
        
        if not session:
            return False, "Session not found", None
        
        if session['session_token'] != session_token:
            return False, "Invalid session token", None
        
        if datetime.utcnow() > session['expires_at']:
            return False, "Session has expired", None
        
        return True, None, session