import os
import smtplib
import uuid
import logging
from datetime import datetime, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from ldap3 import Server, Connection, ALL

logger = logging.getLogger(__name__)

# ============================================================
# ACTIVE DIRECTORY SERVICE
# ============================================================

class ActiveDirectoryService:
    """Authenticate users against Active Directory"""
    
    @staticmethod
    def validate_credentials(username, password):
        """Validate username and password against AD"""
        try:
            ad_server = os.getenv('AD_SERVER', '192.168.56.102')
            ad_domain = os.getenv('AD_DOMAIN', 'nsif-local.test')
            ad_base_dn = os.getenv('AD_BASE_DN', 'DC=nsif-local,DC=test')
            
            logger.info(f'[AD] Validating credentials for: {username}')
            logger.info(f'[AD] Server: {ad_server}, Base DN: {ad_base_dn}')
            
            # Connect to AD
            server = Server(ad_server, get_info=ALL, connect_timeout=5)
            
            # Try different DN formats
            user_dn_formats = [
                f'CN={username},CN=Users,{ad_base_dn}',  # Format 1: CN=user,CN=Users,DC=...
                f'{username}@{ad_domain}',  # Format 2: user@domain (UPN)
                f'{ad_domain}\\{username}',  # Format 3: domain\user (NetBIOS)
            ]
            
            for user_dn in user_dn_formats:
                try:
                    logger.info(f'[AD] Attempting bind with DN: {user_dn}')
                    conn = Connection(server, user=user_dn, password=password, raise_exceptions=False)
                    
                    if conn.bind():
                        logger.info(f'[AD] ✓ Valid credentials for {username} (DN: {user_dn})')
                        conn.unbind()
                        return True
                    else:
                        logger.warning(f'[AD] Bind failed for DN: {user_dn}')
                
                except Exception as e:
                    logger.warning(f'[AD] Error with DN {user_dn}: {str(e)}')
                    continue
            
            logger.error(f'[AD] Invalid credentials for {username} - all DN formats failed')
            return False
            
        except Exception as e:
            logger.error(f'[AD] Error validating credentials: {str(e)}')
            return False

# ============================================================
# EMAIL SERVICE

# ============================================================
class EmailService:
    """Send OTP via email"""
    
    @staticmethod
    def send_otp(recipient_email, otp_token, username):
        """Send OTP via Mailtrap or mock service"""
        try:
            email_provider = os.getenv('EMAIL_PROVIDER', 'mock')
            
            if email_provider == 'mailtrap':
                return EmailService._send_via_mailtrap(recipient_email, otp_token, username)
            else:
                # Use mock/file-based email for testing
                return EmailService._send_via_mock(recipient_email, otp_token, username)
                
        except Exception as e:
            logger.error(f'[EMAIL] Failed to send OTP: {str(e)}')
            return False
    
    @staticmethod
    def _send_via_mailtrap(recipient_email, otp_token, username):
        """Send email via Mailtrap SMTP"""
        try:
            mailtrap_host = os.getenv('MAILTRAP_HOST', 'sandbox.smtp.mailtrap.io')
            mailtrap_port = int(os.getenv('MAILTRAP_PORT', 2525))
            mailtrap_user = os.getenv('MAILTRAP_USERNAME')
            mailtrap_pass = os.getenv('MAILTRAP_PASSWORD')
            email_from = os.getenv('EMAIL_FROM', 'noreply@nsif.cm')
            
            if not mailtrap_user or not mailtrap_pass:
                logger.error('[EMAIL] Mailtrap credentials not configured')
                return False
            
            # Create message
            msg = MIMEMultipart('alternative')
            msg['Subject'] = 'NSIF 2FA OTP Code'
            msg['From'] = email_from
            msg['To'] = recipient_email
            
            # Email body
            text = f"Your OTP code is: {otp_token}\n\nCode expires in 5 minutes."
            html = f"""
            <html>
                <body>
                    <h2>NSIF 2FA Authentication</h2>
                    <p>Your OTP code is:</p>
                    <h1 style="color: #0073aa;">{otp_token}</h1>
                    <p>Code expires in <strong>5 minutes</strong></p>
                </body>
            </html>
            """
            
            msg.attach(MIMEText(text, 'plain'))
            msg.attach(MIMEText(html, 'html'))
            
            # Connect to Mailtrap and send
            server = smtplib.SMTP(mailtrap_host, mailtrap_port, timeout=10)
            server.starttls()
            server.login(mailtrap_user, mailtrap_pass)
            server.send_message(msg)
            server.quit()
            
            logger.info(f'[EMAIL] OTP sent to {recipient_email}')
            return True
            
        except Exception as e:
            logger.error(f'[EMAIL] Mailtrap failed: {str(e)}')
            logger.warning('[EMAIL] Falling back to mock email service')
            return EmailService._send_via_mock(recipient_email, otp_token, username)
    
    @staticmethod
    def _send_via_mock(recipient_email, otp_token, username):
        """Send OTP to file (mock email for testing)"""
        try:
            # Create logs directory if it doesn't exist
            os.makedirs('logs', exist_ok=True)
            
            # Log OTP to file
            log_file = 'logs/otp_codes.log'
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            
            with open(log_file, 'a') as f:
                f.write(f'[{timestamp}] User: {username} | Email: {recipient_email} | OTP: {otp_token}\n')
            
            logger.info(f'[EMAIL] Mock: OTP saved to {log_file}')
            logger.info(f'[EMAIL] ✓ OTP for {username}: {otp_token}')
            return True
            
        except Exception as e:
            logger.error(f'[EMAIL] Mock service failed: {str(e)}')
            return False


# ============================================================
# OTP SERVICE
# ============================================================

class OTPService:
    """Generate and validate OTP tokens"""
    
    # In-memory storage (use database in production)
    _otp_store = {}
    
    @staticmethod
    def generate_otp(length=4):
        """Generate random OTP"""
        import random
        import string
        
        chars = string.ascii_uppercase + string.digits
        otp = ''.join(random.choice(chars) for _ in range(length))
        return otp
    
    @staticmethod
    def create_session(username, app_name, otp_token):
        """Create OTP session"""
        session_id = str(uuid.uuid4())
        expiry_minutes = int(os.getenv('TOKEN_EXPIRY_MINUTES', 5))
        
        OTPService._otp_store[session_id] = {
            'username': username,
            'app_name': app_name,
            'otp_token': otp_token,
            'attempts': 0,
            'created_at': datetime.utcnow(),
            'expires_at': datetime.utcnow() + timedelta(minutes=expiry_minutes)
        }
        
        logger.info(f'[OTP] Session created: {session_id} for {username}')
        return session_id
    
    @staticmethod
    def validate_otp(session_id, otp_code):
        """Validate OTP code"""
        if session_id not in OTPService._otp_store:
            logger.error(f'[OTP] Invalid session_id: {session_id}')
            return False, 'Invalid session'
        
        session = OTPService._otp_store[session_id]
        
        # Check expiry
        if datetime.utcnow() > session['expires_at']:
            logger.error(f'[OTP] Session expired: {session_id}')
            del OTPService._otp_store[session_id]
            return False, 'OTP expired'
        
        # Check attempts
        max_attempts = int(os.getenv('MAX_ATTEMPTS', 3))
        if session['attempts'] >= max_attempts:
            logger.error(f'[OTP] Max attempts exceeded: {session_id}')
            del OTPService._otp_store[session_id]
            return False, 'Too many attempts'
        
        # Check OTP code
        if otp_code.upper() != session['otp_token'].upper():
            session['attempts'] += 1
            logger.warning(f'[OTP] Invalid code attempt {session["attempts"]}: {session_id}')
            return False, f'Invalid OTP code (attempt {session["attempts"]}/{max_attempts})'
        
        # OTP is valid
        logger.info(f'[OTP] ✓ Valid OTP: {session_id}')
        username = session['username']
        app_name = session['app_name']
        
        # Clean up
        del OTPService._otp_store[session_id]
        
        return True, {'username': username, 'app_name': app_name}


# ============================================================
# SESSION SERVICE
# ============================================================

class SessionService:
    """Manage user sessions"""
    
    _sessions = {}
    
    @staticmethod
    def create_session(username, app_name):
        """Create new session token"""
        session_token = str(uuid.uuid4())
        expiry_hours = 24
        
        SessionService._sessions[session_token] = {
            'username': username,
            'app_name': app_name,
            'created_at': datetime.utcnow(),
            'expires_at': datetime.utcnow() + timedelta(hours=expiry_hours)
        }
        
        logger.info(f'[SESSION] New session: {session_token} for {username}')
        return session_token
    
    @staticmethod
    def verify_session(session_token):
        """Verify if session is valid"""
        if session_token not in SessionService._sessions:
            return False, 'Invalid session'
        
        session = SessionService._sessions[session_token]
        
        if datetime.utcnow() > session['expires_at']:
            del SessionService._sessions[session_token]
            return False, 'Session expired'
        
        return True, session
    
# ============================================================
# TOKEN SERVICE
# ============================================================

class TokenService:
    """Token management"""
    
    @staticmethod
    def generate_token():
        """Generate a random token"""
        return str(uuid.uuid4())
    
    @staticmethod
    def validate_token(token):
        """Validate a token"""
        if not token or len(token) < 10:
            return False
        return True
    
    @staticmethod
    def create_otp_session(username, app_name, otp_token):
        """Create OTP session (wrapper for OTPService)"""
        return OTPService.create_session(username, app_name, otp_token)
    
    @staticmethod
    def validate_otp_session(session_id, otp_code):
        """Validate OTP session (wrapper for OTPService)"""
        return OTPService.validate_otp(session_id, otp_code)
    
    @staticmethod
    def create_user_session(username, app_name):
        """Create user session (wrapper for SessionService)"""
        return SessionService.create_session(username, app_name)
    
    @staticmethod
    def verify_user_session(session_token):
        """Verify user session (wrapper for SessionService)"""
        return SessionService.verify_session(session_token)


# ============================================================
# VALIDATION SERVICE
# ============================================================

class ValidationService:
    """Validate user inputs"""
    
    @staticmethod
    def is_valid_username(username):
        """Check if username is valid"""
        if not username or len(username) < 3:
            return False
        return True
    
    @staticmethod
    def is_valid_password(password):
        """Check if password is valid"""
        if not password or len(password) < 6:
            return False
        return True
    
    @staticmethod
    def is_valid_email(email):
        """Check if email is valid"""
        if not email or '@' not in email:
            return False
        return True
    
    @staticmethod
    def is_valid_otp(otp):
        """Check if OTP is valid"""
        if not otp or len(otp) != 4:
            return False
        return True
    
    @staticmethod
    def is_valid_app_name(app_name):
        """Check if app name is valid"""
        if not app_name or len(app_name) < 2:
            return False
        return True