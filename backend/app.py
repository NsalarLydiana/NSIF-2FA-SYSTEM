# backend/app.py
"""
Flask Application Factory
Creates and configures the Flask app for NSIF 2FA
"""

import logging
from flask import Flask, request, jsonify
from flask_cors import CORS
from datetime import datetime

from backend.config import Config
from backend.utils.helpers import (
    is_valid_username,
    is_valid_password,
    is_valid_otp_code
)
from backend.services.auth_services import (
    ActiveDirectoryService,
    EmailService,
    TokenService,
    OTPService
)

# ============================================
# APP CREATION
# ============================================

def create_app():
    """
    Create and configure Flask application
    
    Returns:
        Flask app instance
    """
    app = Flask(__name__)
    
    # Load configuration
    app.config.from_object(Config)
    
    # Setup logging
    logging.basicConfig(level=app.config['LOG_LEVEL'])
    logger = logging.getLogger(__name__)
    
    # Enable CORS (allows requests from other domains)
    CORS(app)
    
    logger.info("=" * 70)
    logger.info("NSIF 2FA MFA PLATFORM STARTED")
    logger.info("Using Real Active Directory (ldap3)")
    logger.info("=" * 70)
    
    # ============================================
    # ROUTES
    # ============================================
    
    @app.route('/health', methods=['GET'])
    def health_check():
        """
        Health check endpoint
        
        Used to verify the server is running
        
        Returns:
            JSON with status information
        """
        return jsonify({
            'status': 'healthy',
            'service': 'NSIF 2FA MFA Platform',
            'version': '1.0.0',
            'timestamp': datetime.utcnow().isoformat()
        }), 200
    
    
    @app.route('/auth/initiate-2fa', methods=['POST'])
    def initiate_2fa():
        """
        STEP 1: User login and OTP initiation
        
        Process:
        1. Receive username and password
        2. Validate against NSIF Active Directory
        3. Generate 4-character OTP code
        4. Send OTP via email (Mailtrap)
        5. Return session ID
        
        Request JSON:
        {
            "username": "hr_user1",
            "password": "NSIFHr@123!",
            "app_name": "hr-system"
        }
        
        Response JSON (Success):
        {
            "status": "pending_otp",
            "session_id": "uuid",
            "message": "OTP sent to hr_user1@nsif.cm",
            "expires_in": 300
        }
        
        Response JSON (Error):
        {
            "status": "error",
            "message": "Invalid username or password"
        }
        """
        try:
            logger.info("=" * 70)
            logger.info("[2FA INITIATE] Request received")
            logger.info("=" * 70)
            
            # Get request data
            data = request.get_json()
            
            if not data:
                return jsonify({
                    'status': 'error',
                    'message': 'Request body is required'
                }), 400
            
            username = data.get('username', '').strip()
            password = data.get('password', '')
            app_name = data.get('app_name', '').strip()
            
            # Validate inputs
            is_valid, error = is_valid_username(username)
            if not is_valid:
                logger.warning(f"[2FA] Invalid username: {error}")
                return jsonify({
                    'status': 'error',
                    'message': error
                }), 400
            
            is_valid, error = is_valid_password(password)
            if not is_valid:
                logger.warning(f"[2FA] Invalid password: {error}")
                return jsonify({
                    'status': 'error',
                    'message': error
                }), 400
            
            if not app_name:
                return jsonify({
                    'status': 'error',
                    'message': 'app_name is required'
                }), 400
            
            logger.info(f"[2FA] Inputs validated. Username: {username}, App: {app_name}")
            
            # ===== STEP 1: Validate against NSIF AD =====
            logger.info(f"[2FA] Validating against Active Directory...")
            is_valid_creds = ActiveDirectoryService.validate_credentials(username, password)
            
            if not is_valid_creds:
                logger.warning(f"[2FA] ✗ Invalid credentials for: {username}")
                return jsonify({
                    'status': 'error',
                    'message': 'Invalid username or password'
                }), 401
            
            logger.info(f"[2FA] ✓ NSIF AD validation successful")
            
            # ===== STEP 2: Generate OTP =====
            logger.info(f"[2FA] Generating OTP token...")
            otp_token = OTPService.generate_otp()
            session_id = OTPService.create_session(username, app_name, otp_token)
            
            logger.info(f"[2FA] ✓ OTP generated: {otp_token}")
            
            # ===== STEP 3: Send Email =====
            logger.info(f"[2FA] Sending email via Mailtrap...")
            
            # Generate email address from username
            recipient_email = f"{username}@nsif-local.test"
            
            email_sent = EmailService.send_otp(
                recipient_email=recipient_email,
                otp_token=otp_token,
                username=username
            )
            
            if not email_sent:
                logger.error(f"[2FA] ✗ Failed to send email")
                return jsonify({
                    'status': 'error',
                    'message': 'Failed to send OTP email. Please try again.'
                }), 500
            
            logger.info(f"[2FA] ✓ Email sent successfully")
            
            # ===== RESPONSE =====
            response = {
                'status': 'pending_otp',
                'session_id': session_id,
                'message': f'OTP sent to {recipient_email}',
                'expires_in': app.config['TOKEN_EXPIRY_MINUTES'] * 60  # seconds
            }
            
            logger.info(f"[2FA] ✓ Response sent with session_id: {session_id}")
            
            return jsonify(response), 200
        
        except Exception as e:
            logger.error(f"[2FA] Error: {str(e)}", exc_info=True)
            return jsonify({
                'status': 'error',
                'message': 'An error occurred'
            }), 500
    
    
    @app.route('/auth/validate-otp', methods=['POST'])
    def validate_otp():
        """
        STEP 2: Validate OTP code and issue session token
        
        Process:
        1. Receive session ID and OTP code
        2. Validate OTP code (correct code, not expired, attempts not exceeded)
        3. Create user session
        4. Return session token
        
        Request JSON:
        {
            "session_id": "uuid",
            "otp_code": "ABC1"
        }
        
        Response JSON (Success):
        {
            "status": "success",
            "message": "Login successful",
            "session_token": "long-token-string",
            "username": "hr_user1",
            "app_name": "hr-system"
        }
        
        Response JSON (Error):
        {
            "status": "error",
            "message": "Invalid OTP code (2 attempts remaining)"
        }
        """
        try:
            logger.info("=" * 70)
            logger.info("[OTP VALIDATE] Request received")
            logger.info("=" * 70)
            
            data = request.get_json()
            
            if not data:
                return jsonify({
                    'status': 'error',
                    'message': 'Request body is required'
                }), 400
            
            session_id = data.get('session_id', '').strip()
            otp_code = data.get('otp_code', '').strip()
            
            # Validate OTP code format
            is_valid, error = is_valid_otp_code(otp_code)
            if not is_valid:
                logger.warning(f"[OTP] Invalid format: {error}")
                return jsonify({
                    'status': 'error',
                    'message': error
                }), 400
            
            logger.info(f"[OTP] Validating: session_id={session_id}, code={otp_code}")
            
            # ===== Validate OTP =====
            is_valid_otp, result = OTPService.validate_otp(session_id, otp_code)
            
            if not is_valid_otp:
                # result is error message string when validation fails
                logger.warning(f"[OTP] ✗ Validation failed: {result}")
                return jsonify({
                    'status': 'error',
                    'message': result
                }), 401
            
            # result is session_data dict when validation succeeds
            session_data = result
            logger.info(f"[OTP] ✓ OTP validated successfully")
            
            # ===== Create User Session =====
            logger.info(f"[OTP] Creating user session...")
            session_token = TokenService.create_user_session(
                username=session_data['username'],
                app_name=session_data['app_name']
            )
            
            logger.info(f"[OTP] ✓ User session created: {session_token}")
            
            # ===== RESPONSE =====
            response = {
                'status': 'success',
                'message': 'Login successful',
                'session_token': session_token,
                'username': session_data['username'],
                'app_name': session_data['app_name']
            }
            
            logger.info(f"[OTP] ✓ Response sent")
            
            return jsonify(response), 200
        
        except Exception as e:
            logger.error(f"[OTP] Error: {str(e)}", exc_info=True)
            return jsonify({
                'status': 'error',
                'message': 'An error occurred'
            }), 500
    
    
    @app.route('/auth/verify-session', methods=['POST'])
    def verify_session():
        """
        Verify an existing session token
        
        Used by applications to verify that a session token is still valid
        
        Request JSON:
        {
            "session_token": "long-token-string"
        }
        
        Response JSON (Valid):
        {
            "status": "valid",
            "username": "hr_user1",
            "app_name": "hr-system"
        }
        
        Response JSON (Invalid):
        {
            "status": "error",
            "message": "Session has expired"
        }
        """
        try:
            data = request.get_json()
            
            if not data:
                return jsonify({
                    'status': 'error',
                    'message': 'Request body is required'
                }), 400
            
            session_token = data.get('session_token', '')
            
            is_valid, session_data = TokenService.verify_user_session(session_token)
            
            if not is_valid:
                logger.warning(f"[VERIFY] Session validation failed: {session_data}")
                return jsonify({
                    'status': 'error',
                    'message': session_data
                }), 401
            
            return jsonify({
                'status': 'valid',
                'username': session_data['username'],
                'app_name': session_data['app_name'],
                'expires_at': session_data['expires_at'].isoformat()
            }), 200
        
        except Exception as e:
            logger.error(f"[VERIFY] Error: {str(e)}", exc_info=True)
            return jsonify({
                'status': 'error',
                'message': 'An error occurred'
            }), 500
    
    
    # ============================================
    # ERROR HANDLERS
    # ============================================
    
    @app.errorhandler(404)
    def not_found(error):
        """Handle 404 Not Found"""
        return jsonify({
            'status': 'error',
            'message': 'Endpoint not found'
        }), 404
    
    @app.errorhandler(500)
    def server_error(error):
        """Handle 500 Internal Server Error"""
        logger.error(f"Server error: {str(error)}", exc_info=True)
        return jsonify({
            'status': 'error',
            'message': 'Internal server error'
        }), 500
    
    return app