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

def create_app():
    app = Flask(__name__)
    app.config.from_object(Config)
    
    logging.basicConfig(level=app.config['LOG_LEVEL'])
    logger = logging.getLogger(__name__)
    
    CORS(app)
    
    logger.info("=" * 70)
    logger.info("NSIF 2FA MFA PLATFORM STARTED")
    logger.info("Using Real Active Directory (ldap3)")
    logger.info("=" * 70)
    
    # ============================================
    # Health check route
    # ============================================
    @app.route('/health', methods=['GET'])
    def health_check():
        return jsonify({
            'status': 'healthy',
            'service': 'NSIF 2FA MFA Platform',
            'version': '1.0.0',
            'timestamp': datetime.utcnow().isoformat()
        }), 200
    
    # ============================================
    # Initiate 2FA
    # ============================================
    @app.route('/auth/initiate-2fa', methods=['POST'])
    def initiate_2fa():
        try:
            logger.info("=" * 70)
            logger.info("[2FA INITIATE] Request received")
            logger.info("=" * 70)
            
            data = request.get_json()
            if not data:
                return jsonify({'status':'error','message':'Request body is required'}), 400
            
            username = data.get('username','').strip()
            password = data.get('password','')
            app_name = data.get('app_name','').strip()
            
            # Validate username
            is_valid, error = is_valid_username(username)
            if not is_valid:
                logger.warning(f"[2FA] Invalid username: {error}")
                return jsonify({'status':'error','message':error}), 400
            
            # 🔴 Skip password validation for GLPI
            if app_name != "glpi":
                is_valid, error = is_valid_password(password)
                if not is_valid:
                    logger.warning(f"[2FA] Invalid password: {error}")
                    return jsonify({'status':'error','message':error}), 400
            else:
                logger.info("[2FA] 🔴 Skipping password validation for GLPI")
            
            if not app_name:
                return jsonify({'status':'error','message':'app_name is required'}), 400
            
            logger.info(f"[2FA] Inputs validated. Username: {username}, App: {app_name}")
            
            # 🔴 Skip AD validation for GLPI
            if app_name == "glpi":
                logger.info("[2FA] 🔴 Skipping AD validation for GLPI (already authenticated)")
                is_valid_creds = True
            else:
                logger.info(f"[2FA] Validating against Active Directory...")
                is_valid_creds = ActiveDirectoryService.validate_credentials(username, password)
                if is_valid_creds:
                    logger.info(f"[2FA] ✓ NSIF AD validation successful")
            
            if not is_valid_creds:
                logger.warning(f"[2FA] ✗ Invalid credentials for: {username}")
                return jsonify({'status':'error','message':'Invalid username or password'}), 401
            
            # ===== STEP 2: Generate OTP =====
            logger.info(f"[2FA] Generating OTP token...")
            otp_token = OTPService.generate_otp()
            session_id = OTPService.create_session(username, app_name, otp_token)
            logger.info(f"[2FA] ✓ OTP generated: {otp_token}")
            
            # ===== STEP 3: Send Email =====
            recipient_email = f"{username}@nsif-local.test"
            logger.info(f"[2FA] Sending email to {recipient_email}...")
            email_sent = EmailService.send_otp(
                recipient_email=recipient_email,
                otp_token=otp_token,
                username=username
            )
            if not email_sent:
                logger.error(f"[2FA] ✗ Failed to send email")
                return jsonify({'status':'error','message':'Failed to send OTP email'}), 500
            
            logger.info(f"[2FA] ✓ Email sent successfully")
            
            # ===== RESPONSE =====
            response = {
                'status': 'pending_otp',
                'session_id': session_id,
                'message': f'OTP sent to {recipient_email}',
                'expires_in': app.config['TOKEN_EXPIRY_MINUTES'] * 60
            }
            logger.info(f"[2FA] ✓ Response sent with session_id: {session_id}")
            
            return jsonify(response), 200
        
        except Exception as e:
            logger.error(f"[2FA] Error: {str(e)}", exc_info=True)
            return jsonify({'status':'error','message':'An error occurred'}), 500
    
    # ============================================
    # Validate OTP
    # ============================================
    @app.route('/auth/validate-otp', methods=['POST'])
    def validate_otp():
        try:
            logger.info("=" * 70)
            logger.info("[OTP VALIDATE] Request received")
            logger.info("=" * 70)
            
            data = request.get_json()
            if not data:
                return jsonify({'status':'error','message':'Request body is required'}), 400
            
            session_id = data.get('session_id','').strip()
            otp_code = data.get('otp_code','').strip()
            
            is_valid, error = is_valid_otp_code(otp_code)
            if not is_valid:
                logger.warning(f"[OTP] Invalid format: {error}")
                return jsonify({'status':'error','message':error}), 400
            
            is_valid_otp, result = OTPService.validate_otp(session_id, otp_code)
            if not is_valid_otp:
                logger.warning(f"[OTP] ✗ Validation failed: {result}")
                return jsonify({'status':'error','message':result}), 401
            
            session_data = result
            logger.info(f"[OTP] ✓ OTP validated successfully")
            
            session_token = TokenService.create_user_session(
                username=session_data['username'],
                app_name=session_data['app_name']
            )
            logger.info(f"[OTP] ✓ User session created: {session_token}")
            
            return jsonify({
                'status':'success',
                'message':'Login successful',
                'session_token':session_token,
                'username':session_data['username'],
                'app_name':session_data['app_name']
            }), 200
        
        except Exception as e:
            logger.error(f"[OTP] Error: {str(e)}", exc_info=True)
            return jsonify({'status':'error','message':'An error occurred'}), 500
    
    # ============================================
    # Verify session token
    # ============================================
    @app.route('/auth/verify-session', methods=['POST'])
    def verify_session():
        try:
            data = request.get_json()
            if not data:
                return jsonify({'status':'error','message':'Request body is required'}), 400
            
            session_token = data.get('session_token','')
            is_valid, session_data = TokenService.verify_user_session(session_token)
            
            if not is_valid:
                logger.warning(f"[VERIFY] Session validation failed: {session_data}")
                return jsonify({'status':'error','message':session_data}), 401
            
            return jsonify({
                'status':'valid',
                'username':session_data['username'],
                'app_name':session_data['app_name'],
                'expires_at':session_data['expires_at'].isoformat()
            }), 200
        
        except Exception as e:
            logger.error(f"[VERIFY] Error: {str(e)}", exc_info=True)
            return jsonify({'status':'error','message':'An error occurred'}), 500
    
    # ============================================
    # Error handlers
    # ============================================
    @app.errorhandler(404)
    def not_found(error):
        return jsonify({'status':'error','message':'Endpoint not found'}), 404
    
    @app.errorhandler(500)
    def server_error(error):
        logger.error(f"Server error: {str(error)}", exc_info=True)
        return jsonify({'status':'error','message':'Internal server error'}), 500
    
    return app