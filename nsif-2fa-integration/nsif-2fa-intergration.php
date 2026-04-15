<?php
/**
 * Plugin Name: NSIF 2FA Integration
 * Plugin URI: https://nsif.cm
 * Description: Integrate NSIF 2FA server with WordPress LDAP login
 * Version: 2.0.0
 * Author: NSIF Development Team
 * License: GPL2
 */

// Security check
if (!defined('ABSPATH')) {
    exit;
}

// Enable sessions
if (!session_id()) {
    session_start();
}

// Configuration
define('NSIF_2FA_SERVER', 'http://localhost:5000');
define('NSIF_2FA_INITIATE', NSIF_2FA_SERVER . '/auth/initiate-2fa');
define('NSIF_2FA_VALIDATE', NSIF_2FA_SERVER . '/auth/validate-otp');

// Handle 2FA requests
add_action('init', 'nsif_handle_requests');

function nsif_handle_requests() {
    // Handle OTP validation
    if (isset($_POST['nsif_action']) && $_POST['nsif_action'] === 'validate_otp') {
        nsif_validate_otp();
    }
    
    // Intercept login form
    if (isset($_POST['log']) && isset($_POST['pwd']) && !isset($_POST['nsif_initiated'])) {
        nsif_intercept_login();
    }
}

/**
 * Intercept login and initiate 2FA
 */
function nsif_intercept_login() {
    $username = isset($_POST['log']) ? sanitize_text_field($_POST['log']) : '';
    $password = isset($_POST['pwd']) ? $_POST['pwd'] : '';
    
    if (empty($username) || empty($password)) {
        return;
    }
    
    // Call Flask 2FA API
    $response = wp_remote_post(
        NSIF_2FA_INITIATE,
        array(
            'headers' => array('Content-Type' => 'application/json'),
            'body' => json_encode(array(
                'username' => $username,
                'password' => $password,
                'app_name' => 'ceh-wordpress'
            )),
            'timeout' => 10,
            'sslverify' => false
        )
    );
    
    if (is_wp_error($response)) {
        wp_die('Error: Could not connect to 2FA server. ' . $response->get_error_message());
    }
    
    $body = json_decode(wp_remote_retrieve_body($response), true);
    
    if (!isset($body['status']) || $body['status'] !== 'pending_otp') {
        wp_die('Error: ' . (isset($body['message']) ? $body['message'] : 'Unknown error'));
    }
    
    // Store session data
    $_SESSION['nsif_session_id'] = $body['session_id'];
    $_SESSION['nsif_username'] = $username;
    $_SESSION['nsif_password'] = $password;
    $_SESSION['nsif_2fa_pending'] = true;
    
    // Show OTP form
    nsif_show_otp_page();
    exit;
}

/**
 * Display OTP input page
 */
function nsif_show_otp_page() {
    ?>
    <!DOCTYPE html>
    <html>
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>NSIF 2FA - Verify OTP</title>
        <style>
            * {
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }
            
            body {
                font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen-Sans, Ubuntu, Cantarell, "Helvetica Neue", sans-serif;
                background: #f1f1f1;
                display: flex;
                justify-content: center;
                align-items: center;
                min-height: 100vh;
                padding: 20px;
            }
            
            .otp-container {
                background: white;
                padding: 50px 40px;
                border-radius: 8px;
                box-shadow: 0 1px 3px rgba(0,0,0,0.12), 0 1px 2px rgba(0,0,0,0.24);
                width: 100%;
                max-width: 400px;
                text-align: center;
            }
            
            .nsif-logo {
                font-size: 32px;
                font-weight: bold;
                color: #0073aa;
                margin-bottom: 30px;
            }
            
            h1 {
                color: #333;
                font-size: 24px;
                margin-bottom: 10px;
            }
            
            .otp-status {
                background: #e8f5e9;
                border-left: 4px solid #4caf50;
                padding: 15px;
                margin: 20px 0;
                border-radius: 4px;
                text-align: left;
            }
            
            .otp-status p {
                margin: 5px 0;
                color: #333;
                font-size: 14px;
            }
            
            .otp-status strong {
                color: #4caf50;
            }
            
            .form-group {
                margin-bottom: 20px;
                text-align: left;
            }
            
            label {
                display: block;
                margin-bottom: 8px;
                color: #333;
                font-weight: 500;
            }
            
            input[type="text"] {
                width: 100%;
                padding: 12px;
                border: 1px solid #ddd;
                border-radius: 4px;
                font-size: 16px;
                font-weight: bold;
                letter-spacing: 4px;
                text-align: center;
                font-family: monospace;
            }
            
            input[type="text"]:focus {
                outline: none;
                border-color: #0073aa;
                box-shadow: 0 0 5px rgba(0,115,170,0.3);
            }
            
            button {
                width: 100%;
                padding: 12px;
                background: #0073aa;
                color: white;
                border: none;
                border-radius: 4px;
                font-size: 16px;
                font-weight: 500;
                cursor: pointer;
                margin-top: 20px;
            }
            
            button:hover {
                background: #005a87;
            }
            
            button:active {
                background: #004570;
            }
            
            .info-box {
                background: #f9f9f9;
                border: 1px solid #eee;
                padding: 15px;
                border-radius: 4px;
                margin-top: 20px;
                font-size: 13px;
                color: #666;
            }
            
            .info-box p {
                margin: 8px 0;
            }
            
            .error {
                background: #ffebee;
                border: 1px solid #ef5350;
                color: #c62828;
                padding: 12px;
                border-radius: 4px;
                margin-bottom: 20px;
            }
        </style>
    </head>
    <body>
        <div class="otp-container">
            <div class="nsif-logo">NSIF 2FA</div>
            
            <h1>Verification Required</h1>
            
            <div class="otp-status">
                <p><strong>✓ Identity verified</strong></p>
                <p>An authentication code has been sent to your email.</p>
            </div>
            
            <form method="POST" action="">
                <div class="form-group">
                    <label for="otp_code">Enter Authentication Code</label>
                    <input 
                        type="text" 
                        id="otp_code"
                        name="nsif_otp_code" 
                        placeholder="0000"
                        maxlength="4"
                        autocomplete="off"
                        required
                        autofocus
                    >
                </div>
                
                <input type="hidden" name="nsif_action" value="validate_otp">
                
                <button type="submit">Verify & Login</button>
            </form>
            
            <div class="info-box">
                <p>📧 Check your email for the 4-digit code</p>
                <p>⏱️ Code expires in 5 minutes</p>
                <p>📧 Check spam folder if you don't see it</p>
            </div>
        </div>
    </body>
    </html>
    <?php
}

/**
 * Validate OTP code
 */
function nsif_validate_otp() {
    if (!isset($_SESSION['nsif_session_id']) || !isset($_SESSION['nsif_username'])) {
        wp_die('Session expired. Please try logging in again.');
    }
    
    $session_id = $_SESSION['nsif_session_id'];
    $otp_code = isset($_POST['nsif_otp_code']) ? sanitize_text_field($_POST['nsif_otp_code']) : '';
    $username = $_SESSION['nsif_username'];
    $password = $_SESSION['nsif_password'];
    
    if (empty($otp_code)) {
        wp_die('OTP code is required');
    }
    
    // Call Flask to validate OTP
    $response = wp_remote_post(
        NSIF_2FA_VALIDATE,
        array(
            'headers' => array('Content-Type' => 'application/json'),
            'body' => json_encode(array(
                'session_id' => $session_id,
                'otp_code' => $otp_code
            )),
            'timeout' => 10,
            'sslverify' => false
        )
    );
    
    if (is_wp_error($response)) {
        wp_die('Error connecting to 2FA server');
    }
    
    $body = json_decode(wp_remote_retrieve_body($response), true);
    
    if (!isset($body['status']) || $body['status'] !== 'success') {
        $error = isset($body['message']) ? $body['message'] : 'OTP validation failed';
        wp_die('Error: ' . $error . '. <a href="' . wp_login_url() . '">Try again</a>');
    }
    
    // OTP is valid - log user in via LDAP
    // Verify user exists in WordPress (LDAP auto-registers them)
    $user = get_user_by('login', $username);
    
    if (!$user) {
        // User doesn't exist, create from LDAP data
        $user_id = wp_create_user($username, $password, $username . '@nsif.cm');
        if (is_wp_error($user_id)) {
            wp_die('Error creating user');
        }
        $user = get_user_by('id', $user_id);
    }
    
    // Set WordPress cookie and log in
    wp_set_current_user($user->ID);
    wp_set_auth_cookie($user->ID);
    
    // Clear session data
    unset($_SESSION['nsif_session_id']);
    unset($_SESSION['nsif_username']);
    unset($_SESSION['nsif_password']);
    unset($_SESSION['nsif_2fa_pending']);
    
    // Redirect to dashboard
    wp_redirect(admin_url());
    exit;
}
?>