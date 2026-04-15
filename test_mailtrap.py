# test_mailtrap.py
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import os
from dotenv import load_dotenv

# Load environment
load_dotenv(os.path.join(os.path.dirname(__file__), 'config', '.env'))

MAILTRAP_HOST = os.getenv('MAILTRAP_HOST')
MAILTRAP_PORT = int(os.getenv('MAILTRAP_PORT'))
MAILTRAP_USERNAME = os.getenv('MAILTRAP_USERNAME')
MAILTRAP_PASSWORD = os.getenv('MAILTRAP_PASSWORD')
EMAIL_FROM = os.getenv('EMAIL_FROM')

print("="*60)
print("TESTING MAILTRAP CONNECTION")
print("="*60)
print(f"\nHost: {MAILTRAP_HOST}")
print(f"Port: {MAILTRAP_PORT}")
print(f"Username: {MAILTRAP_USERNAME if MAILTRAP_USERNAME else '❌ NOT SET'}")
print(f"Password: {'*' * len(MAILTRAP_PASSWORD) if MAILTRAP_PASSWORD else '❌ NOT SET'}")
print(f"From: {EMAIL_FROM}\n")

if not MAILTRAP_USERNAME or not MAILTRAP_PASSWORD:
    print("❌ ERROR: Mailtrap credentials not set in config/.env")
    print("\nUpdate your config/.env with:")
    print("MAILTRAP_USERNAME=your_username")
    print("MAILTRAP_PASSWORD=your_password")
    exit(1)

try:
    print("Connecting to Mailtrap...")
    server = smtplib.SMTP(MAILTRAP_HOST, MAILTRAP_PORT)
    server.starttls()
    
    print("Authenticating...")
    server.login(MAILTRAP_USERNAME, MAILTRAP_PASSWORD)
    
    print("✅ MAILTRAP CONNECTION SUCCESSFUL!\n")
    
    # Send test email
    msg = MIMEMultipart()
    msg['From'] = EMAIL_FROM
    msg['To'] = MAILTRAP_USERNAME + '@mailtrap.io'  # Mailtrap test inbox
    msg['Subject'] = 'NSIF Test Email'
    
    body = "This is a test email from NSIF 2FA system.\n\nTest Code: ABC123"
    msg.attach(MIMEText(body, 'plain'))
    
    print("Sending test email...")
    server.send_message(msg)
    
    print("✅ TEST EMAIL SENT!")
    print("\nCheck your Mailtrap inbox at: https://mailtrap.io/")
    
    server.quit()
    
except Exception as e:
    print(f"❌ ERROR: {str(e)}")
    print("\nPossible issues:")
    print("1. Credentials are incorrect")
    print("2. Firewall is blocking connection to smtp.mailtrap.io:2525")
    print("3. Username/Password have special characters - try copying again")