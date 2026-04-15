# run.py
"""
NSIF 2FA MFA Platform - Application Entry Point
Run this file to start the server
"""

import os
import sys

# Add current directory to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from backend.app import create_app

if __name__ == '__main__':
    # Create Flask app
    app = create_app()
    
    # Run server
    print("\n" + "=" * 70)
    print("NSIF 2FA MFA AUTHENTICATION PLATFORM")
    print("=" * 70)
    print("Server starting...")
    print("\n✅ API Server: http://localhost:5000")
    print("✅ Health Check: http://localhost:5000/health")
    print("\n⏹️  Press CTRL+C to stop the server")
    print("=" * 70 + "\n")
    
    app.run(
        host='0.0.0.0',
        port=5000,
        debug=True
    )