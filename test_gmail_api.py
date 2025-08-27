#!/usr/bin/env python3
"""
Test script for Gmail API connectivity
This script tests the OAuth2 credentials and Gmail API access
"""

import os
import json
import pickle
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

# OAuth 2.0 scopes
SCOPES = [
    'https://www.googleapis.com/auth/gmail.readonly',
    'https://www.googleapis.com/auth/gmail.modify',
    'https://www.googleapis.com/auth/gmail.labels',
    'https://www.googleapis.com/auth/gmail.metadata',
    'https://www.googleapis.com/auth/userinfo.email',
    'openid'
]

CREDENTIALS_FILE = 'credentials_old.json'
TOKEN_FILE = 'token.pickle'

def load_credentials():
    """Load OAuth credentials from file."""
    try:
        with open(CREDENTIALS_FILE, 'r') as creds_file:
            return json.load(creds_file)
    except FileNotFoundError:
        print(f"❌ Credentials file '{CREDENTIALS_FILE}' not found!")
        return None
    except json.JSONDecodeError:
        print(f"❌ Invalid JSON in credentials file '{CREDENTIALS_FILE}'!")
        return None

def get_gmail_service(credentials):
    """Build Gmail API service."""
    try:
        service = build('gmail', 'v1', credentials=credentials)
        return service
    except HttpError as error:
        print(f'❌ Gmail API error: {error}')
        return None

def test_credentials():
    """Test the credentials file."""
    print("🔍 Testing credentials file...")
    
    credentials_data = load_credentials()
    if not credentials_data:
        print("❌ Failed to load credentials")
        return False
    
    print("✅ Credentials file loaded successfully")
    
    # Check required fields
    if 'installed' not in credentials_data:
        print("❌ Missing 'installed' section in credentials")
        return False
    
    installed = credentials_data['installed']
    required_fields = ['client_id', 'client_secret', 'auth_uri', 'token_uri']
    for field in required_fields:
        if field not in installed:
            print(f"❌ Missing required field: installed.{field}")
            return False
    
    print("✅ All required credential fields present")
    return True

def test_gmail_api():
    """Test Gmail API connectivity."""
    print("\n🔍 Testing Gmail API connectivity...")
    
    try:
        # Check if token exists
        if os.path.exists(TOKEN_FILE):
            with open(TOKEN_FILE, 'rb') as token:
                credentials = pickle.load(token)
            
            # Refresh token if expired
            if credentials.expired and credentials.refresh_token:
                credentials.refresh(Request())
                with open(TOKEN_FILE, 'wb') as token:
                    pickle.dump(credentials, token)
            
            # Test API access
            service = get_gmail_service(credentials)
            if service:
                try:
                    # Get user profile
                    profile = service.users().getProfile(userId='me').execute()
                    print(f"✅ Connected to Gmail API as: {profile['emailAddress']}")
                    
                    # Test inbox access
                    results = service.users().messages().list(
                        userId='me', 
                        labelIds=['INBOX'],
                        maxResults=1
                    ).execute()
                    
                    if 'messages' in results:
                        print("✅ Successfully accessed inbox")
                        return True
                    else:
                        print("⚠️  Inbox is empty or inaccessible")
                        return True
                        
                except HttpError as error:
                    print(f"❌ Gmail API error: {error}")
                    return False
            else:
                print("❌ Failed to build Gmail service")
                return False
        else:
            print("⚠️  No token file found. You need to authenticate first.")
            print("   Run the Flask app and complete OAuth authentication.")
            return False
            
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        return False

def main():
    """Main test function."""
    print("🚀 Gmail API Connectivity Test")
    print("=" * 40)
    
    # Test 1: Credentials file
    credentials_ok = test_credentials()
    
    # Test 2: Gmail API (if credentials are ok)
    if credentials_ok:
        api_ok = test_gmail_api()
    else:
        api_ok = False
    
    # Summary
    print("\n" + "=" * 40)
    print("📋 Test Results Summary:")
    print(f"   Credentials: {'✅ OK' if credentials_ok else '❌ FAILED'}")
    print(f"   Gmail API: {'✅ OK' if api_ok else '❌ FAILED'}")
    
    if credentials_ok and api_ok:
        print("\n🎉 All tests passed! Your setup is ready to use.")
        print("   Run 'python app.py' to start the web application.")
    elif not credentials_ok:
        print("\n🔧 To fix credentials:")
        print("   1. Go to Google Cloud Console")
        print("   2. Enable Gmail API")
        print("   3. Create OAuth2 credentials")
        print("   4. Download and save as 'credentials_old.json'")
    elif not api_ok:
        print("\n🔧 To fix API access:")
        print("   1. Run the Flask app: python app.py")
        print("   2. Complete OAuth authentication in browser")
        print("   3. Run this test again")

if __name__ == '__main__':
    main()
