#!/usr/bin/env python3
"""
Check Gmail API permissions and available data
"""

import os
import json
import pickle
from google.oauth2.credentials import Credentials
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError

TOKEN_FILE = 'token.pickle'

def check_permissions():
    """Check what permissions are available."""
    print("🔍 Checking Gmail API Permissions")
    print("=" * 50)
    
    if not os.path.exists(TOKEN_FILE):
        print("❌ No token file found. Please authenticate first.")
        return
    
    try:
        with open(TOKEN_FILE, 'rb') as token:
            credentials = pickle.load(token)
        
        # Refresh token if expired
        if credentials.expired and credentials.refresh_token:
            credentials.refresh(Request())
            with open(TOKEN_FILE, 'wb') as token:
                pickle.dump(credentials, token)
        
        print(f"✅ Token loaded successfully")
        print(f"📧 Scopes granted: {credentials.scopes}")
        print()
        
        # Build service
        service = build('gmail', 'v1', credentials=credentials)
        
        # Get user profile
        profile = service.users().getProfile(userId='me').execute()
        print(f"👤 Connected as: {profile['emailAddress']}")
        print(f"📊 Messages total: {profile.get('messagesTotal', 'Unknown')}")
        print(f"📥 Messages unread: {profile.get('threadsUnread', 'Unknown')}")
        print()
        
        # Check what we can access
        print("🔐 Permission Analysis:")
        
        scopes = credentials.scopes
        if 'https://www.googleapis.com/auth/gmail.readonly' in scopes:
            print("✅ Full Gmail access - Can read complete emails with headers and body")
        elif 'https://www.googleapis.com/auth/gmail.metadata' in scopes:
            print("✅ Metadata access - Can read email headers but not full body")
        else:
            print("⚠️  Limited access - Basic Gmail operations only")
        
        if 'https://www.googleapis.com/auth/gmail.modify' in scopes:
            print("✅ Modify access - Can modify emails (mark as read, move, etc.)")
        
        if 'https://www.googleapis.com/auth/gmail.labels' in scopes:
            print("✅ Labels access - Can manage Gmail labels")
        
        if 'https://www.googleapis.com/auth/userinfo.email' in scopes:
            print("✅ User info access - Can read user profile information")
        
        print()
        print("📋 Available Operations:")
        
        # Test different operations
        try:
            # Test inbox access
            results = service.users().messages().list(
                userId='me', 
                labelIds=['INBOX'],
                maxResults=1
            ).execute()
            print("✅ Can list inbox messages")
        except HttpError as e:
            print(f"❌ Cannot list inbox messages: {e}")
        
        try:
            # Test full message access
            if results.get('messages'):
                msg = service.users().messages().get(
                    userId='me', 
                    id=results['messages'][0]['id'],
                    format='full'
                ).execute()
                print("✅ Can read full email content (headers + body)")
            else:
                print("⚠️  No messages to test full content access")
        except HttpError as e:
            if "Metadata scope doesn't allow format FULL" in str(e):
                print("⚠️  Can only read email metadata (headers only)")
            else:
                print(f"❌ Cannot read full email content: {e}")
        
        print()
        print("🎯 Recommendation:")
        if 'https://www.googleapis.com/auth/gmail.readonly' in scopes:
            print("   You have full access! You can scrape complete emails with headers and body.")
        elif 'https://www.googleapis.com/auth/gmail.metadata' in scopes:
            print("   You have metadata access. You can scrape email headers but not the full body.")
            print("   To get full email content, request 'gmail.readonly' scope.")
        else:
            print("   Limited access. Consider requesting additional scopes for better functionality.")
        
    except Exception as e:
        print(f"❌ Error checking permissions: {e}")

if __name__ == '__main__':
    check_permissions()
