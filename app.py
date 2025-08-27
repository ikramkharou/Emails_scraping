import os
import json
import base64
import time
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash, send_file, Response
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import Flow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
import pickle
from datetime import datetime
import re
from dotenv import load_dotenv
from imap_scraper import create_imap_scraper, IMAPScraper

# Load environment variables
load_dotenv()

app = Flask(__name__)
app.secret_key = os.getenv('SECRET_KEY', 'your-secret-key-here')

# Configure session to be more persistent
app.config['PERMANENT_SESSION_LIFETIME'] = 3600  # 1 hour

# Global log queue for SSE (in-memory storage)
log_queues = {}
current_session_id = None

# OAuth 2.0 credentials - Use full Gmail access for complete email scraping
# Using ONLY the most permissive scope to force full access
SCOPES = [
    'https://mail.google.com/'  # Full access to Gmail (most permissive) - ONLY THIS SCOPE
]

# Load credentials from file
def load_credentials():
    try:
        with open('credentials_old.json', 'r') as creds_file:
            return json.load(creds_file)
    except FileNotFoundError:
        return None

CREDENTIALS_FILE = 'credentials_old.json'
TOKEN_FILE = 'token.pickle'

def get_gmail_service(credentials):
    """Build Gmail API service."""
    try:
        service = build('gmail', 'v1', credentials=credentials)
        return service
    except HttpError as error:
        print(f'An error occurred: {error}')
        return None

def parse_raw_email(raw_data):
    """Parse raw email data to extract headers and body."""
    try:
        # Decode raw data
        raw_bytes = base64.urlsafe_b64decode(raw_data)
        raw_text = raw_bytes.decode('utf-8', errors='ignore')
        
        # Split headers and body
        parts = raw_text.split('\r\n\r\n', 1)
        if len(parts) < 2:
            return None, None
        
        headers_text, body_text = parts
        
        # Parse headers
        headers = {}
        for line in headers_text.split('\r\n'):
            if ':' in line:
                key, value = line.split(':', 1)
                headers[key.strip()] = value.strip()
        
        return headers, body_text
    except Exception as e:
        print(f"❌ Error parsing raw email: {e}")
        return None, None

def parse_email_content(email_data):
    """Parse email content and extract filtered raw headers and body with enhanced Gmail API support."""
    try:
        # Check if this is raw format data
        if 'raw' in email_data:
            print("📧 Processing raw format email")
            raw_headers, raw_body = parse_raw_email(email_data['raw'])
            if raw_headers and raw_body:
                # Filter headers
                excluded_headers = {
                    'DKIM-Signature', 'DMARC-Results', 'Received', 'Authentication-Results',
                    'ARC-Authentication-Results', 'Return-Path', 'Delivered-To',
                    'X-Received', 'X-Google-Smtp-Source', 'X-Received-By', 'X-Received-From'
                }
                
                parsed_headers = {}
                for key, value in raw_headers.items():
                    if key not in excluded_headers:
                        parsed_headers[key] = value
                
                return {
                    'id': email_data['id'],
                    'threadId': email_data.get('threadId', ''),
                    'headers': parsed_headers,
                    'body_plain': raw_body,
                    'body_html': '',
                    'snippet': email_data.get('snippet', ''),
                    'internalDate': email_data.get('internalDate', ''),
                    'format': 'raw',
                    'sizeEstimate': email_data.get('sizeEstimate', 0),
                    'labelIds': email_data.get('labelIds', []),
                    'historyId': email_data.get('historyId', ''),
                    'payload_mime_type': 'raw'
                }
        
        # Extract headers (filtered) for other formats
        headers = email_data.get('payload', {}).get('headers', [])
        parsed_headers = {}
        
        # Headers to exclude
        excluded_headers = {
            'DKIM-Signature', 'DMARC-Results', 'Received', 'Authentication-Results',
            'ARC-Authentication-Results', 'Return-Path', 'Delivered-To',
            'X-Received', 'X-Google-Smtp-Source', 'X-Received-By', 'X-Received-From'
        }
        
        # Get filtered raw headers
        for header in headers:
            header_name = header['name']
            header_value = header['value']
            
            # Skip excluded headers
            if header_name in excluded_headers:
                continue
                
            # Store filtered headers
            parsed_headers[header_name] = header_value
        
        # Extract body content with enhanced parsing
        body = ""
        body_html = ""
        
        def extract_body_from_parts(parts, depth=0):
            """Recursively extract body from multipart messages with better handling."""
            nonlocal body, body_html
            
            for part in parts:
                mime_type = part.get('mimeType', '')
                part_id = part.get('partId', '')
                
                print(f"📧 Processing part {part_id} with mimeType: {mime_type} (depth: {depth})")
                
                # Handle text content
                if mime_type in ['text/plain', 'text/html']:
                    if 'data' in part.get('body', {}):
                        try:
                            decoded_data = base64.urlsafe_b64decode(part['body']['data']).decode('utf-8', errors='ignore')
                            if mime_type == 'text/plain':
                                body += decoded_data
                                print(f"✅ Extracted plain text body: {len(decoded_data)} characters")
                            else:
                                body_html += decoded_data
                                print(f"✅ Extracted HTML body: {len(decoded_data)} characters")
                        except Exception as e:
                            print(f"❌ Error decoding {mime_type}: {e}")
                    elif 'attachmentId' in part.get('body', {}):
                        print(f"📎 Found attachment in {mime_type} part")
                
                # Handle nested parts
                elif 'parts' in part:
                    print(f"📧 Found nested parts in {mime_type}")
                    extract_body_from_parts(part['parts'], depth + 1)
                
                # Handle other content types
                else:
                    print(f"📧 Unhandled mimeType: {mime_type}")
                    if 'data' in part.get('body', {}):
                        try:
                            decoded_data = base64.urlsafe_b64decode(part['body']['data']).decode('utf-8', errors='ignore')
                            body += f"[{mime_type} content: {decoded_data[:200]}...]"
                            print(f"✅ Extracted {mime_type} content: {len(decoded_data)} characters")
                        except Exception as e:
                            print(f"❌ Error decoding {mime_type}: {e}")
        
        # Extract body from payload with enhanced logic
        payload = email_data.get('payload', {})
        mime_type = payload.get('mimeType', 'unknown')
        print(f"📧 Processing main payload with mimeType: {mime_type}")
        
        # Handle different payload structures
        if 'parts' in payload:
            # Multipart message
            print(f"📧 Multipart message with {len(payload['parts'])} parts")
            extract_body_from_parts(payload['parts'])
        elif mime_type in ['text/plain', 'text/html']:
            # Simple text message
            print(f"📧 Simple {mime_type} message")
            if 'data' in payload.get('body', {}):
                try:
                    decoded_data = base64.urlsafe_b64decode(payload['body']['data']).decode('utf-8', errors='ignore')
                    if mime_type == 'text/html':
                        body_html = decoded_data
                        print(f"✅ Extracted simple HTML body: {len(body_html)} characters")
                    else:
                        body = decoded_data
                        print(f"✅ Extracted simple plain text body: {len(body)} characters")
                except Exception as e:
                    print(f"❌ Error decoding simple {mime_type}: {e}")
            else:
                print(f"⚠️  No body data found in simple {mime_type} message")
        else:
            # Other content types
            print(f"📧 Other content type: {mime_type}")
            if 'data' in payload.get('body', {}):
                try:
                    decoded_data = base64.urlsafe_b64decode(payload['body']['data']).decode('utf-8', errors='ignore')
                    body += f"[{mime_type} content: {decoded_data[:200]}...]"
                    print(f"✅ Extracted {mime_type} content: {len(decoded_data)} characters")
                except Exception as e:
                    print(f"❌ Error decoding {mime_type}: {e}")
            else:
                print(f"⚠️  No body data found in {mime_type} message")
        
        # Also try to get snippet if no body content
        if not body and not body_html:
            snippet = email_data.get('snippet', '')
            if snippet:
                body = f"[Email snippet: {snippet}]"
                print(f"✅ Using email snippet: {len(snippet)} characters")
            else:
                body = "[Email body not available with current permissions]"
                print(f"⚠️  No body content extracted, using placeholder")
        
        # Determine format type
        if body and body != "[Email body not available with current permissions]":
            format_type = 'full'
            print(f"✅ Email has body content - format: {format_type}")
        elif parsed_headers:
            format_type = 'metadata'
            print(f"⚠️  Email has headers only - format: {format_type}")
        else:
            format_type = 'minimal'
            print(f"⚠️  Email has minimal data - format: {format_type}")
        
        return {
            'id': email_data['id'],
            'threadId': email_data.get('threadId', ''),
            'headers': parsed_headers,
            'body_plain': body,
            'body_html': body_html,
            'snippet': email_data.get('snippet', ''),
            'internalDate': email_data.get('internalDate', ''),
            'format': format_type,
            'sizeEstimate': email_data.get('sizeEstimate', 0),
            'labelIds': email_data.get('labelIds', []),
            'historyId': email_data.get('historyId', ''),
            'payload_mime_type': mime_type
        }
    except Exception as e:
        print(f"❌ Error parsing email: {e}")
        return None

@app.route('/')
def index():
    """Main page with email input and authentication."""
    return render_template('index.html')

@app.route('/authenticate', methods=['POST'])
def authenticate():
    """Start OAuth authentication flow."""
    email = request.form.get('email')
    if not email:
        flash('Please enter an email address', 'error')
        return redirect(url_for('index'))
    
    session['target_email'] = email
    
    try:
        credentials_data = load_credentials()
        if not credentials_data:
            flash('Credentials file not found. Please check credentials_old.json', 'error')
            return redirect(url_for('index'))
        
        # Clear any existing tokens to force fresh authentication
        if os.path.exists(TOKEN_FILE):
            os.remove(TOKEN_FILE)
        
        flow = Flow.from_client_secrets_file(
            CREDENTIALS_FILE, 
            scopes=SCOPES,
            redirect_uri='http://localhost:5000/oauth2callback'
        )
        
        auth_url, state = flow.authorization_url(
            access_type='offline',
            include_granted_scopes='true',
            prompt='consent'  # Force consent screen to ensure all scopes are granted
        )
        
        # Store the state parameter
        session['oauth_state'] = state
        print(f"🔑 Starting OAuth flow with scopes: {SCOPES}")
        return redirect(auth_url)
        
    except Exception as e:
        flash(f'Authentication error: {str(e)}', 'error')
        return redirect(url_for('index'))

@app.route('/oauth2callback')
def oauth2callback():
    """Handle OAuth callback and token generation."""
    try:
        oauth_state = session.get('oauth_state')
        if not oauth_state:
            print("⚠️  No OAuth state found in session, attempting to proceed without state...")
            # Try to proceed without state for better compatibility
            flash('OAuth state not found, but attempting to complete authentication...', 'warning')
        
        # Recreate the flow with more flexible scope handling
        flow = Flow.from_client_secrets_file(
            CREDENTIALS_FILE, 
            scopes=SCOPES,
            redirect_uri='http://localhost:5000/oauth2callback',
            state=oauth_state if oauth_state else None
        )
        
        # Recreate the flow with more flexible scope handling
        flow = Flow.from_client_secrets_file(
            CREDENTIALS_FILE, 
            scopes=SCOPES,
            redirect_uri='http://localhost:5000/oauth2callback',
            state=oauth_state
        )
        
        # Try to fetch token with enhanced scope change handling
        try:
            flow.fetch_token(authorization_response=request.url)
            credentials = flow.credentials
            print(f"✅ Successfully got credentials")
        except Exception as token_error:
            error_str = str(token_error)
            print(f"⚠️  Token fetch error: {error_str}")
            
            # If state is missing, try a fresh flow without state
            if "No OAuth state found" in error_str or not oauth_state:
                print("🔄 Attempting fresh OAuth flow without state...")
                try:
                    fresh_flow = Flow.from_client_secrets_file(
                        CREDENTIALS_FILE, 
                        scopes=SCOPES,
                        redirect_uri='http://localhost:5000/oauth2callback'
                    )
                    fresh_flow.fetch_token(authorization_response=request.url)
                    credentials = fresh_flow.credentials
                    print(f"✅ Successfully got credentials with fresh flow")
                except Exception as fresh_error:
                    print(f"❌ Fresh flow also failed: {fresh_error}")
                    raise fresh_error
            elif "Scope has changed" in error_str:
                print(f"🔄 Scope change detected, attempting to handle gracefully...")
                
                # Extract authorization code from URL
                from urllib.parse import urlparse, parse_qs
                parsed_url = urlparse(request.url)
                auth_code = parse_qs(parsed_url.query).get('code', [None])[0]
                
                if not auth_code:
                    raise Exception("No authorization code found in callback URL")
                
                # Try multiple approaches to handle scope changes
                approaches = [
                    # Approach 1: Use the same scopes but with manual code exchange
                    lambda: Flow.from_client_secrets_file(
                        CREDENTIALS_FILE, 
                        scopes=SCOPES,
                        redirect_uri='http://localhost:5000/oauth2callback',
                        state=oauth_state
                    ),
                    # Approach 2: Use more permissive scope handling
                    lambda: Flow.from_client_secrets_file(
                        CREDENTIALS_FILE, 
                        scopes=SCOPES + ['https://www.googleapis.com/auth/gmail.metadata'],
                        redirect_uri='http://localhost:5000/oauth2callback',
                        state=oauth_state
                    ),
                    # Approach 3: Fresh flow without state
                    lambda: Flow.from_client_secrets_file(
                        CREDENTIALS_FILE, 
                        scopes=SCOPES,
                        redirect_uri='http://localhost:5000/oauth2callback'
                    )
                ]
                
                credentials = None
                for i, approach in enumerate(approaches, 1):
                    try:
                        print(f"🔄 Trying approach {i}...")
                        flow_attempt = approach()
                        
                        # Try to fetch token with the authorization code
                        flow_attempt.fetch_token(code=auth_code)
                        credentials = flow_attempt.credentials
                        print(f"✅ Successfully got credentials with approach {i}")
                        break
                        
                    except Exception as e:
                        print(f"❌ Approach {i} failed: {e}")
                        continue
                
                if not credentials:
                    print(f"❌ All approaches failed")
                    raise token_error
            else:
                raise token_error
        
        # Get the actually granted scopes
        if hasattr(credentials, 'scopes') and credentials.scopes:
            granted_scopes = credentials.scopes
            print(f"🔑 Granted scopes: {granted_scopes}")
            
            # Check if we have the essential scopes we requested
            requested_scopes_set = set(SCOPES)
            granted_scopes_set = set(granted_scopes)
            
            # Check if all our requested scopes are granted (ignore additional ones)
            missing_scopes = requested_scopes_set - granted_scopes_set
            if missing_scopes:
                print(f"⚠️  Missing requested scopes: {missing_scopes}")
                flash(f'⚠️  Warning: Some requested permissions were not granted: {missing_scopes}', 'warning')
            else:
                print(f"✅ All requested scopes granted!")
                
            # Check for additional scopes granted by Google
            additional_scopes = granted_scopes_set - requested_scopes_set
            if additional_scopes:
                print(f"✅ Additional scopes granted by Google: {additional_scopes}")
        else:
            # Fallback to our requested scopes
            granted_scopes = SCOPES
            print(f"⚠️  No scopes found, using requested scopes: {granted_scopes}")
        
        # Check if we have the essential scope for email body content
        has_readonly = 'https://www.googleapis.com/auth/gmail.readonly' in granted_scopes
        has_modify = 'https://www.googleapis.com/auth/gmail.modify' in granted_scopes
        has_full_gmail = 'https://mail.google.com/' in granted_scopes
        
        if not (has_readonly or has_modify or has_full_gmail):
            flash('⚠️  Warning: You only granted metadata access. You need to grant "Read Gmail" permissions to get email body content. Please re-authenticate.', 'warning')
        else:
            flash('✅ Authentication successful! You have full Gmail access.', 'success')
        
        # Save credentials with the granted scopes (including any additional ones)
        with open(TOKEN_FILE, 'wb') as token:
            pickle.dump(credentials, token)
        
        session['credentials'] = {
            'token': credentials.token,
            'refresh_token': credentials.refresh_token,
            'token_uri': credentials.token_uri,
            'client_id': credentials.client_id,
            'client_secret': credentials.client_secret,
            'scopes': granted_scopes  # Use the actual granted scopes
        }
        
        # Clean up OAuth state
        session.pop('oauth_state', None)
        
        flash('Authentication successful!', 'success')
        return redirect(url_for('dashboard'))
        
    except Exception as e:
        print(f"❌ OAuth callback error: {str(e)}")
        flash(f'OAuth callback error: {str(e)}', 'error')
        return redirect(url_for('index'))

@app.route('/dashboard')
def dashboard():
    """Dashboard page for email scraping."""
    # Check for either Gmail API credentials or IMAP credentials
    if 'credentials' not in session and 'imap_credentials' not in session:
        flash('Please authenticate first', 'error')
        return redirect(url_for('index'))
    
    return render_template('dashboard.html')

@app.route('/search_and_scrape_emails')
def search_and_scrape_emails():
    """Search all emails from inbox and scrape them in one operation."""
    if 'credentials' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    # Check permissions first
    creds_data = session['credentials']
    scopes = creds_data.get('scopes', [])
    has_readonly = 'https://www.googleapis.com/auth/gmail.readonly' in scopes
    has_modify = 'https://www.googleapis.com/auth/gmail.modify' in scopes
    has_metadata = 'https://www.googleapis.com/auth/gmail.metadata' in scopes
    has_full_gmail = 'https://mail.google.com/' in scopes  # Check for the most permissive scope
    
    print(f"🔍 Checking permissions - Scopes: {scopes}")
    print(f"🔍 Has readonly: {has_readonly}, Has modify: {has_modify}, Has metadata: {has_metadata}, Has full Gmail: {has_full_gmail}")
    
    # Check if we have any scope that allows full content access
    has_full_access = has_readonly or has_modify or has_full_gmail
    
    if not has_full_access:
        return jsonify({
            'error': '❌ Insufficient permissions! You only have metadata access which cannot retrieve email body content.\n\n'
                     '🔑 Required: "Read Gmail" permission (gmail.readonly, gmail.modify, or https://mail.google.com/ scope)\n'
                     '📧 Current: Only metadata access (gmail.metadata scope)\n\n'
                     '💡 Solution: Click "Re-Authenticate" and make sure to grant "Read Gmail" permissions when prompted.',
            'needs_reauth': True,
            'current_scopes': scopes,
            'required_scopes': ['https://www.googleapis.com/auth/gmail.readonly', 'https://www.googleapis.com/auth/gmail.modify', 'https://mail.google.com/']
        }), 403
    
    try:
        # Add initial log to stream
        add_log_to_stream('🚀 Starting Gmail extraction process...', 'info')
        add_log_to_stream('🔧 Initializing Gmail API connection...', 'processing')
        
        # Rebuild credentials object
        creds_data = session['credentials']
        credentials = Credentials(
            token=creds_data['token'],
            refresh_token=creds_data.get('refresh_token'),
            token_uri=creds_data['token_uri'],
            client_id=creds_data['client_id'],
            client_secret=creds_data['client_secret'],
            scopes=creds_data['scopes']
        )
        
        # Refresh token if expired
        if credentials.expired and credentials.refresh_token:
            add_log_to_stream('🔄 Refreshing expired token...', 'processing')
            credentials.refresh(Request())
            session['credentials']['token'] = credentials.token
            with open(TOKEN_FILE, 'wb') as token:
                pickle.dump(credentials, token)
            add_log_to_stream('✅ Token refreshed successfully', 'success')
        
        # Build Gmail service
        add_log_to_stream('🔧 Building Gmail API service...', 'processing')
        service = get_gmail_service(credentials)
        if not service:
            add_log_to_stream('❌ Failed to build Gmail service', 'error')
            return jsonify({'error': 'Failed to build Gmail service'}), 500
        add_log_to_stream('✅ Gmail service built successfully', 'success')
        
        # Get user info
        add_log_to_stream('👤 Getting user profile...', 'processing')
        user_info = service.users().getProfile(userId='me').execute()
        user_email = user_info['emailAddress']
        add_log_to_stream(f'✅ Connected as: {user_email}', 'success')
        
        # Step 1: Search ALL emails from inbox
        add_log_to_stream('🔍 Searching all emails from inbox...', 'processing')
        all_messages = []
        page_token = None
        page_count = 0
        
        while True:
            page_count += 1
            add_log_to_stream(f'📄 Fetching page {page_count} of emails...', 'info')
            
            results = service.users().messages().list(
                userId='me',
                labelIds=['INBOX'],
                maxResults=500,
                pageToken=page_token
            ).execute()
            
            messages = results.get('messages', [])
            all_messages.extend(messages)
            add_log_to_stream(f'📧 Found {len(messages)} emails on page {page_count}', 'info')
            
            page_token = results.get('nextPageToken')
            if not page_token:
                break
        
        message_ids = [msg['id'] for msg in all_messages]
        total_emails_found = len(all_messages)
        add_log_to_stream(f'📊 Total emails found: {total_emails_found}', 'success')
        
        # Step 2: Scrape all found emails
        add_log_to_stream(f'🔄 Starting extraction of {len(message_ids)} emails...', 'processing')
        
        emails_data = []
        success_count = 0
        error_count = 0
        
        for i, message_id in enumerate(message_ids):
            current_progress = int((i / len(message_ids)) * 100)
            add_log_to_stream(f'📧 Processing email {i+1}/{len(message_ids)} ({current_progress}%)', 'processing')
            
            # Try multiple formats to get the best content
            msg = None
            format_used = None
            
            # First try: Full format (best for body content)
            try:
                msg = service.users().messages().get(
                    userId='me', 
                    id=message_id,
                    format='full'
                ).execute()
                format_used = 'full'
                add_log_to_stream(f'✅ Email {i+1}: Got full format', 'success')
            except HttpError as e:
                add_log_to_stream(f'⚠️  Email {i+1}: Full format failed, trying raw...', 'warning')
                
                # Second try: Raw format (alternative for full content)
                try:
                    msg = service.users().messages().get(
                        userId='me', 
                        id=message_id,
                        format='raw'
                    ).execute()
                    format_used = 'raw'
                    add_log_to_stream(f'✅ Email {i+1}: Got raw format', 'success')
                except HttpError as e2:
                    add_log_to_stream(f'⚠️  Email {i+1}: Raw format failed, trying metadata...', 'warning')
                    
                    # Third try: Metadata format with all headers
                    try:
                        msg = service.users().messages().get(
                            userId='me', 
                            id=message_id,
                            format='metadata',
                            metadataHeaders=['*']  # Get ALL headers
                        ).execute()
                        format_used = 'metadata'
                        add_log_to_stream(f'✅ Email {i+1}: Got metadata format', 'success')
                    except HttpError as e3:
                        add_log_to_stream(f'❌ Email {i+1}: All formats failed', 'error')
                        error_count += 1
                        continue
            
            if msg:
                parsed_email = parse_email_content(msg)
                if parsed_email:
                    # Add format info to the parsed email
                    parsed_email['api_format_used'] = format_used
                    emails_data.append(parsed_email)
                    success_count += 1
                    add_log_to_stream(f'✅ Email {i+1}: Successfully parsed using {format_used} format', 'success')
                else:
                    add_log_to_stream(f'❌ Email {i+1}: Failed to parse content', 'error')
                    error_count += 1
            else:
                add_log_to_stream(f'❌ Email {i+1}: No message data retrieved', 'error')
                error_count += 1
        
        add_log_to_stream(f'📊 Extraction Summary:', 'info')
        add_log_to_stream(f'   ✅ Successful: {success_count}', 'success')
        add_log_to_stream(f'   ❌ Failed: {error_count}', 'warning')
        add_log_to_stream(f'   📧 Total processed: {len(message_ids)}', 'info')
        
        # Save scraped data
        add_log_to_stream('💾 Saving extracted data to file...', 'processing')
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f'scraped_emails_{timestamp}.json'
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump({
                'user_email': user_email,
                'scrape_time': datetime.now().isoformat(),
                'total_emails': len(message_ids),
                'scraped_emails': len(emails_data),
                'success_count': success_count,
                'error_count': error_count,
                'emails': emails_data
            }, f, indent=2, ensure_ascii=False)
        
        add_log_to_stream(f'✅ Data saved to: {filename}', 'success')
        add_log_to_stream('🎉 Extraction completed successfully!', 'complete')
        
        return jsonify({
            'success': True,
            'emails_count': len(emails_data),
            'user_email': user_email,
            'filename': filename,
            'total_emails': len(message_ids),
            'success_count': success_count,
            'error_count': error_count,
            'emails': emails_data[:20],  # Return first 20 emails for preview
            'message': f'Successfully scraped {len(emails_data)} emails from {len(message_ids)} total emails'
        })
        
    except Exception as e:
        add_log_to_stream(f'❌ Fatal error during extraction: {str(e)}', 'error')
        return jsonify({'error': f'Search and scrape error: {str(e)}'}), 500



@app.route('/check_permissions')
def check_permissions():
    """Check current Gmail API permissions."""
    if 'credentials' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    try:
        creds_data = session['credentials']
        scopes = creds_data.get('scopes', [])
        
        permissions = {
            'has_full_access': 'https://www.googleapis.com/auth/gmail.readonly' in scopes,
            'has_metadata_access': 'https://www.googleapis.com/auth/gmail.metadata' in scopes,
            'has_modify_access': 'https://www.googleapis.com/auth/gmail.modify' in scopes,
            'has_labels_access': 'https://www.googleapis.com/auth/gmail.labels' in scopes,
            'has_compose_access': 'https://www.googleapis.com/auth/gmail.compose' in scopes,
            'has_send_access': 'https://www.googleapis.com/auth/gmail.send' in scopes,
            'has_full_gmail': 'https://mail.google.com/' in scopes,
            'granted_scopes': scopes
        }
        
        # Check if we have the minimum required scope for full content
        has_minimum_scope = permissions['has_full_access'] or permissions['has_modify_access'] or permissions['has_full_gmail']
        
        return jsonify({
            'success': True,
            'permissions': permissions,
            'can_get_full_content': has_minimum_scope,
            'message': 'Full content available' if has_minimum_scope else 'Only metadata available - re-authentication needed',
            'needs_reauth': not has_minimum_scope
        })
        
    except Exception as e:
        return jsonify({'error': f'Error checking permissions: {str(e)}'}), 500

@app.route('/reauth')
def reauth():
    """Force re-authentication with full scopes."""
    # Clear existing credentials and tokens
    session.pop('credentials', None)
    session.pop('target_email', None)
    session.pop('oauth_state', None)
    
    # Remove token file to force fresh authentication
    if os.path.exists(TOKEN_FILE):
        os.remove(TOKEN_FILE)
    
    # Redirect to authentication page
    flash('Authentication cleared. Please re-authenticate with full Gmail permissions', 'info')
    return redirect(url_for('index'))

@app.route('/clear_auth')
def clear_auth():
    """Clear all authentication data and tokens."""
    # Clear session data
    session.clear()
    
    # Remove token file
    if os.path.exists(TOKEN_FILE):
        os.remove(TOKEN_FILE)
    
    # Also remove any other credential files that might exist
    for file_path in ['credentials.json', 'credentials_old.json']:
        if os.path.exists(file_path):
            try:
                os.remove(file_path)
                print(f"✅ Removed: {file_path}")
            except Exception as e:
                print(f"❌ Error removing {file_path}: {e}")
    
    flash('All authentication data cleared. You can now start fresh.', 'success')
    return redirect(url_for('index'))

@app.route('/force_clear_auth')
def force_clear_auth():
    """Force clear all authentication data and provide detailed feedback."""
    cleared_files = []
    
    # Clear session data
    session.clear()
    cleared_files.append("Session data")
    
    # Remove token files
    for file_path in ['token.pickle', 'credentials.json', 'credentials_old.json']:
        if os.path.exists(file_path):
            try:
                os.remove(file_path)
                cleared_files.append(file_path)
            except Exception as e:
                print(f"❌ Error removing {file_path}: {e}")
    
    if cleared_files:
        flash(f'✅ Successfully cleared: {", ".join(cleared_files)}. Please re-authenticate.', 'success')
    else:
        flash('ℹ️ No authentication files found to clear.', 'info')
    
    return redirect(url_for('index'))

# IMAP Scraping Routes
@app.route('/imap_scrape', methods=['POST'])
def imap_scrape():
    """Scrape emails using IMAP protocol."""
    try:
        data = request.get_json()
        email_address = data.get('email_address')
        password = data.get('password')
        folder = data.get('folder', 'INBOX')
        search_criteria = data.get('search_criteria', 'ALL')
        max_emails = data.get('max_emails', None)
        imap_server = data.get('imap_server', None)
        imap_port = data.get('imap_port', None)
        use_ssl = data.get('use_ssl', True)
        
        if not email_address or not password:
            return jsonify({'error': 'Email address and password are required'}), 400
        
        # Add initial log
        add_log_to_stream('🚀 Starting IMAP email extraction...', 'info')
        add_log_to_stream(f'📧 Connecting to {email_address}...', 'processing')
        
        # Create IMAP scraper
        scraper = create_imap_scraper(
            email_address=email_address,
            password=password,
            imap_server=imap_server,
            imap_port=imap_port,
            use_ssl=use_ssl
        )
        
        if not scraper:
            add_log_to_stream('❌ Failed to connect to IMAP server', 'error')
            return jsonify({'error': 'Failed to connect to IMAP server. Check your credentials and server settings.'}), 500
        
        add_log_to_stream(f'✅ Connected to IMAP server: {scraper.imap_server}', 'success')
        
        # Get available folders
        folders = scraper.get_folders()
        add_log_to_stream(f'📁 Available folders: {", ".join(folders[:5])}{"..." if len(folders) > 5 else ""}', 'info')
        
        # Progress callback function
        def progress_callback(message, log_type):
            add_log_to_stream(message, log_type)
        
        # Scrape emails
        add_log_to_stream(f'🔍 Searching emails in folder: {folder}', 'processing')
        emails = scraper.scrape_emails(
            folder=folder,
            search_criteria=search_criteria,
            max_emails=max_emails,
            progress_callback=progress_callback
        )
        
        if not emails:
            add_log_to_stream('⚠️ No emails found or failed to scrape', 'warning')
            scraper.disconnect()
            return jsonify({'error': 'No emails found or failed to scrape'}), 404
        
        # Save to file
        add_log_to_stream('💾 Saving scraped data to file...', 'processing')
        filename = scraper.save_emails_to_file(emails)
        
        if filename:
            add_log_to_stream(f'✅ Data saved to: {filename}', 'success')
        else:
            add_log_to_stream('⚠️ Failed to save data to file', 'warning')
        
        # Store IMAP credentials in session for dashboard access
        session['imap_credentials'] = {
            'email_address': email_address,
            'password': password,
            'imap_server': scraper.imap_server,
            'imap_port': imap_port,
            'use_ssl': use_ssl,
            'connected': True
        }
        session['user_email'] = email_address
        session['auth_method'] = 'imap'
        
        # Disconnect
        scraper.disconnect()
        add_log_to_stream('🔌 Disconnected from IMAP server', 'info')
        
        return jsonify({
            'success': True,
            'emails_count': len(emails),
            'user_email': email_address,
            'filename': filename,
            'imap_server': scraper.imap_server,
            'folder': folder,
            'emails': emails[:20],  # Return first 20 emails for preview
            'message': f'Successfully scraped {len(emails)} emails using IMAP'
        })
        
    except Exception as e:
        add_log_to_stream(f'❌ IMAP scraping error: {str(e)}', 'error')
        return jsonify({'error': f'IMAP scraping error: {str(e)}'}), 500

@app.route('/test_imap_connection', methods=['POST'])
def test_imap_connection():
    """Test IMAP connection without scraping."""
    try:
        data = request.get_json()
        email_address = data.get('email_address')
        password = data.get('password')
        imap_server = data.get('imap_server', None)
        imap_port = data.get('imap_port', None)
        use_ssl = data.get('use_ssl', True)
        
        if not email_address or not password:
            return jsonify({'error': 'Email address and password are required'}), 400
        
        add_log_to_stream(f'🔍 Testing IMAP connection to {email_address}...', 'processing')
        
        # Create IMAP scraper
        scraper = create_imap_scraper(
            email_address=email_address,
            password=password,
            imap_server=imap_server,
            imap_port=imap_port,
            use_ssl=use_ssl
        )
        
        if not scraper:
            add_log_to_stream('❌ IMAP connection test failed', 'error')
            return jsonify({'error': 'Failed to connect to IMAP server'}), 500
        
        # Get folders
        folders = scraper.get_folders()
        
        # Get email count in INBOX
        email_ids = scraper.search_emails('INBOX', 'ALL')
        inbox_count = len(email_ids)
        
        # Disconnect
        scraper.disconnect()
        
        add_log_to_stream('✅ IMAP connection test successful', 'success')
        
        return jsonify({
            'success': True,
            'imap_server': scraper.imap_server,
            'folders': folders,
            'inbox_count': inbox_count,
            'message': f'Successfully connected to {scraper.imap_server}'
        })
        
    except Exception as e:
        add_log_to_stream(f'❌ IMAP connection test error: {str(e)}', 'error')
        return jsonify({'error': f'IMAP connection test error: {str(e)}'}), 500

@app.route('/store_imap_credentials', methods=['POST'])
def store_imap_credentials():
    """Store IMAP credentials in session without scraping."""
    try:
        data = request.get_json()
        email_address = data.get('email_address')
        password = data.get('password')
        imap_server = data.get('imap_server', None)
        imap_port = data.get('imap_port', None)
        use_ssl = data.get('use_ssl', True)
        
        if not email_address or not password:
            return jsonify({'error': 'Email address and password are required'}), 400
        
        # Store IMAP credentials in session
        session['imap_credentials'] = {
            'email_address': email_address,
            'password': password,
            'imap_server': imap_server,
            'imap_port': imap_port,
            'use_ssl': use_ssl,
            'connected': True
        }
        session['user_email'] = email_address
        session['auth_method'] = 'imap'
        
        return jsonify({
            'success': True,
            'user_email': email_address,
            'imap_server': imap_server,
            'message': 'IMAP credentials stored successfully'
        })
        
    except Exception as e:
        return jsonify({'error': f'Error storing credentials: {str(e)}'}), 500

@app.route('/get_imap_servers')
def get_imap_servers():
    """Get list of common IMAP servers."""
    imap_servers = {
        'gmail.com': {
            'server': 'imap.gmail.com',
            'port': 993,
            'ssl': True,
            'note': 'Requires App Password if 2FA is enabled'
        },
        'outlook.com': {
            'server': 'outlook.office365.com',
            'port': 993,
            'ssl': True,
            'note': 'Microsoft account'
        },
        'hotmail.com': {
            'server': 'outlook.office365.com',
            'port': 993,
            'ssl': True,
            'note': 'Microsoft account'
        },
        'yahoo.com': {
            'server': 'imap.mail.yahoo.com',
            'port': 993,
            'ssl': True,
            'note': 'Requires App Password'
        },
        'aol.com': {
            'server': 'imap.aol.com',
            'port': 993,
            'ssl': True,
            'note': 'AOL account'
        },
        'yandex.com': {
            'server': 'imap.yandex.com',
            'port': 993,
            'ssl': True,
            'note': 'Yandex Mail'
        }
    }
    
    return jsonify({
        'success': True,
        'imap_servers': imap_servers
    })

@app.route('/dashboard_imap_scrape')
def dashboard_imap_scrape():
    """Scrape emails from dashboard using stored IMAP credentials."""
    try:
        # Check if IMAP credentials are stored in session
        if 'imap_credentials' not in session or not session['imap_credentials'].get('connected'):
            return jsonify({'error': 'No IMAP credentials found. Please authenticate first.'}), 401
        
        credentials = session['imap_credentials']
        
        # Add initial log
        add_log_to_stream('🚀 Starting IMAP email extraction from dashboard...', 'info')
        add_log_to_stream(f'📧 Connecting to {credentials["email_address"]}...', 'processing')
        
        # Create IMAP scraper
        scraper = create_imap_scraper(
            email_address=credentials['email_address'],
            password=credentials['password'],
            imap_server=credentials['imap_server'],
            imap_port=credentials['imap_port'],
            use_ssl=credentials['use_ssl']
        )
        
        if not scraper:
            add_log_to_stream('❌ Failed to connect to IMAP server', 'error')
            return jsonify({'error': 'Failed to connect to IMAP server. Please re-authenticate.'}), 500
        
        add_log_to_stream(f'✅ Connected to IMAP server: {scraper.imap_server}', 'success')
        
        # Get available folders
        folders = scraper.get_folders()
        add_log_to_stream(f'📁 Available folders: {", ".join(folders[:5])}{"..." if len(folders) > 5 else ""}', 'info')
        
        # Progress callback function
        def progress_callback(message, log_type):
            add_log_to_stream(message, log_type)
        
        # Scrape emails from INBOX
        add_log_to_stream('🔍 Searching all emails in INBOX...', 'processing')
        emails = scraper.scrape_emails(
            folder='INBOX',
            search_criteria='ALL',
            max_emails=None,  # Get all emails
            progress_callback=progress_callback
        )
        
        if not emails:
            add_log_to_stream('⚠️ No emails found or failed to scrape', 'warning')
            scraper.disconnect()
            return jsonify({'error': 'No emails found or failed to scrape'}), 404
        
        # Save to file
        add_log_to_stream('💾 Saving scraped data to file...', 'processing')
        filename = scraper.save_emails_to_file(emails)
        
        if filename:
            add_log_to_stream(f'✅ Data saved to: {filename}', 'success')
        else:
            add_log_to_stream('⚠️ Failed to save data to file', 'warning')
        
        # Disconnect
        scraper.disconnect()
        add_log_to_stream('🔌 Disconnected from IMAP server', 'info')
        add_log_to_stream('✅ IMAP email extraction completed successfully!', 'complete')
        
        return jsonify({
            'success': True,
            'emails_count': len(emails),
            'user_email': credentials['email_address'],
            'filename': filename,
            'imap_server': scraper.imap_server,
            'message': f'Successfully scraped {len(emails)} emails using IMAP'
        })
        
    except Exception as e:
        add_log_to_stream(f'❌ IMAP scraping error: {str(e)}', 'error')
        return jsonify({'error': f'IMAP scraping error: {str(e)}'}), 500

@app.route('/reset_pagination')
def reset_pagination():
    """Reset email pagination."""
    if 'email_pagination' in session:
        session.pop('email_pagination')
    return jsonify({'success': True, 'message': 'Pagination reset'})

@app.route('/test_log')
def test_log():
    """Test endpoint to add a log message."""
    add_log_to_stream('🧪 Test log message from server', 'info')
    return jsonify({'success': True, 'message': 'Test log added'})

@app.route('/get_session_id')
def get_session_id():
    """Get the current session ID for SSE connection."""
    global current_session_id
    if not current_session_id:
        current_session_id = str(time.time())
    return jsonify({'session_id': current_session_id})

@app.route('/test_sse')
def test_sse():
    """Test SSE connection."""
    return """
    <!DOCTYPE html>
    <html>
    <head>
        <title>SSE Test</title>
    </head>
    <body>
        <h1>SSE Test</h1>
        <div id="logs"></div>
        <button onclick="addTestLog()">Add Test Log</button>
        <script>
            const eventSource = new EventSource('/stream_logs');
            const logsDiv = document.getElementById('logs');
            
            eventSource.onmessage = function(event) {
                const data = JSON.parse(event.data);
                if (data.message && data.type !== 'heartbeat') {
                    const log = document.createElement('div');
                    log.textContent = `[${data.type}] ${data.message}`;
                    logsDiv.appendChild(log);
                }
            };
            
            eventSource.onerror = function(event) {
                console.error('SSE Error:', event);
                const log = document.createElement('div');
                log.textContent = '❌ SSE Error';
                log.style.color = 'red';
                logsDiv.appendChild(log);
            };
            
            eventSource.onopen = function(event) {
                console.log('SSE Connected');
                const log = document.createElement('div');
                log.textContent = '✅ SSE Connected';
                log.style.color = 'green';
                logsDiv.appendChild(log);
            };
            
            function addTestLog() {
                fetch('/test_log');
            }
        </script>
    </body>
    </html>
    """

def cleanup_old_log_queues():
    """Clean up old log queues to prevent memory leaks."""
    current_time = time.time()
    expired_sessions = []
    
    for session_id in log_queues:
        # Remove queues older than 1 hour
        try:
            session_time = float(session_id)
            if current_time - session_time > 3600:  # 1 hour
                expired_sessions.append(session_id)
        except ValueError:
            # If session_id is not a timestamp, keep it for now
            pass
    
    for session_id in expired_sessions:
        del log_queues[session_id]

@app.route('/get_extraction_progress')
def get_extraction_progress():
    """Get current extraction progress for real-time updates."""
    # This would be implemented with a proper progress tracking system
    # For now, return a simple status
    return jsonify({
        'status': 'running',
        'progress': 0,
        'current_email': 0,
        'total_emails': 0,
        'success_count': 0,
        'error_count': 0
    })

@app.route('/stream_logs')
def stream_logs():
    """Stream real-time logs from the extraction process."""
    def generate():
        try:
            # Use the global session ID or create one
            global current_session_id
            if not current_session_id:
                current_session_id = str(time.time())
            
            session_id = current_session_id
            print(f"SSE: New connection with session_id: {session_id}")
            
            # Initialize log queue for this session
            if session_id not in log_queues:
                log_queues[session_id] = []
            
            # Send initial connection message
            yield f"data: {json.dumps({'message': 'Connected to log stream', 'type': 'info'})}\n\n"
            
            # Keep connection alive and check for new logs
            heartbeat_count = 0
            while True:
                try:
                    if session_id in log_queues and log_queues[session_id]:
                        log = log_queues[session_id].pop(0)
                        yield f"data: {json.dumps(log)}\n\n"
                        heartbeat_count = 0  # Reset heartbeat counter when we send real data
                    else:
                        # Send heartbeat to keep connection alive
                        heartbeat_count += 1
                        if heartbeat_count % 50 == 0:  # Send heartbeat every 5 seconds (50 * 0.1s)
                            yield f"data: {json.dumps({'message': 'heartbeat', 'type': 'heartbeat'})}\n\n"
                    
                    time.sleep(0.1)  # Check every 100ms
                except Exception as e:
                    print(f"SSE Error in loop: {e}")
                    break
        except Exception as e:
            print(f"SSE Error in generate: {e}")
            yield f"data: {json.dumps({'message': f'SSE Error: {str(e)}', 'type': 'error'})}\n\n"
    
    response = Response(generate(), mimetype='text/event-stream')
    response.headers['Cache-Control'] = 'no-cache'
    response.headers['X-Accel-Buffering'] = 'no'
    response.headers['Connection'] = 'keep-alive'
    response.headers['Access-Control-Allow-Origin'] = '*'
    return response

def add_log_to_stream(message, log_type='info'):
    """Add a log message to the stream queue."""
    try:
        # Use a global session ID or create a default one
        global current_session_id
        if not current_session_id:
            current_session_id = str(time.time())
        
        # Initialize log queue for this session if it doesn't exist
        if current_session_id not in log_queues:
            log_queues[current_session_id] = []
        
        # Add log message
        log_queues[current_session_id].append({
            'message': message,
            'type': log_type,
            'timestamp': datetime.now().isoformat()
        })
        
        print(f"SSE: Added log to session {current_session_id}: {message}")
        print(f"SSE: Queue length for session {current_session_id}: {len(log_queues[current_session_id])}")
        
        # Keep only last 100 messages to prevent memory issues
        if len(log_queues[current_session_id]) > 100:
            log_queues[current_session_id] = log_queues[current_session_id][-100:]
        
        # Clean up old log queues periodically
        if len(log_queues) > 10:  # Only cleanup if we have many sessions
            cleanup_old_log_queues()
    except Exception as e:
        print(f"SSE: Error adding log: {e}")
        # Fallback to print if SSE fails
        print(f"[{log_type.upper()}] {message}")

@app.route('/download/<filename>')
def download_file(filename):
    """Download scraped email data."""
    try:
        return send_file(filename, as_attachment=True)
    except Exception as e:
        flash(f'Download error: {str(e)}', 'error')
        return redirect(url_for('dashboard'))

if __name__ == '__main__':
    os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'  # Only for development
    app.run(debug=True, host='0.0.0.0', port=5000)
