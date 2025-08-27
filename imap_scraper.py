import imaplib
import email
import json
import base64
import time
from datetime import datetime
from email.header import decode_header
from email.utils import parsedate_to_datetime
import html2text
from bs4 import BeautifulSoup
import re
import ssl

class IMAPScraper:
    def __init__(self, email_address, password, imap_server=None, imap_port=None, use_ssl=True):
        """
        Initialize IMAP scraper
        
        Args:
            email_address (str): Email address
            password (str): Email password or app password
            imap_server (str): IMAP server (auto-detected if None)
            imap_port (int): IMAP port (auto-detected if None)
            use_ssl (bool): Use SSL connection
        """
        self.email_address = email_address
        self.password = password
        self.use_ssl = use_ssl
        
        # Auto-detect IMAP server based on email domain
        if imap_server is None:
            self.imap_server = self._get_imap_server(email_address)
        else:
            self.imap_server = imap_server
            
        if imap_port is None:
            self.imap_port = 993 if use_ssl else 143
        else:
            self.imap_port = imap_port
            
        self.connection = None
        self.is_connected = False
        
    def _get_imap_server(self, email_address):
        """Auto-detect IMAP server based on email domain"""
        domain = email_address.split('@')[1].lower()
        
        # Common IMAP servers
        imap_servers = {
            'outlook.com': 'outlook.office365.com',
            'hotmail.com': 'outlook.office365.com',
            'yahoo.com': 'imap.mail.yahoo.com',
            'aol.com': 'imap.aol.com',
            'icloud.com': 'imap.mail.me.com',
            'protonmail.com': '127.0.0.1',  # ProtonMail uses bridge
            'tutanota.com': 'imap.tutanota.com',
            'zoho.com': 'imap.zoho.com',
            'yandex.com': 'imap.yandex.com',
            'mail.ru': 'imap.mail.ru'
        }
        
        return imap_servers.get(domain, f'imap.{domain}')
    
    def connect(self):
        """Connect to IMAP server"""
        try:
            if self.use_ssl:
                # Create SSL context
                context = ssl.create_default_context()
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                self.connection = imaplib.IMAP4_SSL(
                    self.imap_server, 
                    self.imap_port,
                    ssl_context=context
                )
            else:
                self.connection = imaplib.IMAP4(self.imap_server, self.imap_port)
            
            # Login
            self.connection.login(self.email_address, self.password)
            self.is_connected = True
            return True
            
        except Exception as e:
            print(f"❌ IMAP connection failed: {e}")
            return False
    
    def disconnect(self):
        """Disconnect from IMAP server"""
        if self.connection and self.is_connected:
            try:
                self.connection.logout()
            except:
                pass
            finally:
                self.connection = None
                self.is_connected = False
    
    def get_folders(self):
        """Get list of available folders/mailboxes"""
        if not self.is_connected:
            return []
        
        try:
            status, folders = self.connection.list()
            if status == 'OK':
                folder_list = []
                for folder in folders:
                    # Decode folder name
                    folder_name = folder.decode('utf-8')
                    # Extract folder name from IMAP format
                    match = re.search(r'"[^"]*" (.+)$', folder_name)
                    if match:
                        folder_name = match.group(1)
                    folder_list.append(folder_name)
                return folder_list
            return []
        except Exception as e:
            print(f"❌ Error getting folders: {e}")
            return []
    
    def search_emails(self, folder='INBOX', search_criteria='ALL', max_emails=None):
        """
        Search emails in specified folder
        
        Args:
            folder (str): Folder to search in (default: INBOX)
            search_criteria (str): IMAP search criteria (default: ALL)
            max_emails (int): Maximum number of emails to retrieve (default: None for all)
        """
        if not self.is_connected:
            return []
        
        try:
            # Select folder
            status, messages = self.connection.select(folder)
            if status != 'OK':
                print(f"❌ Failed to select folder {folder}")
                return []
            
            # Search for emails
            status, message_numbers = self.connection.search(None, search_criteria)
            if status != 'OK':
                print(f"❌ Search failed")
                return []
            
            # Get list of message numbers
            email_ids = message_numbers[0].split()
            
            # Limit number of emails if specified
            if max_emails and len(email_ids) > max_emails:
                email_ids = email_ids[-max_emails:]  # Get most recent emails
            
            return email_ids
            
        except Exception as e:
            print(f"❌ Error searching emails: {e}")
            return []
    
    def fetch_email(self, email_id):
        """Fetch a single email by ID"""
        if not self.is_connected:
            return None
        
        try:
            # Fetch email data
            status, message_data = self.connection.fetch(email_id, '(RFC822)')
            if status != 'OK':
                return None
            
            # Parse email
            raw_email = message_data[0][1]
            email_message = email.message_from_bytes(raw_email)
            
            return self._parse_email_message(email_message, email_id.decode())
            
        except Exception as e:
            print(f"❌ Error fetching email {email_id}: {e}")
            return None
    
    def _parse_email_message(self, email_message, email_id):
        """Parse email message and extract content"""
        try:
            # Extract headers
            headers = {}
            for header_name in email_message.keys():
                header_value = email_message[header_name]
                if header_value:
                    # Decode header if needed
                    decoded_header = decode_header(header_value)
                    decoded_value = ""
                    for value, encoding in decoded_header:
                        if isinstance(value, bytes):
                            if encoding:
                                decoded_value += value.decode(encoding, errors='ignore')
                            else:
                                decoded_value += value.decode('utf-8', errors='ignore')
                        else:
                            decoded_value += str(value)
                    headers[header_name] = decoded_value
            
            # Extract body content
            body_plain = ""
            body_html = ""
            
            if email_message.is_multipart():
                # Handle multipart messages
                for part in email_message.walk():
                    content_type = part.get_content_type()
                    content_disposition = str(part.get('Content-Disposition', ''))
                    
                    # Skip attachments
                    if 'attachment' in content_disposition:
                        continue
                    
                    # Get content
                    try:
                        payload = part.get_payload(decode=True)
                        if payload is None:
                            continue
                        
                        # Decode content
                        charset = part.get_content_charset() or 'utf-8'
                        content = payload.decode(charset, errors='ignore')
                        
                        if content_type == 'text/plain':
                            body_plain += content
                        elif content_type == 'text/html':
                            body_html += content
                            
                    except Exception as e:
                        print(f"⚠️ Error parsing part: {e}")
                        continue
            else:
                # Handle simple messages
                content_type = email_message.get_content_type()
                try:
                    payload = email_message.get_payload(decode=True)
                    if payload:
                        charset = email_message.get_content_charset() or 'utf-8'
                        content = payload.decode(charset, errors='ignore')
                        
                        if content_type == 'text/plain':
                            body_plain = content
                        elif content_type == 'text/html':
                            body_html = content
                except Exception as e:
                    print(f"⚠️ Error parsing simple message: {e}")
            
            # Convert HTML to plain text if needed
            if body_html and not body_plain:
                try:
                    h = html2text.HTML2Text()
                    h.ignore_links = False
                    h.ignore_images = False
                    body_plain = h.handle(body_html)
                except Exception as e:
                    print(f"⚠️ Error converting HTML to text: {e}")
            
            # Extract date
            date_str = headers.get('Date', '')
            email_date = None
            if date_str:
                try:
                    email_date = parsedate_to_datetime(date_str)
                except:
                    email_date = datetime.now()
            else:
                email_date = datetime.now()
            
            # Create email object
            email_data = {
                'id': email_id,
                'headers': headers,
                'body_plain': body_plain,
                'body_html': body_html,
                'subject': headers.get('Subject', ''),
                'from': headers.get('From', ''),
                'to': headers.get('To', ''),
                'cc': headers.get('Cc', ''),
                'bcc': headers.get('Bcc', ''),
                'date': email_date.isoformat() if email_date else None,
                'date_timestamp': email_date.timestamp() if email_date else None,
                'format': 'imap',
                'size': len(body_plain) + len(body_html)
            }
            
            return email_data
            
        except Exception as e:
            print(f"❌ Error parsing email message: {e}")
            return None
    
    def scrape_emails(self, folder='INBOX', search_criteria='ALL', max_emails=None, progress_callback=None):
        """
        Scrape emails from specified folder
        
        Args:
            folder (str): Folder to scrape from
            search_criteria (str): IMAP search criteria
            max_emails (int): Maximum number of emails to scrape
            progress_callback (function): Callback function for progress updates
        """
        if not self.is_connected:
            return []
        
        try:
            # Search for emails
            email_ids = self.search_emails(folder, search_criteria, max_emails)
            total_emails = len(email_ids)
            
            if total_emails == 0:
                return []
            
            print(f"📧 Found {total_emails} emails to scrape")
            
            # Scrape each email
            scraped_emails = []
            success_count = 0
            error_count = 0
            
            for i, email_id in enumerate(email_ids):
                try:
                    # Progress callback
                    if progress_callback:
                        progress = int((i / total_emails) * 100)
                        progress_callback(f"📧 Processing email {i+1}/{total_emails} ({progress}%)", 'processing')
                    
                    # Fetch and parse email
                    email_data = self.fetch_email(email_id)
                    if email_data:
                        scraped_emails.append(email_data)
                        success_count += 1
                        
                        if progress_callback:
                            progress_callback(f"✅ Email {i+1}: Successfully scraped", 'success')
                    else:
                        error_count += 1
                        if progress_callback:
                            progress_callback(f"❌ Email {i+1}: Failed to scrape", 'error')
                            
                except Exception as e:
                    error_count += 1
                    if progress_callback:
                        progress_callback(f"❌ Email {i+1}: Error - {str(e)}", 'error')
                    continue
            
            # Final progress callback
            if progress_callback:
                progress_callback(f"📊 Scraping Summary: ✅ {success_count} successful, ❌ {error_count} failed", 'info')
                progress_callback(f"🎉 IMAP scraping completed! Scraped {len(scraped_emails)} emails", 'complete')
            
            return scraped_emails
            
        except Exception as e:
            if progress_callback:
                progress_callback(f"❌ Fatal error during IMAP scraping: {str(e)}", 'error')
            return []
    
    def save_emails_to_file(self, emails, filename=None):
        """Save scraped emails to JSON file"""
        if not filename:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f'imap_scraped_emails_{timestamp}.json'
        
        try:
            data = {
                'user_email': self.email_address,
                'scrape_time': datetime.now().isoformat(),
                'total_emails': len(emails),
                'imap_server': self.imap_server,
                'emails': emails
            }
            
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            
            return filename
            
        except Exception as e:
            print(f"❌ Error saving emails to file: {e}")
            return None

# Helper function to create IMAP scraper
def create_imap_scraper(email_address, password, imap_server=None, imap_port=None, use_ssl=True):
    """Create and connect IMAP scraper"""
    scraper = IMAPScraper(email_address, password, imap_server, imap_port, use_ssl)
    if scraper.connect():
        return scraper
    else:
        return None
