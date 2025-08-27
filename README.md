# Mail Scraper Extractor 📧

A powerful Flask-based web application for extracting and scraping emails from multiple email service providers with real-time terminal logging and a modern user interface.

## 🚀 Features

- **🔐 Dual Authentication** - Gmail API OAuth 2.0 + IMAP direct connection
- **📧 Multi-ESP Support** - Extract emails from Gmail, Outlook, Yahoo, AOL,  and more
- **🌐 IMAP Protocol** - Direct connection to any email provider via IMAP
- **📧 Full Email Extraction** - Extract emails with headers, body content, and metadata
- **💾 JSON Export** - Download extracted data in JSON format
- **🛡️ Permission Management** - Check and manage Gmail API permissions
- **💻 Real-time Progress** - Live terminal logging and progress tracking
- **🔒 Raw RFC822 Support** - Extract emails in raw RFC822 format
- **⚡ Auto-Detection** - Automatic IMAP server detection based on email domain

## 📋 Prerequisites

- Python 3.7 or higher
- Google Cloud Platform account (for Gmail API)
- Email credentials (for IMAP connection)

## 🛠️ Installation

### 1. Clone the Repository
```bash
git clone <repository-url>
cd scraping_gmail
```

### 2. Create Virtual Environment
```bash
python -m venv venv

# On Windows
venv\Scripts\activate

# On macOS/Linux
source venv/bin/activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Set Up Google Cloud Platform (for Gmail API)

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select existing one
3. Enable the Gmail API
4. Create OAuth 2.0 credentials:
   - Go to "APIs & Services" > "Credentials"
   - Click "Create Credentials" > "OAuth 2.0 Client IDs"
   - Choose "Web application"
   - Add authorized redirect URI: `http://localhost:5000/oauth2callback`
   - Download the credentials JSON file

### 5. Configure Credentials
1. Rename your downloaded credentials file to `credentials_old.json`
2. Place it in the project root directory

### 6. Environment Variables
Create a `.env` file in the project root:
```env
SECRET_KEY=your-secret-key-here
OAUTHLIB_INSECURE_TRANSPORT=1
```

## 🚀 Usage

### 1. Start the Application
```bash
python app.py
```

### 2. Access the Application
Open your browser and navigate to: `http://localhost:5000`

### 3. Choose Authentication Method

#### **Gmail API Method:**
1. Click on the "Gmail API" tab
2. Enter your Gmail address
3. Click "Start Authentication"
4. Grant the required permissions
5. You'll be redirected to the dashboard

#### **IMAP Method:**
1. Click on the "IMAP" tab
2. Enter your email credentials:
   - Email Address
   - Password/App Password
   - IMAP Server (auto-detected)
   - Port (default: 993)
3. Enable SSL/TLS (recommended)
4. Click "Test Connection" to verify
5. Click "Start Scraping" to begin extraction

### 4. Email Extraction
1. **Check Permissions** - Verify your email API permissions
2. **Start Extraction** - Click "Search & Scrape All Emails" or "Start Scraping"
3. **Monitor Progress** - Watch real-time logs in the terminal
4. **Download Results** - Download the extracted data as JSON

## 📁 Project Structure

```
scraping_gmail/
├── app.py                 # Main Flask application
├── imap_scraper.py        # IMAP scraping functionality
├── requirements.txt       # Python dependencies
├── credentials_old.json   # Google OAuth credentials
├── templates/            # HTML templates
│   ├── base.html         # Base template
│   ├── index.html        # Home page with dual tabs
│   └── dashboard.html    # Dashboard page
├── static/               # Static files (CSS, JS)
├── venv/                # Virtual environment
└── README.md            # This file
```

## 🔧 Configuration

### Supported Email Providers

#### **Gmail API:**
- Full OAuth 2.0 authentication
- Secure token-based access
- No password required

#### **IMAP Providers:**
- **Gmail**: `imap.gmail.com` (use App Password if 2FA enabled)
- **Outlook/Hotmail**: `outlook.office365.com`
- **Yahoo**: `imap.mail.yahoo.com`
- **AOL**: `imap.aol.com`
- **iCloud**: `imap.mail.me.com`
- **Zoho**: `imap.zoho.com`
- **Yandex**: `imap.yandex.com`
- **Custom**: Any IMAP server

### Gmail API Scopes
The application uses the following Gmail API scopes:
- `https://mail.google.com/` - Full access to Gmail

### Email Extraction Features
- **Multiple Formats**: Supports full, raw, and metadata formats
- **Content Parsing**: Extracts headers, body (plain text and HTML)
- **Error Handling**: Graceful handling of extraction failures
- **Progress Tracking**: Real-time progress updates
- **Batch Processing**: Processes emails in batches for efficiency
- **Multi-Protocol**: Gmail API and IMAP support
- **Raw RFC822**: Extract emails in raw RFC822 format

### Debug Mode
The application runs in debug mode by default. For production:
```python
app.run(debug=False, host='0.0.0.0', port=5000)
```

## 🔄 API Endpoints

### Gmail API Endpoints
- `GET /` - Home page with dual authentication tabs
- `POST /authenticate` - Start OAuth authentication
- `GET /oauth2callback` - OAuth callback handler
- `GET /dashboard` - Dashboard page
- `GET /search_and_scrape_emails` - Start Gmail API extraction
- `GET /check_permissions` - Check Gmail API permissions

### IMAP Endpoints
- `POST /test_imap_connection` - Test IMAP connection
- `POST /imap_scrape` - Start IMAP email extraction
- `GET /get_imap_servers` - Get list of common IMAP servers

### General Endpoints
- `GET /stream_logs` - Server-Sent Events for real-time logs
- `GET /download/<filename>` - Download extracted data
- `GET /clear_auth` - Clear authentication data
- `GET /force_clear_auth` - Force clear all auth data

## 🔒 Security Features

- **OAuth 2.0**: Secure authentication for Gmail API
- **SSL/TLS**: Encrypted connections for IMAP
- **Token Management**: Secure token storage and refresh
- **Session Security**: Protected session management
- **Input Validation**: Form validation and sanitization
- **App Password Support**: Secure 2FA handling for Gmail

## 🎨 UI Features

- **Dual Tab Interface**: Choose between Gmail API and IMAP
- **Responsive Design**: Works on desktop and mobile
- **Real-time Terminal**: Live logging and progress updates
- **Professional Styling**: Clean, modern interface
- **Auto-detection**: Automatic IMAP server detection
- **Form Validation**: Client-side and server-side validation
- **Minimalistic Design**: Clean, compact form layouts
- **Hover Effects**: Professional button interactions

## 🚀 Getting Started

1. **Choose your method**: Gmail API (OAuth) or IMAP (direct)
2. **Configure credentials**: Set up Google Cloud or use email credentials
3. **Start the app**: Run `python app.py`
4. **Authenticate**: Use the appropriate tab for your method
5. **Extract emails**: Monitor progress and download results

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.
