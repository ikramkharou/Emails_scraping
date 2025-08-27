# MailRaw Source 📧

A powerful Flask-based web application for extracting and scraping emails from Gmail with real-time terminal logging and a modern user interface.

## 🚀 Features

- **🔐 OAuth 2.0 Authentication** - Secure Gmail API authentication
- **📧 Full Email Extraction** - Extract emails with headers, body content, and metadata
- **💾 JSON Export** - Download extracted data in JSON format
- **🛡️ Permission Management** - Check and manage Gmail API permissions

## 📋 Prerequisites

- Python 3.7 or higher
- Google Cloud Platform account
- Gmail API enabled
- OAuth 2.0 credentials

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

### 4. Set Up Google Cloud Platform

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

### 3. Authentication Process
1. Enter your Gmail address on the home page
2. Click "Start Authentication"
3. Grant the required permissions to the application
4. You'll be redirected to the dashboard

### 4. Email Extraction
1. **Check Permissions** - Verify your Gmail API permissions
2. **Start Extraction** - Click "Search & Scrape All Emails"
3. **Monitor Progress** - Watch real-time logs in the terminal
4. **Download Results** - Download the extracted data as JSON

## 📁 Project Structure

```
scraping_gmail/
├── app.py                 # Main Flask application
├── requirements.txt       # Python dependencies
├── credentials_old.json   # Google OAuth credentials
├── templates/            # HTML templates
│   ├── base.html         # Base template
│   ├── index.html        # Home page
│   └── dashboard.html    # Dashboard page
├── static/               # Static files (CSS, JS)
├── venv/                # Virtual environment
└── README.md            # This file
```

## 🔧 Configuration

### Gmail API Scopes
The application uses the following Gmail API scopes:
- `https://mail.google.com/` - Full access to Gmail



### Email Extraction
- **Multiple Formats**: Supports full, raw, and metadata formats
- **Content Parsing**: Extracts headers, body (plain text and HTML)
- **Error Handling**: Graceful handling of extraction failures
- **Progress Tracking**: Real-time progress updates
- **Batch Processing**: Processes emails in batches for efficiency



### Debug Mode
The application runs in debug mode by default. For production:
```python
app.run(debug=False, host='0.0.0.0', port=5000)
```



## 🔄 API Endpoints

- `GET /` - Home page
- `POST /authenticate` - Start OAuth authentication
- `GET /oauth2callback` - OAuth callback handler
- `GET /dashboard` - Dashboard page
- `GET /search_and_scrape_emails` - Start email extraction
- `GET /check_permissions` - Check Gmail API permissions
- `GET /stream_logs` - Server-Sent Events for real-time logs
- `GET /download/<filename>` - Download extracted data
- `GET /clear_auth` - Clear authentication data
