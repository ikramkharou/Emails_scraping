#!/usr/bin/env python3
"""
Setup script for Gmail Scraper
This script helps users set up the environment and verify installation
"""

import subprocess
import sys
import os

def run_command(command, description):
    """Run a command and print status."""
    print(f"🔧 {description}...")
    try:
        result = subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
        print(f"✅ {description} completed successfully")
        return True
    except subprocess.CalledProcessError as e:
        print(f"❌ {description} failed:")
        print(f"   Error: {e.stderr}")
        return False

def check_python_version():
    """Check if Python version is compatible."""
    print("🐍 Checking Python version...")
    version = sys.version_info
    if version.major >= 3 and version.minor >= 7:
        print(f"✅ Python {version.major}.{version.minor}.{version.micro} is compatible")
        return True
    else:
        print(f"❌ Python {version.major}.{version.minor}.{version.micro} is not compatible")
        print("   Please upgrade to Python 3.7 or higher")
        return False

def install_dependencies():
    """Install required dependencies."""
    print("📦 Installing dependencies...")
    return run_command("pip install -r requirements.txt", "Installing dependencies")

def check_files():
    """Check if required files exist."""
    print("📁 Checking required files...")
    
    required_files = [
        'app.py',
        'requirements.txt',
        'credentials_old.json'
    ]
    
    missing_files = []
    for file in required_files:
        if os.path.exists(file):
            print(f"✅ {file} found")
        else:
            print(f"❌ {file} missing")
            missing_files.append(file)
    
    return len(missing_files) == 0

def setup_environment():
    """Set up environment variables."""
    print("🔧 Setting up environment...")
    
    if not os.path.exists('.env'):
        try:
            with open('.env', 'w') as f:
                f.write("SECRET_KEY=your-secret-key-here-change-this-in-production\n")
                f.write("DEBUG=True\n")
                f.write("OAUTHLIB_INSECURE_TRANSPORT=1\n")
            print("✅ Created .env file with default settings")
        except Exception as e:
            print(f"❌ Failed to create .env file: {e}")
            return False
    else:
        print("✅ .env file already exists")
    
    return True

def main():
    """Main setup function."""
    print("🚀 Gmail Scraper Setup")
    print("=" * 40)
    
    # Check Python version
    if not check_python_version():
        return False
    
    # Check required files
    if not check_files():
        print("\n❌ Some required files are missing.")
        print("   Please ensure you have all project files.")
        return False
    
    # Install dependencies
    if not install_dependencies():
        print("\n❌ Failed to install dependencies.")
        print("   Please check your internet connection and pip installation.")
        return False
    
    # Setup environment
    if not setup_environment():
        print("\n❌ Failed to setup environment.")
        return False
    
    print("\n" + "=" * 40)
    print("🎉 Setup completed successfully!")
    print("\n📋 Next steps:")
    print("   1. Verify your Google Cloud Project setup:")
    print("      - Gmail API enabled")
    print("      - OAuth2 credentials configured")
    print("   2. Test the setup: python test_gmail_api.py")
    print("   3. Start the application: python app.py")
    print("   4. Open browser and go to: http://localhost:5000")
    
    return True

if __name__ == '__main__':
    success = main()
    sys.exit(0 if success else 1)
