#!/usr/bin/env python3
"""
Clear Authentication Data Script
This script clears all authentication data to resolve OAuth scope change errors.
"""

import os
import sys

def clear_auth_data():
    """Clear all authentication data and tokens."""
    files_to_remove = [
        'token.pickle',
        'credentials.json'
        # Note: credentials_old.json is NOT removed as it contains essential OAuth credentials
    ]
    
    print("🧹 Clearing authentication data...")
    
    removed_files = []
    for file_path in files_to_remove:
        if os.path.exists(file_path):
            try:
                os.remove(file_path)
                removed_files.append(file_path)
                print(f"✅ Removed: {file_path}")
            except Exception as e:
                print(f"❌ Error removing {file_path}: {e}")
        else:
            print(f"ℹ️  File not found: {file_path}")
    
    if removed_files:
        print(f"\n✅ Successfully cleared {len(removed_files)} authentication files!")
        print("\n📋 Next steps:")
        print("1. Restart your Flask application")
        print("2. Go to http://localhost:5000")
        print("3. Enter your Gmail address and authenticate")
        print("4. The application now includes gmail.metadata scope to prevent scope changes")
    else:
        print("\nℹ️  No authentication files were found to remove.")
        print("You can proceed with re-authentication.")

if __name__ == "__main__":
    clear_auth_data()
