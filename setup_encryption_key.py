#!/usr/bin/env python3
"""
Encryption Key Setup Script
Run this script to generate a new encryption key for your application.
"""

from cryptography.fernet import Fernet
import os

def main():
    print("=== Encryption Key Generator ===")
    
    # Generate new key
    key = Fernet.generate_key()
    key_str = key.decode()
    
    print(f"Generated encryption key: {key_str}")
    print()
    
    # Option 1: Environment variable
    print("Option 1 - Add to your .env file:")
    print(f"ENCRYPTION_KEY={key_str}")
    print()
    
    # Option 2: Save to file
    print("Option 2 - Save to secure file:")
    filename = input("Enter filename (or press Enter for 'encryption.key'): ").strip()
    if not filename:
        filename = "encryption.key"
    
    try:
        with open(filename, "wb") as f:
            f.write(key)
        os.chmod(filename, 0o600)  # Restrict permissions
        print(f"Key saved to {filename}")
        print(f"Set environment variable: ENCRYPTION_KEY_FILE={filename}")
    except Exception as e:
        print(f"Error saving to file: {e}")
    
    print()
    print("IMPORTANT SECURITY NOTES:")
    print("- Keep this key secret and secure")
    print("- Back up the key safely")
    print("- Never commit keys to version control")
    print("- Use different keys for different environments")

if __name__ == "__main__":
    main()
