import bcrypt
import os
import re
import secrets
import streamlit as st
import pandas as pd
import matplotlib.pyplot as plt
from datetime import datetime, timedelta
from dotenv import load_dotenv
import mysql.connector
from mysql.connector import pooling
# import pymssql  # For SQL Server alternative
from cryptography.fernet import Fernet  # For encryption
import json
from pathlib import Path
import sys

load_dotenv()

# ---------- Database Configuration ----------

# Encryption setup

def generate_encryption_key():
    """Generate a new Fernet encryption key"""
    return Fernet.generate_key()

def save_key_to_file(key, filepath="encryption.key"):
    """Save encryption key to a secure file"""
    try:
        with open(filepath, "wb") as key_file:
            key_file.write(key)
        # Set restrictive permissions (owner read/write only)
        os.chmod(filepath, 0o600)
        print(f"Encryption key saved to {filepath}")
        return True
    except Exception as e:
        print(f"Error saving key: {e}")
        return False

def load_key_from_file(filepath="encryption.key"):
    """Load encryption key from file"""
    try:
        with open(filepath, "rb") as key_file:
            return key_file.read()
    except FileNotFoundError:
        print(f"Key file {filepath} not found")
        return None
    except Exception as e:
        print(f"Error loading key: {e}")
        return None

def setup_encryption_key():
    """
    Setup encryption key with multiple fallback options:
    1. Environment variable
    2. Key file
    3. Generate new key (development only)
    """
    # Option 1: Check environment variable first
    env_key = os.environ.get("ENCRYPTION_KEY")
    if env_key:
        try:
            # Validate the key works
            Fernet(env_key.encode())
            print("Using encryption key from environment variable")
            return env_key.encode()
        except Exception as e:
            print(f"Invalid encryption key in environment variable: {e}")
    
    # Option 2: Try to load from file
    key_file_path = os.environ.get("ENCRYPTION_KEY_FILE", "encryption.key")
    file_key = load_key_from_file(key_file_path)
    if file_key:
        try:
            # Validate the key works
            Fernet(file_key)
            print(f"Using encryption key from file: {key_file_path}")
            return file_key
        except Exception as e:
            print(f"Invalid encryption key in file: {e}")
    
    # Option 3: Generate new key (only in development)
    if os.environ.get("ENVIRONMENT") == "development":
        print("WARNING: Generating new encryption key for development")
        print("This should NOT happen in production!")
        new_key = generate_encryption_key()
        
        # Save it for future use
        save_key_to_file(new_key, key_file_path)
        
        # Also show it so you can set it as env var
        print(f"Generated key (set as ENCRYPTION_KEY): {new_key.decode()}")
        return new_key
    
    # If we get here, no key could be found or generated
    raise ValueError(
        "No encryption key found! Please either:\n"
        "1. Set ENCRYPTION_KEY environment variable, or\n"
        "2. Create an encryption key file, or\n"
        "3. Set ENVIRONMENT=development to auto-generate (dev only)"
    )

def create_key_setup_script():
    """Create a helper script for key generation"""
    script_content = '''#!/usr/bin/env python3
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
'''
    
    with open("setup_encryption_key.py", "w") as f:
        f.write(script_content)
    os.chmod("setup_encryption_key.py", 0o755)
    print("Created setup_encryption_key.py - run this script to generate keys")

# Initialize encryption with improved setup
try:
    ENCRYPTION_KEY = setup_encryption_key()
    cipher_suite = Fernet(ENCRYPTION_KEY)
    print("✓ Encryption initialized successfully")
except Exception as e:
    print(f"✗ Encryption setup failed: {e}")
    if not os.environ.get("ENCRYPTION_KEY") and not os.path.exists("encryption.key"):
        print("\nTo fix this, you can:")
        print("1. Run: python -c \"from cryptography.fernet import Fernet; print('ENCRYPTION_KEY=' + Fernet.generate_key().decode())\"")
        print("2. Add the output to your .env file")
        print("3. Or create a key file using the setup script")
        
        # Offer to create the setup script
        create_key_setup_script()
    sys.exit(1)

def encrypt_data(data: str) -> str:
    """Encrypt sensitive data before storage"""
    if not data:
        return data
    try:
        return cipher_suite.encrypt(data.encode()).decode()
    except Exception as e:
        raise ValueError(f"Encryption failed: {e}")

def decrypt_data(encrypted_data: str) -> str:
    """Decrypt data when retrieving"""
    if not encrypted_data:
        return encrypted_data
    try:
        return cipher_suite.decrypt(encrypted_data.encode()).decode()
    except Exception as e:
        raise ValueError(f"Decryption failed: {e}")

# ---------- Key Management Utilities ----------

def rotate_encryption_key(old_key_source, new_key=None):
    """
    Utility to help rotate encryption keys
    WARNING: This requires careful planning in production!
    """
    if new_key is None:
        new_key = generate_encryption_key()
    
    # This is a template - you'd need to implement the actual rotation logic
    # based on your specific needs (re-encrypting all data, etc.)
    print("Key rotation requires custom implementation based on your data")
    print("Consider:")
    print("1. Backup all encrypted data")
    print("2. Decrypt with old key, re-encrypt with new key") 
    print("3. Update all instances with new key")
    print("4. Verify all data is accessible")
    
    return new_key

def verify_encryption_setup():
    """Test that encryption/decryption is working correctly"""
    test_data = "test_encryption_data_12345"
    try:
        encrypted = encrypt_data(test_data)
        decrypted = decrypt_data(encrypted)
        
        if decrypted == test_data:
            print("✓ Encryption verification successful")
            return True
        else:
            print("✗ Encryption verification failed - data mismatch")
            return False
    except Exception as e:
        print(f"✗ Encryption verification failed: {e}")
        return False

# Run verification on import
if __name__ != "__main__":
    verify_encryption_setup()
# MySQL Configuration
def get_db_connection():
    try:
        conn = mysql.connector.connect(
            host=os.environ.get("DB_HOST"),
            port=int(os.environ.get("DB_PORT", 3306)),
            user=os.environ.get("DB_USER"),
            password=os.environ.get("DB_PASSWORD"),
            database=os.environ.get("DB_NAME"),
            ssl_ca='/path/to/server-ca.pem',
            ssl_cert='/path/to/client-cert.pem',
            ssl_key='/path/to/client-key.pem'
        )
        return conn
    except mysql.connector.Error as err:
        st.error(f"Database connection error: {err}")
        return None

# ---------- Database Schema Initialization ----------

def init_db():
    try:
        conn = get_db_connection()
        if conn is None:
            return False
        cursor = conn.cursor()
        
        # Users table
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            user_id INT AUTO_INCREMENT PRIMARY KEY,
            username VARCHAR(255) UNIQUE NOT NULL,
            password VARCHAR(255) NOT NULL,
            email VARCHAR(255) UNIQUE,
            is_kyc_complete BOOLEAN DEFAULT FALSE,
            reset_token VARCHAR(255),
            token_expiration DATETIME,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
        ) ENGINE=InnoDB;
        """)
        
        # KYC data table (separate from users)
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS user_kyc (
            kyc_id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT NOT NULL,
            full_name VARCHAR(255) NOT NULL,
            date_of_birth DATE NOT NULL,
            business_name VARCHAR(255),
            business_type ENUM('Sole Proprietorship', 'Partnership', 'Corporation', 'LLC', 'Other'),
            business_formed_date DATE,
            business_address TEXT,
            business_registration_number VARCHAR(255),
            proof_id_path VARCHAR(255),
            proof_business_path VARCHAR(255),
            FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        ) ENGINE=InnoDB;
        """)
        
        # Payment methods table (tokenized only)
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS payment_methods (
            payment_method_id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT NOT NULL,
            token_id VARCHAR(255) NOT NULL,  # From payment processor
            card_last4 CHAR(4) NOT NULL,
            card_brand VARCHAR(50) NOT NULL,
            expiry_month CHAR(2) NOT NULL,
            expiry_year CHAR(4) NOT NULL,
            is_default BOOLEAN DEFAULT FALSE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
        ) ENGINE=InnoDB;
        """)
        
        # Transactions table
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS transactions (
            transaction_id INT AUTO_INCREMENT PRIMARY KEY,
            user_id INT NOT NULL,
            amount DECIMAL(15,2) NOT NULL,
            currency CHAR(3) NOT NULL,
            status ENUM('pending', 'completed', 'failed', 'refunded') NOT NULL,
            payment_method_id INT,
            customer_name VARCHAR(255),
            description TEXT,
            processor_transaction_id VARCHAR(255),  # From payment processor
            processor_response TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
            FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE,
            FOREIGN KEY (payment_method_id) REFERENCES payment_methods(payment_method_id)
        ) ENGINE=InnoDB;
        """)
        
        # Transaction events table (for audit trail)
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS transaction_events (
            event_id INT AUTO_INCREMENT PRIMARY KEY,
            transaction_id INT NOT NULL,
            event_type VARCHAR(50) NOT NULL,
            event_data TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY (transaction_id) REFERENCES transactions(transaction_id) ON DELETE CASCADE
        ) ENGINE=InnoDB;
        """)
        
        conn.commit()
        cursor.close()
        conn.close()
        return True
    except Exception as e:
        st.error(f"Database initialization failed: {e}")
        return False

# ---------- User Operations ----------

def get_user_by_username(username):
    conn = get_db_connection()
    if conn is None:
        return None
    try:
        cursor = conn.cursor(dictionary=True)
        query = "SELECT * FROM users WHERE username = %s"
        cursor.execute(query, (username,))
        return cursor.fetchone()
    finally:
        cursor.close()
        conn.close()

def save_user(user_data):
    conn = get_db_connection()
    if conn is None:
        return False
    try:
        cursor = conn.cursor()
        
        if 'user_id' in user_data:
            # Update existing user
            query = """
            UPDATE users SET
                username = %s,
                password = %s,
                email = %s,
                is_kyc_complete = %s,
                reset_token = %s,
                token_expiration = %s
            WHERE user_id = %s
            """
            params = (
                user_data['username'],
                user_data['password'],
                user_data.get('email'),
                user_data.get('is_kyc_complete', False),
                user_data.get('reset_token'),
                user_data.get('token_expiration'),
                user_data['user_id']
            )
        else:
            # Insert new user
            query = """
            INSERT INTO users (username, password, email, is_kyc_complete, reset_token, token_expiration)
            VALUES (%s, %s, %s, %s, %s, %s)
            """
            params = (
                user_data['username'],
                user_data['password'],
                user_data.get('email'),
                user_data.get('is_kyc_complete', False),
                user_data.get('reset_token'),
                user_data.get('token_expiration')
            )
        
        cursor.execute(query, params)
        conn.commit()
        return True
    except Exception as e:
        conn.rollback()
        st.error(f"Failed to save user: {e}")
        return False
    finally:
        cursor.close()
        conn.close()

# ---------- Transaction Operations ----------

def create_transaction(transaction_data):
    conn = get_db_connection()
    if conn is None:
        return None
    try:
        cursor = conn.cursor(dictionary=True)
        
        # First insert the transaction
        query = """
        INSERT INTO transactions (
            user_id, amount, currency, status, 
            payment_method_id, customer_name, description,
            processor_transaction_id, processor_response
        ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
        """
        params = (
            transaction_data['user_id'],
            transaction_data['amount'],
            transaction_data['currency'],
            transaction_data.get('status', 'pending'),
            transaction_data.get('payment_method_id'),
            transaction_data.get('customer_name'),
            transaction_data.get('description'),
            transaction_data.get('processor_transaction_id'),
            transaction_data.get('processor_response')
        )
        
        cursor.execute(query, params)
        transaction_id = cursor.lastrowid
        
        # Add initial event
        event_query = """
        INSERT INTO transaction_events (
            transaction_id, event_type, event_data
        ) VALUES (%s, %s, %s)
        """
        cursor.execute(event_query, (
            transaction_id,
            'created',
            json.dumps({'status': 'pending'}) if transaction_data.get('processor_response') else None
        ))
        
        conn.commit()
        return transaction_id
    except Exception as e:
        conn.rollback()
        st.error(f"Failed to create transaction: {e}")
        return None
    finally:
        cursor.close()
        conn.close()

def get_user_transactions(user_id, limit=100):
    conn = get_db_connection()
    if conn is None:
        return []
    try:
        cursor = conn.cursor(dictionary=True)
        query = """
        SELECT t.*, pm.card_last4, pm.card_brand
        FROM transactions t
        LEFT JOIN payment_methods pm ON t.payment_method_id = pm.payment_method_id
        WHERE t.user_id = %s
        ORDER BY t.created_at DESC
        LIMIT %s
        """
        cursor.execute(query, (user_id, limit))
        return cursor.fetchall()
    except Exception as e:
        st.error(f"Failed to get transactions: {e}")
        return []
    finally:
        cursor.close()
        conn.close()

# ---------- Payment Method Operations ----------

def get_user_kyc(user_id):
    """Retrieve KYC data for a user."""
    conn = get_db_connection()
    if conn is None:
        return None
    try:
        cursor = conn.cursor(dictionary=True)
        query = "SELECT * FROM user_kyc WHERE user_id = %s ORDER BY created_at DESC LIMIT 1"
        cursor.execute(query, (user_id,))
        return cursor.fetchone()
    except Exception as e:
        st.error(f"Failed to get KYC data: {e}")
        return None
    finally:
        cursor.close()
        conn.close()

def get_user_payment_methods(user_id):
    """Retrieve all payment methods for a user."""
    conn = get_db_connection()
    if conn is None:
        return []
    try:
        cursor = conn.cursor(dictionary=True)
        query = """
        SELECT payment_method_id, user_id, token_id, card_last4, card_brand, expiry_month, expiry_year, is_default
        FROM payment_methods
        WHERE user_id = %s
        ORDER BY is_default DESC, payment_method_id ASC
        """
        cursor.execute(query, (user_id,))
        payment_methods = cursor.fetchall()
        # Optionally decrypt token_id if needed, but not exposing here for security
        return payment_methods
    except Exception as e:
        st.error(f"Failed to get payment methods: {e}")
        return []
    finally:
        cursor.close()
        conn.close()

def add_payment_method(payment_method_data):
    """Store only tokenized payment method info"""
    conn = get_db_connection()
    if conn is None:
        return None
    try:
        cursor = conn.cursor()
        
        query = """
        INSERT INTO payment_methods (
            user_id, token_id, card_last4, card_brand,
            expiry_month, expiry_year, is_default
        ) VALUES (%s, %s, %s, %s, %s, %s, %s)
        """
        params = (
            payment_method_data['user_id'],
            encrypt_data(payment_method_data['token_id']),  # Encrypt the token
            payment_method_data['card_last4'],
            payment_method_data['card_brand'],
            payment_method_data['expiry_month'],
            payment_method_data['expiry_year'],
            payment_method_data.get('is_default', False)
        )
        
        cursor.execute(query, params)
        payment_method_id = cursor.lastrowid
        
        # If this is set as default, unset others
        if payment_method_data.get('is_default', False):
            update_query = """
            UPDATE payment_methods 
            SET is_default = FALSE 
            WHERE user_id = %s AND payment_method_id != %s
            """
            cursor.execute(update_query, (payment_method_data['user_id'], payment_method_id))
        
        conn.commit()
        return payment_method_id
    except Exception as e:
        conn.rollback()
        st.error(f"Failed to add payment method: {e}")
        return None
    finally:
        cursor.close()
        conn.close()

# ---------- Updated Page Classes ----------

class Page:
    def render(self):
        raise NotImplementedError("Subclasses should implement this!")

class Create_a_Payment(Page):
    def render(self):
        st.title("Create a Payment")
        user = User.get(st.session_state["username"])
        
        # Get user's payment methods
        payment_methods = get_user_payment_methods(user.user_id)
        
        with st.form("payment_form"):
            amount = st.number_input('Amount', min_value=0.01, step=0.01)
            currency = st.selectbox("Currency", ["USD", "EUR", "GBP"])
            customer_name = st.text_input("Customer Name")
            description = st.text_input("Description")
            
            if payment_methods:
                payment_method = st.selectbox(
                    "Payment Method",
                    options=[f"{pm['card_brand']} ****{pm['card_last4']} ({pm['expiry_month']}/{pm['expiry_year']})" 
                            for pm in payment_methods],
                    index=0
                )
                selected_pm_id = payment_methods[0]['payment_method_id']  # Default to first
            else:
                st.warning("No payment methods available. Please add one first.")
                selected_pm_id = None
            
            submit_button = st.form_submit_button("Create Payment")
        
        if submit_button:
            if not selected_pm_id:
                st.error("Please add a payment method first")
                return
            
            transaction_data = {
                'user_id': user.user_id,
                'amount': float(amount),
                'currency': currency,
                'customer_name': customer_name,
                'description': description,
                'payment_method_id': selected_pm_id,
                'status': 'pending'
            }
            
            transaction_id = create_transaction(transaction_data)
            if transaction_id:
                st.success(f"Payment created successfully! Transaction ID: {transaction_id}")
            else:
                st.error("Failed to create payment")

class Transactions(Page):
    def render(self):
        st.title("Transaction History")
        user = User.get(st.session_state["username"])
        transactions = get_user_transactions(user.user_id)
        
        if not transactions:
            st.info("No transactions found")
            return
        
        # Prepare data for display
        df_data = []
        for tx in transactions:
            df_data.append({
                "ID": tx['transaction_id'],
                "Date": tx['created_at'].strftime("%Y-%m-%d %H:%M"),
                "Amount": f"{tx['amount']} {tx['currency']}",
                "Status": tx['status'].capitalize(),
                "Payment Method": f"{tx.get('card_brand', 'Unknown')} ****{tx.get('card_last4', '')}" if tx.get('card_last4') else "N/A",
                "Description": tx.get('description', '')
            })
        
        df = pd.DataFrame(df_data)
        st.dataframe(df)
        
        # Visualization
        st.subheader("Transaction Summary")
        if not df.empty:
            # Convert amount to numeric for plotting
            df['Amount_Numeric'] = df['Amount'].apply(lambda x: float(x.split()[0]))
            
            fig, ax = plt.subplots(figsize=(10, 4))
            df.groupby('Status')['Amount_Numeric'].sum().plot(kind='bar', ax=ax)
            ax.set_ylabel("Total Amount")
            ax.set_title("Transaction Amounts by Status")
            st.pyplot(fig)

# ---------- Updated User Class ----------

class User:
    def __init__(self, user_id, username, password, email=None, is_kyc_complete=False, 
                 reset_token=None, token_expiration=None):
        self.user_id = user_id
        self.username = username
        self.password = password
        self.email = email
        self.is_kyc_complete = is_kyc_complete
        self.reset_token = reset_token
        self.token_expiration = token_expiration
        self._kyc_data = None
    
    @property
    def kyc_data(self):
        if self._kyc_data is None:
            self._kyc_data = get_user_kyc(self.user_id)
        return self._kyc_data
    
    def save(self):
        user_data = {
            'user_id': self.user_id,
            'username': self.username,
            'password': self.password,
            'email': self.email,
            'is_kyc_complete': self.is_kyc_complete,
            'reset_token': self.reset_token,
            'token_expiration': self.token_expiration
        }
        return save_user(user_data)
    
    def add_transaction(self, transaction_data):
        transaction_data['user_id'] = self.user_id
        return create_transaction(transaction_data)
    
    def get_transactions(self, limit=100):
        return get_user_transactions(self.user_id, limit)
    
    @staticmethod
    def get(username):
        user_data = get_user_by_username(username)
        if user_data:
            return User(
                user_id=user_data['user_id'],
                username=user_data['username'],
                password=user_data['password'],
                email=user_data.get('email'),
                is_kyc_complete=bool(user_data.get('is_kyc_complete', False)),
                reset_token=user_data.get('reset_token'),
                token_expiration=user_data.get('token_expiration')
            )
        return None

# ... [rest of your application code] ...

if __name__ == "__main__":
    # Initialize database with proper tables
    if not init_db():
        st.error("Failed to initialize database")
        st.stop()
    
    # ... [rest of your main application code] ...