import sqlite3
from datetime import datetime
import threading
import json
import os
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


class SecureDatabaseManager:
    def __init__(self, db_name='user_scores.db', encryption_key=None):
        """Initialize database connection with encryption"""
        if not encryption_key:
            encryption_key = os.urandom(32)

        # Initialize encryption
        salt = b'secure_salt_for_db'  # In production, store this securely
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(encryption_key))
        self.cipher_suite = Fernet(key)

        # Database setup
        self.db_name = self._encrypt_string(db_name)
        self.thread_local = threading.local()
        self.lock = threading.Lock()

        # Ensure database is created
        self.get_connection()

    def get_connection(self):
        """Get thread-local database connection with WAL mode"""
        if not hasattr(self.thread_local, "connection"):
            self.thread_local.connection = self.create_database()
            # Enable Write-Ahead Logging for better concurrency
            self.thread_local.connection.execute('PRAGMA journal_mode=WAL')
            # Enable foreign key constraints
            self.thread_local.connection.execute('PRAGMA foreign_keys=ON')
        return self.thread_local.connection

    def create_database(self):
        """Create database with enhanced security schema"""
        try:
            conn = sqlite3.connect(self._decrypt_string(self.db_name),
                                   check_same_thread=False,
                                   isolation_level='EXCLUSIVE')
            cursor = conn.cursor()

            # Users table with enhanced security
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                email TEXT UNIQUE NOT NULL,
                phone_number TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                password_salt TEXT NOT NULL,
                password_last_changed TIMESTAMP,
                score INTEGER DEFAULT 0,
                totp_secret TEXT,
                verification_method TEXT DEFAULT 'email',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP,
                last_verification_attempt TIMESTAMP,
                failed_attempts INTEGER DEFAULT 0,
                lockout_until TIMESTAMP,
                account_status TEXT DEFAULT 'active',
                security_questions TEXT,
                last_password_reset TIMESTAMP,
                require_password_change BOOLEAN DEFAULT 0,
                CHECK (account_status IN ('active', 'locked', 'disabled', 'pending_verification'))
            )
            ''')

            conn.commit()
            return conn
        except sqlite3.Error as e:
            print(f"Database error: {e}")
            return None

    def check_user_exists(self, email, phone_number):
        """
        Check if a user with given email or phone number exists.

        Args:
            email (str): User's email
            phone_number (str): User's phone number

        Returns:
            bool: True if user exists, False otherwise
        """
        try:
            # Encrypt the email and phone for comparison
            encrypted_email = self._encrypt_string(email)
            encrypted_phone = self._encrypt_string(phone_number)

            cursor = self.get_connection().cursor()
            cursor.execute('''
                SELECT COUNT(*) FROM users 
                WHERE email = ? OR phone_number = ?
            ''', (encrypted_email, encrypted_phone))

            count = cursor.fetchone()[0]
            return count > 0
        except Exception as e:
            print(f"Error checking user existence: {e}")
            # In case of any error, prevent registration
            return True

    def create_user(self, name, email, phone_number, password_hash, totp_secret):
        """Create a new user with enhanced security"""
        try:
            with self.lock:
                # Encrypt user details
                encrypted_name = self._encrypt_string(name)
                encrypted_email = self._encrypt_string(email)
                encrypted_phone = self._encrypt_string(phone_number)
                encrypted_totp = self._encrypt_string(totp_secret)

                # Start a transaction
                conn = self.get_connection()
                cursor = conn.cursor()

                # Check if user exists before attempting to insert
                cursor.execute('''
                    SELECT COUNT(*) FROM users 
                    WHERE email = ? OR phone_number = ?
                ''', (encrypted_email, encrypted_phone))

                # If user already exists, return False
                if cursor.fetchone()[0] > 0:
                    return False

                # If no existing user, proceed with insertion
                cursor.execute('''
                INSERT INTO users (
                    name, email, phone_number, password_hash, 
                    password_salt, totp_secret, created_at,
                    password_last_changed, account_status
                )
                VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, 'pending_verification')
                ''', (
                    encrypted_name,
                    encrypted_email,
                    encrypted_phone,
                    password_hash,
                    base64.b64encode(os.urandom(32)).decode('utf-8'),
                    encrypted_totp
                ))

                conn.commit()
                return True
        except sqlite3.IntegrityError:
            # This catches unique constraint violations
            return False
        except Exception as e:
            print(f"Error creating user: {e}")
            if self.get_connection():
                self.get_connection().rollback()
            return False

    # Existing encryption and other methods remain the same
    def _encrypt_string(self, text):
        """Encrypt sensitive string data"""
        if isinstance(text, str):
            return self.cipher_suite.encrypt(text.encode()).decode()
        return text

    def _decrypt_string(self, encrypted_text):
        """Decrypt sensitive string data"""
        if isinstance(encrypted_text, str):
            return self.cipher_suite.decrypt(encrypted_text.encode()).decode()
        return encrypted_text

    def _encrypt_data(self, data):
        """Encrypt data before storing in database"""
        return self.cipher_suite.encrypt(json.dumps(data).encode()).decode()

    def _decrypt_data(self, encrypted_data):
        """Decrypt data retrieved from database"""
        return json.loads(self.cipher_suite.decrypt(encrypted_data.encode()))

    def close(self):
        """Securely close database connection"""
        try:
            if hasattr(self.thread_local, "connection"):
                # Securely clear any sensitive data in memory
                cursor = self.thread_local.connection.cursor()
                cursor.execute("PRAGMA secure_delete = ON")
                self.thread_local.connection.commit()

                self.thread_local.connection.close()
                del self.thread_local.connection
        except Exception as e:
            print(f"Error closing database: {e}")