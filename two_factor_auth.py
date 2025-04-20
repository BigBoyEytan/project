import re
import secrets
import hashlib
import os
import json
import time
import sqlite3
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta

# Default email credentials
DEFAULT_EMAIL = "IronSystem2Fa@gmail.com"
DEFAULT_PASSWORD = "qnhm llwn rrnu whpt"


class AuthSystem:
    """
    Authentication manager with email-based 2FA.
    """

    def __init__(self, db_manager=None, db_path='user_auth.db', email_config=None):
        self.db_manager = db_manager
        self.db_path = db_path
        self.verification_codes = {}

        # Set environment variables if not already set
        if not os.environ.get('EMAIL_USERNAME'):
            os.environ['EMAIL_USERNAME'] = DEFAULT_EMAIL

        if not os.environ.get('EMAIL_PASSWORD'):
            os.environ['EMAIL_PASSWORD'] = DEFAULT_PASSWORD

        # Default email configuration
        self.email_config = {
            'smtp_server': 'smtp.gmail.com',
            'smtp_port': 587,
            'email': os.environ.get('EMAIL_USERNAME', DEFAULT_EMAIL),
            'password': os.environ.get('EMAIL_PASSWORD', DEFAULT_PASSWORD),
            'app_name': 'Security Scanner'
        }

        # Override with provided config if any
        if email_config:
            self.email_config.update(email_config)

        # Initialize database if not using db_manager
        if not self.db_manager:
            self._init_database()

    def _init_database(self):
        """Initialize the SQLite database with user table"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Create users table if it doesn't exist
        cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            phone_number TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            status TEXT DEFAULT 'active'
        )
        ''')

        conn.commit()
        conn.close()

    def validate_email(self, email):
        """Validate email format"""
        email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(email_regex, email) is not None

    def validate_phone(self, phone):
        """Validate phone number format"""
        phone_regex = r'^\+[1-9]\d{9,14}$'
        return re.match(phone_regex, phone) is not None

    def hash_password(self, password, salt=None):
        """Hash password with salt"""
        if salt is None:
            salt = secrets.token_hex(16)

        hashed_password = hashlib.sha256(f"{password}{salt}".encode()).hexdigest()
        return salt, hashed_password

    def verify_password(self, input_password, stored_hash):
        """Verify password against stored hash"""
        try:
            salt, stored_password = stored_hash.split(':')
            _, input_hash = self.hash_password(input_password, salt)
            return input_hash == stored_password
        except Exception as e:
            print(f"Password verification error: {e}")
            return False

    def register_user(self, name, email, password):
        """Register a new user without phone number"""
        # Validate inputs
        if not name or not email or not password:
            return False, "All fields are required"

        if not self.validate_email(email):
            return False, "Invalid email format"

        if len(password) < 8:
            return False, "Password must be at least 8 characters"

        try:
            # Check if user exists
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
            existing_user = cursor.fetchone()

            if existing_user:
                conn.close()
                return False, "Email already in use"

            # Hash password
            salt, password_hash = self.hash_password(password)

            # Insert new user
            cursor.execute(
                "INSERT INTO users (name, email, password_hash, created_at) VALUES (?, ?, ?, ?)",
                (name, email, f"{salt}:{password_hash}", datetime.now())
            )

            conn.commit()
            conn.close()

            print(f"User registered: {name} ({email})")
            return True, "User registered successfully"

        except Exception as e:
            print(f"Registration error: {e}")
            return False, f"Registration failed: {str(e)}"

    def login(self, email, password, verification_method='email'):
        """
        Validate credentials and initiate 2FA via email

        Args:
            email (str): User's email
            password (str): User's password
            verification_method (str): Method for 2FA (only 'email' is supported)

        Returns:
            tuple: (success, message)
        """
        try:
            # Get user from database (either from db_manager or direct)
            user = None
            if self.db_manager:
                user = self.db_manager.get_user_by_email(email)
            else:
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                cursor.execute("SELECT id, name, email, phone_number, password_hash FROM users WHERE email = ?",
                               (email,))
                user = cursor.fetchone()
                conn.close()

            if not user:
                return False, "User not found"

            # Verify password
            if self.db_manager:
                password_hash = user[4]  # Adjust based on your database schema
                password_salt = user[5]
                calculated_hash = hashlib.sha256(f"{password}{password_salt}".encode()).hexdigest()
                if calculated_hash != password_hash:
                    return False, "Invalid password"
            else:
                if not self.verify_password(password, user[4]):
                    return False, "Invalid password"

            # Generate verification code
            verification_code = self.generate_verification_code(email)

            # Send verification code via email
            send_result = self.send_verification_email(email, verification_code)

            if not send_result:
                return False, "Failed to send verification email. Please check your email configuration."

            return True, "Verification code sent to your email"

        except Exception as e:
            print(f"Login error: {e}")
            return False, f"Login failed: {str(e)}"

    def generate_verification_code(self, user_identifier):
        """Generate a verification code"""
        # Generate 6-digit code
        code = str(secrets.randbelow(900000) + 100000)

        # Store code with expiration (5 minutes)
        expiration = datetime.now() + timedelta(minutes=5)
        self.verification_codes[user_identifier] = {
            'code': code,
            'expiration': expiration
        }

        return code

    def send_verification_email(self, recipient_email, verification_code):
        """
        Send verification code via email

        Args:
            recipient_email (str): User's email address
            verification_code (str): The verification code to send

        Returns:
            bool: True if email was sent successfully, False otherwise
        """
        try:
            # Create message
            msg = MIMEMultipart()
            msg['Subject'] = f"{self.email_config['app_name']} - Your Verification Code"
            msg['From'] = self.email_config['email']
            msg['To'] = recipient_email

            # Create email body
            body = f"""
            <html>
            <body style="font-family: Arial, sans-serif; padding: 20px; max-width: 600px;">
                <div style="background-color: #f8f9fa; padding: 20px; border-radius: 5px; border: 1px solid #dee2e6;">
                    <h2 style="color: #343a40;">{self.email_config['app_name']} - Security Verification</h2>
                    <p>Your verification code is:</p>
                    <div style="background-color: #e9ecef; padding: 10px; text-align: center; font-size: 24px; font-weight: bold; letter-spacing: 5px; margin: 20px 0; border-radius: 3px;">
                        {verification_code}
                    </div>
                    <p>This code will expire in 5 minutes.</p>
                    <p>If you did not request this code, please ignore this email.</p>
                </div>
                <p style="color: #6c757d; font-size: 12px; margin-top: 20px;">
                    This is an automated message. Please do not reply to this email.
                </p>
            </body>
            </html>
            """

            msg.attach(MIMEText(body, 'html'))

            # Connect to SMTP server and send email
            with smtplib.SMTP(self.email_config['smtp_server'], self.email_config['smtp_port']) as server:
                server.starttls()  # Secure the connection
                server.login(self.email_config['email'], self.email_config['password'])
                server.send_message(msg)

            print(f"Verification email sent to {recipient_email}")
            return True

        except Exception as e:
            print(f"Error sending verification email: {e}")

            # For debugging - print the verification code in console
            print("\n" + "=" * 50)
            print(f"VERIFICATION CODE for {recipient_email}: {verification_code}")
            print("=" * 50 + "\n")

            return False

    def verify_2fa(self, user_identifier, submitted_code):
        """Verify the 2FA code"""
        # Check if code exists
        stored_data = self.verification_codes.get(user_identifier)
        if not stored_data:
            return False, "No verification code found. Please request a new code."

        # Check if code has expired
        if datetime.now() > stored_data['expiration']:
            del self.verification_codes[user_identifier]
            return False, "Verification code has expired. Please request a new code."

        # Verify code
        if submitted_code == stored_data['code']:
            # Remove the used code
            del self.verification_codes[user_identifier]
            return True, "Verification successful"
        else:
            return False, "Invalid verification code"

    def get_user_info(self, email):
        """Get user information by email"""
        try:
            if self.db_manager:
                user_data = self.db_manager.get_user_by_email(email)
                if user_data:
                    return {
                        'id': user_data[0],
                        'name': user_data[1],
                        'email': user_data[2],
                        'phone': user_data[3],
                        'status': user_data[9] if len(user_data) > 9 else 'active'
                    }
                return None
            else:
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                cursor.execute("SELECT id, name, email, phone_number, status FROM users WHERE email = ?", (email,))
                user = cursor.fetchone()
                conn.close()

                if user:
                    return {
                        'id': user[0],
                        'name': user[1],
                        'email': user[2],
                        'phone': user[3],
                        'status': user[4]
                    }

            return None

        except Exception as e:
            print(f"Error retrieving user: {e}")
            return None