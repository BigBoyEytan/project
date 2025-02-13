import hashlib
import secrets
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from twilio.rest import Client
import pyotp
import re
from datetime import datetime
from DB_and_related.databses import DatabaseManager


class AuthSystem:
    """
    A comprehensive two-factor authentication system that supports both email and SMS verification.

    This system handles:
    1. User registration with secure password hashing
    2. Two-step login process (password + verification code)
    3. Email and SMS verification methods
    """

    def __init__(self, email_config, twilio_config, db_manager=None):
        """
        Initialize the authentication system with necessary configurations.

        Args:
            email_config (dict): Contains email sender details
                - sender: Email address to send verifications from
                - password: Password for the sender email
            twilio_config (dict): Contains Twilio credentials for SMS
                - sid: Twilio account SID
                - token: Twilio auth token
                - phone: Twilio phone number
            db_manager (DatabaseManager, optional): Database manager instance
        """
        # Initialize database connection
        self.db = db_manager if db_manager else DatabaseManager()

        # Email configuration
        self.email_sender = email_config['sender']
        self.email_password = email_config['password']

        # Twilio configuration for SMS
        self.twilio_sid = twilio_config['sid']
        self.twilio_token = twilio_config['token']
        self.twilio_phone = twilio_config['phone']

        # Store verification codes in memory (in production, use Redis/database)
        self.verification_codes = {}

    def register_user(self, name, email, phone_number, password):
        """
        Register a new user with the system.

        Process:
        1. Validate email and phone formats
        2. Generate secure password hash with salt
        3. Generate TOTP secret for future use
        4. Store user data in database

        Args:
            name (str): User's full name
            email (str): User's email address
            phone_number (str): User's phone number (with country code)
            password (str): User's chosen password

        Returns:
            tuple: (success: bool, message: str)
        """
        try:
            # Input validation
            if not self._validate_email(email):
                return False, "Invalid email format"

            if not self._validate_phone(phone_number):
                return False, "Invalid phone number format"

            # Generate password hash with unique salt
            salt = secrets.token_hex(16)
            password_hash = self._hash_password(password, salt)

            # Generate TOTP secret for potential future use
            totp_secret = pyotp.random_base32()

            # Create user record
            success = self.db.create_user(
                name,
                email,
                phone_number,
                f"{salt}:{password_hash}",  # Store salt with hash
                totp_secret
            )

            if success:
                return True, "User registered successfully"
            return False, "Email or phone number already exists"

        except Exception as e:
            return False, f"Registration error: {str(e)}"

    def login(self, email, password, verification_method='email'):
        """
        First step of the login process - verify password and send verification code.

        Process:
        1. Verify user exists
        2. Validate password
        3. Generate and send verification code

        Args:
            email (str): User's email address
            password (str): User's password
            verification_method (str): 'email' or 'sms'

        Returns:
            tuple: (success: bool, message: str)
        """
        try:
            # Get user from database
            user = self.db.get_user_by_email(email)
            if not user:
                return False, "User not found"

            # Verify password
            stored_hash = user[4]  # password_hash field
            salt = stored_hash.split(':')[0]
            if not self._verify_password(password, salt, stored_hash):
                return False, "Invalid password"

            # Generate and send verification code
            if verification_method == 'email':
                code = self._send_email_verification(user[2])  # email field
            else:
                code = self._send_sms_verification(user[3])  # phone_number field

            if not code:
                return False, f"Failed to send verification code via {verification_method}"

            # Store verification code
            self._store_verification_code(user[0], code)

            return True, "Verification code sent"

        except Exception as e:
            return False, f"Login error: {str(e)}"

    def verify_2fa(self, email, code):
        """
        Second step of the login process - verify the 2FA code.

        Process:
        1. Verify user exists
        2. Validate verification code
        3. Update login status

        Args:
            email (str): User's email address
            code (str): Verification code entered by user

        Returns:
            tuple: (success: bool, message: str)
        """
        try:
            user = self.db.get_user_by_email(email)
            if not user:
                return False, "User not found"

            # Verify the code
            if not self._verify_code(user[0], code):
                return False, "Invalid verification code"

            # Update last login time
            self.db.reset_failed_attempts(user[0])
            return True, "Login successful"

        except Exception as e:
            return False, f"Verification error: {str(e)}"

    def _validate_email(self, email):
        """
        Validate email format using regex.

        Pattern matches:
        - Local part: letters, numbers, and common special characters
        - Domain: letters, numbers, dots
        - TLD: 2 or more characters
        """
        pattern = r'^[\w\.-]+@[\w\.-]+\.\w+$'
        return re.match(pattern, email) is not None

    def _validate_phone(self, phone):
        """
        Validate phone number format.

        Format requirements:
        - Starts with +
        - Contains 10-15 digits
        - No spaces or special characters
        """
        pattern = r'^\+\d{10,15}$'
        return re.match(pattern, phone) is not None

    def _hash_password(self, password, salt):
        """
        Create secure hash of password using SHA-256.

        Process:
        1. Combine password with salt
        2. Create SHA-256 hash
        3. Return hexadecimal representation
        """
        return hashlib.sha256(f"{password}{salt}".encode()).hexdigest()

    def _verify_password(self, password, salt, stored_hash):
        """
        Verify password against stored hash.

        Process:
        1. Extract salt from stored hash
        2. Hash input password with salt
        3. Compare with stored hash
        """
        salt_from_storage = stored_hash.split(':')[0]
        hash_from_storage = stored_hash.split(':')[1]
        return self._hash_password(password, salt_from_storage) == hash_from_storage

    def _send_email_verification(self, email):
        """
        Send verification code via email using SMTP.

        Process:
        1. Generate 6-digit code
        2. Create email message
        3. Send via SMTP
        """
        code = secrets.randbelow(900000) + 100000  # Generate 6-digit code

        msg = MIMEMultipart()
        msg['From'] = self.email_sender
        msg['To'] = email
        msg['Subject'] = "Your Verification Code"

        body = f"""
        Your verification code is: {code}

        If you didn't request this code, please ignore this email.
        Do not share this code with anyone.
        """
        msg.attach(MIMEText(body, 'plain'))

        try:
            with smtplib.SMTP('smtp.gmail.com', 587) as server:
                server.starttls()
                server.login(self.email_sender, self.email_password)
                server.send_message(msg)
            return code
        except Exception as e:
            print(f"Error sending email: {e}")
            return None

    def _send_sms_verification(self, phone_number):
        """
        Send verification code via SMS using Twilio.

        Process:
        1. Generate 6-digit code
        2. Create SMS message
        3. Send via Twilio API
        """
        code = secrets.randbelow(900000) + 100000  # Generate 6-digit code

        try:
            client = Client(self.twilio_sid, self.twilio_token)
            message = client.messages.create(
                body=f"Your verification code is: {code}\nDo not share this code.",
                from_=self.twilio_phone,
                to=phone_number
            )
            return code
        except Exception as e:
            print(f"Error sending SMS: {e}")
            return None

    def _store_verification_code(self, user_id, code):
        """
        Store verification code in memory.
        In production, use Redis or database with proper expiration.
        """
        self.verification_codes[user_id] = code

    def _verify_code(self, user_id, code):
        """
        Verify the provided code against stored code.
        """
        stored_code = self.verification_codes.get(user_id)
        if stored_code and str(stored_code) == str(code):
            del self.verification_codes[user_id]  # Remove code after use
            return True
        return False

    def __del__(self):
        """Cleanup database connection on object destruction"""
        self.db.close()