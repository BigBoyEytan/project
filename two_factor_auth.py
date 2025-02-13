import re
import secrets
import hashlib
import pyotp
from datetime import datetime, timedelta


class AuthSystem:
    """
    Comprehensive Two-Factor Authentication System
    """

    def __init__(self, database_manager, email_config=None, sms_config=None):
        """
        Initialize the authenticator with database and communication configs

        Args:
            database_manager (SecureDatabaseManager): Database management system
            email_config (dict, optional): Email configuration for sending verification
            sms_config (dict, optional): SMS configuration for sending verification
        """
        self.db = database_manager
        self.email_config = email_config or {}
        self.sms_config = sms_config or {}

        # Verification code storage with expiration
        self.verification_codes = {}

    def validate_email(self, email):
        """
        Validate email format with comprehensive regex and additional checks

        Args:
            email (str): Email to validate

        Returns:
            bool: Whether email is valid
        """
        # More robust email validation
        email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'

        # Check basic regex
        if not re.match(email_regex, email):
            return False

        # Additional checks
        if len(email) > 254:  # RFC 5321 maximum total length
            return False

        # Prevent consecutive dots in domain
        if '..' in email:
            return False

        # Ensure valid domain structure
        domain = email.split('@')[1]
        if domain.startswith('.') or domain.endswith('.'):
            return False

        return True

    def validate_phone(self, phone):
        """
        Validate phone number format with strict rules

        Args:
            phone (str): Phone number to validate

        Returns:
            bool: Whether phone number is valid
        """
        # More strict phone validation
        phone_regex = r'^\+[1-9]\d{9,14}$'
        return re.match(phone_regex, phone) is not None

    def register_user(self, name, email, phone, password):
        """
        Register a new user

        Args:
            name (str): User's full name
            email (str): User's email
            phone (str): User's phone number
            password (str): User's password

        Returns:
            tuple: (success, message)
        """
        # Validate inputs
        if not self.validate_email(email):
            return False, "Invalid email format"

        if not self.validate_phone(phone):
            return False, "Invalid phone number format"

        # Check if user exists
        try:
            if self.db.check_user_exists(email, phone):
                return False, "User already exists"
        except Exception as e:
            return False, "Registration check failed"

        # Hash password
        salt, hashed_password = self.hash_password(password)

        # Generate TOTP secret
        totp_secret = pyotp.random_base32()

        # Create user
        try:
            created = self.db.create_user(
                name,
                email,
                phone,
                f"{salt}:{hashed_password}",
                totp_secret
            )

            return (True, "User registered successfully") if created else (False, "Registration failed")

        except Exception as e:
            print(f"Registration error: {e}")
            return False, "Registration failed"

    # Rest of the methods remain the same as in the previous implementation
    def hash_password(self, password, salt=None):
        """
        Securely hash a password

        Args:
            password (str): Plain text password
            salt (str, optional): Salt for password hashing

        Returns:
            tuple: (salt, hashed_password)
        """
        # Generate salt if not provided
        if salt is None:
            salt = secrets.token_hex(16)

        # Hash password with salt
        hashed_password = hashlib.sha256(f"{password}{salt}".encode()).hexdigest()

        return salt, hashed_password

    def verify_password(self, input_password, stored_hash):
        """
        Verify a password against stored hash

        Args:
            input_password (str): Password to verify
            stored_hash (str): Stored password hash (format: 'salt:hash')

        Returns:
            bool: Whether password is correct
        """
        try:
            salt, stored_password = stored_hash.split(':')
            _, input_hash = self.hash_password(input_password, salt)
            return input_hash == stored_password
        except Exception:
            return False

    # Verification code methods remain the same
    def generate_verification_code(self, user_identifier, method='email'):
        """
        Generate a time-limited verification code

        Args:
            user_identifier (str): Unique user identifier (email/phone)
            method (str): Verification method ('email' or 'sms')

        Returns:
            str: Verification code
        """
        # Generate 6-digit code
        code = str(secrets.randbelow(900000) + 100000)

        # Store with expiration (15 minutes)
        self.verification_codes[user_identifier] = {
            'code': code,
            'created_at': datetime.now(),
            'method': method
        }

        return code

    def validate_verification_code(self, user_identifier, submitted_code):
        """
        Validate a verification code

        Args:
            user_identifier (str): User's email or phone
            submitted_code (str): Code submitted by user

        Returns:
            bool: Whether code is valid
        """
        # Check if code exists
        stored_code_data = self.verification_codes.get(user_identifier)
        if not stored_code_data:
            return False

        # Check code expiration (15 minutes)
        code_age = datetime.now() - stored_code_data['created_at']
        if code_age > timedelta(minutes=15):
            del self.verification_codes[user_identifier]
            return False

        # Validate code
        is_valid = str(submitted_code) == stored_code_data['code']

        # Remove code after validation
        if is_valid:
            del self.verification_codes[user_identifier]

        return is_valid