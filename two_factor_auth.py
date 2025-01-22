import hashlib
import secrets
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from twilio.rest import Client
import pyotp
import re
from datetime import datetime, timedelta
from DB_and_related.databses import DatabaseManager

class AuthSystem:
    def __init__(self, email_config, twilio_config, db_manager=None):
        """
        Initialize the authentication system
        email_config: dict with 'sender' and 'password'
        twilio_config: dict with 'sid', 'token', and 'phone'
        db_manager: DatabaseManager instance (optional)
        """
        self.db = db_manager if db_manager else DatabaseManager()
        self.email_sender = email_config['sender']
        self.email_password = email_config['password']
        self.twilio_sid = twilio_config['sid']
        self.twilio_token = twilio_config['token']
        self.twilio_phone = twilio_config['phone']

    def register_user(self, name, email, phone_number, password):
        """Register a new user"""
        try:
            if not self._validate_email(email) or not self._validate_phone(phone_number):
                return False, "Invalid email or phone number format"

            # Generate password hash with salt
            salt = secrets.token_hex(16)
            password_hash = self._hash_password(password, salt)

            # Generate TOTP secret for 2FA
            totp_secret = pyotp.random_base32()

            # Create user in database
            success = self.db.create_user(
                name,
                email,
                phone_number,
                f"{salt}:{password_hash}",
                totp_secret
            )

            if success:
                return True, "User registered successfully"
            return False, "Email or phone number already exists"
        except Exception as e:
            return False, f"Registration error: {str(e)}"

    def login(self, email, password, verification_method='email'):
        """First step of login - verify password and send 2FA code"""
        try:
            user = self.db.get_user_by_email(email)
            if not user:
                return False, "User not found"

            # Check for too many failed attempts
            if user[9] >= 5:  # failed_attempts
                last_login = datetime.fromisoformat(user[8]) if user[8] else datetime.min
                if datetime.now() - last_login < timedelta(minutes=15):
                    return False, "Account temporarily locked. Try again later"

            # Verify password
            stored_hash = user[4]  # password_hash
            salt = stored_hash.split(':')[0]
            if not self._verify_password(password, salt, stored_hash):
                self.db.update_failed_attempts(user[0])
                return False, "Invalid password"

            # Send verification code
            if verification_method == 'email':
                code = self._send_email_verification(user[2])  # email
            else:
                code = self._send_sms_verification(user[3])  # phone_number

            if not code:
                return False, f"Failed to send verification code via {verification_method}"

            # Store verification code temporarily (in practice, use Redis or similar)
            self._store_verification_code(user[0], code)

            return True, "Verification code sent"
        except Exception as e:
            return False, f"Login error: {str(e)}"

    def verify_2fa(self, email, code):
        """Second step of login - verify 2FA code"""
        try:
            user = self.db.get_user_by_email(email)
            if not user:
                return False, "User not found"

            # Verify the code (in practice, compare with stored code in Redis)
            if not self._verify_code(user[0], code):
                return False, "Invalid verification code"

            # Reset failed attempts and update last login
            self.db.reset_failed_attempts(user[0])
            return True, "Login successful"
        except Exception as e:
            return False, f"Verification error: {str(e)}"

    def _validate_email(self, email):
        """Validate email format"""
        pattern = r'^[\w\.-]+@[\w\.-]+\.\w+$'
        return re.match(pattern, email) is not None

    def _validate_phone(self, phone):
        """Validate phone number format"""
        pattern = r'^\+\d{10,15}$'
        return re.match(pattern, phone) is not None

    def _hash_password(self, password, salt):
        """Hash password with salt using SHA-256"""
        return hashlib.sha256(f"{password}{salt}".encode()).hexdigest()

    def _verify_password(self, password, salt, stored_hash):
        """Verify password against stored hash"""
        salt_from_storage = stored_hash.split(':')[0]
        hash_from_storage = stored_hash.split(':')[1]
        return self._hash_password(password, salt_from_storage) == hash_from_storage

    def _send_email_verification(self, email):
        """Send verification code via email"""
        code = secrets.randbelow(900000) + 100000  # 6-digit code

        msg = MIMEMultipart()
        msg['From'] = self.email_sender
        msg['To'] = email
        msg['Subject'] = "Your Verification Code"

        body = f"Your verification code is: {code}"
        msg.attach(MIMEText(body, 'plain'))

        try:
            server = smtplib.SMTP('smtp.gmail.com', 587)
            server.starttls()
            server.login(self.email_sender, self.email_password)
            server.send_message(msg)
            server.quit()
            return code
        except Exception as e:
            print(f"Error sending email: {e}")
            return None

    def _send_sms_verification(self, phone_number):
        """Send verification code via SMS"""
        code = secrets.randbelow(900000) + 100000  # 6-digit code

        try:
            client = Client(self.twilio_sid, self.twilio_token)
            message = client.messages.create(
                body=f"Your verification code is: {code}",
                from_=self.twilio_phone,
                to=phone_number
            )
            return code
        except Exception as e:
            print(f"Error sending SMS: {e}")
            return None

    def _store_verification_code(self, user_id, code):
        """
        Store verification code temporarily
        In production, use Redis or similar with expiration
        """
        # This is a placeholder - implement proper storage in production
        pass

    def _verify_code(self, user_id, code):
        """
        Verify the provided code
        In production, compare with stored code in Redis
        """
        # This is a placeholder - implement proper verification in production
        return True

    def __del__(self):
        """Cleanup database connection"""
        self.db.close()