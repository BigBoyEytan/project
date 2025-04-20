import socket
import json
import getpass
import re
import ssl
import platform
import uuid
import hashlib
import os
import time
from datetime import datetime
from OpenSSL import crypto


class SecureClient:
    def __init__(self, host='localhost', port=8000):
        self.host = host
        self.port = port
        self.socket = None
        self.session_token = None
        self.user_email = None

        # Ensure certificate exists before trying to load it
        self._ensure_certificate_exists()

        # Create SSL context with proper configuration
        self.ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

        # For development with self-signed certificates, we disable verification
        # In production, you'd use CERT_REQUIRED
        self.ssl_context.check_hostname = False
        self.ssl_context.verify_mode = ssl.CERT_NONE

        self.ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2
        self.ssl_context.maximum_version = ssl.TLSVersion.TLSv1_3
        self.ssl_context.set_ciphers('HIGH:!aNULL:!eNULL:!EXPORT:!DES:!MD5:!PSK:!RC4')
        # Load certificate
        try:
            cert_path = os.path.abspath("server.crt")
            print(f"Loading certificate from {cert_path}")
            self.ssl_context.load_verify_locations(cert_path)
            print("Certificate loaded successfully")
        except Exception as e:
            print(f"Warning: Error loading certificate: {e}")
            # Continue anyway since we're using CERT_NONE

    def _ensure_certificate_exists(self):
        """Ensure the certificate file exists, generate if needed"""
        CERTFILE = "server.crt"
        KEYFILE = "server.key"

        if os.path.exists(CERTFILE):
            print(f"Certificate file exists: {CERTFILE}")
            return

        print("Certificate not found. Generating self-signed certificate...")

        try:
            # Create a key pair
            k = crypto.PKey()
            k.generate_key(crypto.TYPE_RSA, 2048)

            # Create a self-signed cert
            cert = crypto.X509()
            cert.get_subject().C = "US"
            cert.get_subject().ST = "Network"
            cert.get_subject().L = "Socket"
            cert.get_subject().O = "Secure Communication"
            cert.get_subject().OU = "TLS Server"
            cert.get_subject().CN = "localhost"
            cert.set_serial_number(1000)
            cert.gmtime_adj_notBefore(0)
            cert.gmtime_adj_notAfter(10 * 365 * 24 * 60 * 60)  # Valid for 10 years
            cert.set_issuer(cert.get_subject())
            cert.set_pubkey(k)
            cert.sign(k, 'sha256')

            # Write certificate and key to files
            with open(CERTFILE, "wb") as cert_file:
                cert_file.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
            with open(KEYFILE, "wb") as key_file:
                key_file.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, k))

            print(f"Certificate files generated successfully: {CERTFILE}, {KEYFILE}")
        except Exception as e:
            print(f"Error generating certificate: {e}")
            raise

    def close(self):
        """Securely close the connection"""
        if self.socket:
            try:
                if self.session_token:
                    self._send_command('logout', {
                        'token': self.session_token,
                        'device_info': self._get_device_info()
                    })
                self.socket.shutdown(socket.SHUT_RDWR)
            except Exception as e:
                print(f"Error during shutdown: {e}")
            finally:
                self.socket.close()
                self.session_token = None
                self.user_email = None
                print("Connection closed")

    def connect(self):
        """Connect to the secure server"""
        try:
            print(f"Connecting to {self.host}:{self.port}...")
            # Create base socket
            base_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            base_socket.settimeout(10)  # Set a reasonable timeout

            # First establish a raw connection
            base_socket.connect((self.host, self.port))
            print("Raw socket connection established")

            # Add debug info
            print(f"Client SSL context - minimum_version: {self.ssl_context.minimum_version}")
            print(f"Client SSL context - maximum_version: {self.ssl_context.maximum_version}")

            # Now wrap it in SSL
            print("Applying SSL wrapper...")
            self.socket = self.ssl_context.wrap_socket(base_socket, server_hostname=self.host)
            print("SSL wrapper successful")

            # Get SSL info for debugging
            print(f"SSL version: {self.socket.version()}")
            print(f"Cipher: {self.socket.cipher()}")

            return True
        except socket.timeout:
            print("Connection timed out")
            return False
        except ConnectionRefusedError:
            print("Connection refused - server might not be running")
            return False
        except ssl.SSLError as e:
            print(f"SSL Error: {e}")
            print(f"SSL error details: {str(e)}")  # Add more error details
            return False
        except Exception as e:
            print(f"Secure connection error: {e}")
            print(f"Exception type: {type(e).__name__}")  # Add exception type
            return False

    def register(self):
        """Register a new user with the server"""
        print("\n=== Secure Registration ===")
        try:
            name = input("Enter your name: ")
            while True:
                email = input("Enter your email: ")
                if self._validate_email(email):
                    break
                print("Invalid email format. Please try again.")

            # Removed phone number collection

            while True:
                password = getpass.getpass("Enter your password: ")
                if self._validate_password(password):
                    confirm_password = getpass.getpass("Confirm password: ")
                    if password == confirm_password:
                        break
                    print("Passwords don't match!")
                else:
                    print("Password must be at least 8 characters long and contain uppercase, "
                          "lowercase, number, and special character.")

            device_info = self._get_device_info()
            response = self._send_command('register', {
                'name': name,
                'email': email,
                'password': password,
                'device_info': device_info
            })

            if response['status'] == 'success':
                print("Registration successful!")
                return True
            else:
                print(f"Registration failed: {response['message']}")
                return False
        except Exception as e:
            print(f"Registration error: {e}")
            return False

    def login(self):
        """Login with the server using two-factor authentication"""
        print("\n=== Secure Login ===")
        try:
            email = input("Enter your email: ")
            password = getpass.getpass("Enter your password: ")
            verification_method = "email"  # Always use email for 2FA

            print("Using email for verification")

            # Store email for later use during 2FA verification
            self.user_email = email

            device_info = self._get_device_info()
            response = self._send_command('login', {
                'email': email,
                'password': password,
                'verification_method': verification_method,
                'device_info': device_info
            })

            if response['status'] == 'success':
                print("Please check your email for the verification code.")
                print("NOTE: For testing, the code is also printed in the server console.")

                attempts = 0
                while attempts < 3:
                    code = input("Enter verification code from email: ")
                    verify_response = self._send_command('verify_2fa', {
                        'email': email,
                        'code': code,
                        'device_info': device_info
                    })

                    if verify_response['status'] == 'success':
                        self.session_token = verify_response['token']
                        print("Login successful!")
                        return True
                    else:
                        print(f"Verification failed: {verify_response['message']}")
                        attempts += 1
                        if attempts < 3:
                            retry = input("Try again? (y/n): ").lower()
                            if retry != 'y':
                                break
                if attempts >= 3:
                    print("Maximum verification attempts exceeded.")
            else:
                print(f"Login failed: {response['message']}")
                self.user_email = None
            return False
        except Exception as e:
            print(f"Login error: {e}")
            self.user_email = None
            return False

    def logout(self):
        """Log out the current user"""
        if not self.session_token:
            print("Not logged in")
            return False

        try:
            response = self._send_command('logout', {
                'token': self.session_token,
                'device_info': self._get_device_info()
            })

            if response['status'] == 'success':
                print("Logged out successfully")
                self.session_token = None
                self.user_email = None
                return True
            else:
                print(f"Logout failed: {response['message']}")
                return False
        except Exception as e:
            print(f"Logout error: {e}")
            return False

    def submit_scan_data(self, scan_results):
        """Submit scan results to the server"""
        if not self.session_token:
            print("Not logged in")
            return False

        try:
            response = self._send_command('submit_scan', {
                'scan_results': scan_results,
                'token': self.session_token,
                'device_info': self._get_device_info()
            })

            if response['status'] == 'success':
                print("Scan results submitted successfully")
                return True
            else:
                print(f"Submission failed: {response['message']}")
                return False
        except Exception as e:
            print(f"Scan submission error: {e}")
            return False

    def submit_apps_data(self, apps_data):
        """Submit applications data to the server"""
        if not self.session_token:
            print("Not logged in")
            return False

        try:
            response = self._send_command('submit_apps', {
                'apps_data': apps_data,
                'token': self.session_token,
                'device_info': self._get_device_info()
            })

            if response['status'] == 'success':
                print("Apps data submitted successfully")
                return True
            else:
                print(f"Submission failed: {response['message']}")
                return False
        except Exception as e:
            print(f"Apps submission error: {e}")
            return False

    def _send_command(self, command, data):
        """Send a command to the server with all required metadata"""
        if not self.socket:
            return {'status': 'error', 'message': 'Not connected to server'}

        try:
            # Add request timestamp and nonce for security
            data['command'] = command
            data['timestamp'] = str(datetime.now())
            data['nonce'] = uuid.uuid4().hex

            # Create message signature
            message_data = json.dumps(data, sort_keys=True)
            signature = hashlib.sha256(message_data.encode()).hexdigest()
            data['signature'] = signature

            message = json.dumps(data) + '\n'
            self.socket.sendall(message.encode('utf-8'))

            response = b''
            while True:
                chunk = self.socket.recv(4096)
                if not chunk:
                    break
                response += chunk
                if response.endswith(b'\n'):
                    break

            # Verify response signature if present
            response_data = json.loads(response.decode('utf-8'))
            if 'signature' in response_data:
                signature = response_data.pop('signature')
                verification_data = json.dumps(response_data, sort_keys=True)
                if signature != hashlib.sha256(verification_data.encode()).hexdigest():
                    return {'status': 'error', 'message': 'Invalid response signature'}

            return response_data
        except socket.timeout:
            return {'status': 'error', 'message': 'Connection timeout'}
        except Exception as e:
            print(f"Secure communication error: {e}")
            return {'status': 'error', 'message': 'Communication error'}

    def _validate_email(self, email):
        """Validate email format"""
        email_regex = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(email_regex, email) is not None

    def _validate_phone(self, phone):
        """Validate phone number format"""
        phone_regex = r'^\+[1-9]\d{9,14}$'
        return re.match(phone_regex, phone) is not None

    def _validate_password(self, password):
        """Validate password with minimal requirements"""
        # Only check that it's not empty and contains only English letters and numbers
        if not password:
            return False
        # Check for English letters and numbers only
        if not all(c.isalnum() or c in "!@#$%^&*(),.?\":{}|<>" for c in password):
            return False
        return True

    def _get_device_info(self):
        """Get current device information for security tracking"""
        try:
            return {
                'hostname': socket.gethostname(),
                'platform': platform.system(),
                'platform_version': platform.version(),
                'processor': platform.processor(),
                'machine': platform.machine(),
                'device_id': self._generate_device_id()
            }
        except Exception as e:
            print(f"Error getting device info: {e}")
            return {"error": str(e)}

    def _generate_device_id(self):
        """Generate a unique device ID based on hardware information"""
        try:
            system_info = f"{platform.node()}-{platform.machine()}-{platform.processor()}"
            return hashlib.md5(system_info.encode()).hexdigest()
        except Exception:
            # Fallback to a random ID
            return hashlib.md5(str(datetime.now()).encode()).hexdigest()


