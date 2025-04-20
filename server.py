import socket
import json
import threading
import os
import secrets
import ssl
import hashlib
from datetime import datetime, timedelta
from OpenSSL import crypto

from databases import SecureDatabaseManager
from two_factor_auth import AuthSystem


class SecureServer:
    def __init__(self, host='0.0.0.0', port=8000):
        # Use the same host value in all places
        self.host = host
        self.port = port

        ENCRYPTION_KEY = b'secure_encryption_key_for_development'

        # Then use it consistently
        self.db_manager = SecureDatabaseManager(
            db_name='user_scores.db',
            encryption_key=ENCRYPTION_KEY
        )

        # Set default email credentials if not already set in environment
        default_email = "IronSystem2Fa@gmail.com"
        default_password = "qnhm llwn rrnu whpt"

        if not os.environ.get('EMAIL_USERNAME'):
            os.environ['EMAIL_USERNAME'] = default_email

        if not os.environ.get('EMAIL_PASSWORD'):
            os.environ['EMAIL_PASSWORD'] = default_password

        # Email config for 2FA
        email_config = {
            'smtp_server': 'smtp.gmail.com',
            'smtp_port': 587,
            'email': os.environ.get('EMAIL_USERNAME', default_email),
            'password': os.environ.get('EMAIL_PASSWORD', default_password),
            'app_name': 'Security Scanner & Optimizer'
        }

        # Initialize authentication system with email config
        self.auth_system = AuthSystem(self.db_manager, email_config=email_config)

        # Generate SSL certificates if they don't exist
        self.generate_self_signed_cert()

        # Create SSL context
        try:
            self.ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

            # ADD THIS: Set compatible TLS versions
            self.ssl_context.minimum_version = ssl.TLSVersion.TLSv1_2
            self.ssl_context.maximum_version = ssl.TLSVersion.TLSv1_3

            # ADD THIS: Set cipher suites
            self.ssl_context.set_ciphers('HIGH:!aNULL:!eNULL:!EXPORT:!DES:!MD5:!PSK:!RC4')

            self.ssl_context.load_cert_chain(certfile="server.crt", keyfile="server.key")
            print(f"Loaded SSL certificates successfully")
        except Exception as e:
            print(f"Error setting up SSL context: {e}")
            raise

        # Create secure socket
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # Set socket options to reuse address
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
            print(f"Socket bound to {self.host}:{self.port}")
        except Exception as e:
            print(f"Error setting up server socket: {e}")
            raise

        # Initialize session storage
        self.active_sessions = {}
        self.session_lock = threading.Lock()

        # Rate limiting
        self.request_counts = {}
        self.rate_limit = 100  # requests per minute

        print("Server initialized successfully!")
        print(f"Using email: {email_config['email']} for 2FA")

    def generate_self_signed_cert(self):
        """
        Generate self-signed certificate and key if they don't exist.
        In production, use properly signed certificates.
        """
        CERTFILE = "server.crt"
        KEYFILE = "server.key"

        # Skip if files already exist
        if os.path.exists(CERTFILE) and os.path.exists(KEYFILE):
            print(f"Using existing certificate files: {CERTFILE}, {KEYFILE}")
            return

        print("Generating self-signed certificates...")

        # Create a key pair
        k = crypto.PKey()
        k.generate_key(crypto.TYPE_RSA, 2048)

        # Create a self-signed cert with multiple subject alternative names
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

        # Add subject alternative names (include both localhost and 0.0.0.0)
        sans = ["DNS:localhost", "IP:127.0.0.1", "IP:0.0.0.0"]
        san_extension = crypto.X509Extension(
            b"subjectAltName",
            False,
            ", ".join(sans).encode()
        )
        cert.add_extensions([san_extension])

        cert.sign(k, 'sha256')

        # Write certificate and key to files
        with open(CERTFILE, "wb") as cert_file:
            cert_file.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
        with open(KEYFILE, "wb") as key_file:
            key_file.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, k))

        print(f"Certificate files generated successfully: {CERTFILE}, {KEYFILE}")

    def start(self):
        print(f"Secure server started on {self.host}:{self.port}")
        try:
            while True:
                try:
                    print("Waiting for client connection...")
                    client_socket, address = self.server_socket.accept()
                    print(f"Raw connection accepted from {address}")

                    if self._check_rate_limit(address[0]):
                        try:
                            # Wrap the socket with SSL
                            print(f"Wrapping socket with SSL for {address}")
                            secure_socket = self.ssl_context.wrap_socket(client_socket, server_side=True)
                            print(f"SSL handshake successful with {address}")

                            # Start a new thread to handle this client
                            client_thread = threading.Thread(target=self.handle_client,
                                                             args=(secure_socket, address))
                            client_thread.start()
                        except Exception as ssl_error:
                            print(f"SSL handshake failed with {address}: {ssl_error}")
                            client_socket.close()
                    else:
                        print(f"Rate limit exceeded for {address}, connection closed")
                        client_socket.close()
                except Exception as accept_error:
                    print(f"Error accepting connection: {accept_error}")
        except KeyboardInterrupt:
            print("Server shutting down...")
        except Exception as e:
            print(f"Server error: {e}")
        finally:
            self.server_socket.close()
            print("Server socket closed")

    def handle_client(self, client_socket, address):
        print(f"New secure connection from {address}")
        try:
            while True:
                data = self.receive_data(client_socket)
                if not data:
                    break

                command = data.get('command')
                if command == 'register':
                    response = self.handle_registration(data, address)
                elif command == 'login':
                    response = self.handle_login(data, address)
                elif command == 'verify_2fa':
                    response = self.handle_2fa_verification(data, address)
                elif command == 'submit_scan':
                    response = self.handle_scan_submission(data, address)
                elif command == 'submit_apps':
                    response = self.handle_apps_submission(data, address)
                elif command == 'logout':
                    response = self.handle_logout(data, address)
                else:
                    response = {'status': 'error', 'message': 'Invalid command'}

                self.send_data(client_socket, response)

                # If client is logging out, break the connection loop
                if command == 'logout':
                    break

        except Exception as e:
            print(f"Error handling client {address}: {e}")
        finally:
            with self.session_lock:
                if address in self.active_sessions:
                    del self.active_sessions[address]
            client_socket.close()
            print(f"Connection closed with {address}")

    def handle_registration(self, data, address):
        """Handle user registration using the auth system"""
        print(f"Registration request from {address}")

        try:
            # Extract registration data
            name = data.get('name', '')
            email = data.get('email', '')
            password = data.get('password', '')
            device_info = data.get('device_info', {})

            # Validate required fields - removed phone_number
            if not name or not email or not password:
                return {'status': 'error', 'message': 'All fields are required'}

            # Register user with database manager
            # Hash password
            salt = secrets.token_hex(16)
            password_hash = hashlib.sha256(f"{password}{salt}".encode()).hexdigest()

            # Register user with database manager - no phone number
            success = self.db_manager.create_user(name, email, password_hash, salt)

            if success:
                return {'status': 'success', 'message': 'User registered successfully'}
            else:
                return {'status': 'error', 'message': 'User already exists or registration failed'}

        except Exception as e:
            print(f"Registration error: {e}")
            return {'status': 'error', 'message': f'Registration failed: {str(e)}'}

    def handle_login(self, data, address):
        """Handle user login and initiate email 2FA"""
        print(f"Login request from {address}")

        try:
            # Extract login data
            email = data.get('email', '')
            password = data.get('password', '')
            verification_method = data.get('verification_method', 'email')  # Default to email
            device_info = data.get('device_info', {})

            # Get user from database
            user = self.db_manager.get_user_by_email(email)
            if not user:
                return {'status': 'error', 'message': 'User not found'}

            # Verify password
            # Indexes: 0=id, 1=name, 2=email, 3=password_hash, 4=password_salt
            # (adjusted since we removed phone_number)
            password_hash = user[3]
            password_salt = user[4]

            # Calculate hash with provided password and stored salt
            calculated_hash = hashlib.sha256(f"{password}{password_salt}".encode()).hexdigest()

            # Check if password matches
            if calculated_hash != password_hash:
                return {'status': 'error', 'message': 'Invalid password'}

            # Generate and send email verification code
            verification_code = self.auth_system.generate_verification_code(email)

            # Send verification email
            email_sent = self.auth_system.send_verification_email(email, verification_code)

            if not email_sent:
                return {'status': 'error', 'message': 'Failed to send verification email. Please try again later.'}

            # Store the verification code with expiration (5 minutes) in our session management
            expiration = datetime.now() + timedelta(minutes=5)

            with self.session_lock:
                if 'pending_verifications' not in self.active_sessions:
                    self.active_sessions['pending_verifications'] = {}

                self.active_sessions['pending_verifications'][email] = {
                    'code': verification_code,
                    'expiration': expiration,
                    'email': email
                }

            return {'status': 'success', 'message': 'Verification code sent to your email'}

        except Exception as e:
            print(f"Login error: {e}")
            return {'status': 'error', 'message': f'Login failed: {str(e)}'}

    def handle_2fa_verification(self, data, address):
        """Handle email 2FA verification"""
        print(f"2FA verification request from {address}")

        try:
            # Extract verification data
            email = data.get('email', '')
            verification_code = data.get('code', '')
            device_info = data.get('device_info', {})

            # Verify the code
            with self.session_lock:
                if ('pending_verifications' not in self.active_sessions or
                        email not in self.active_sessions['pending_verifications']):
                    return {'status': 'error', 'message': 'No pending verification found'}

                verification_data = self.active_sessions['pending_verifications'][email]

                # Check if code has expired
                if datetime.now() > verification_data['expiration']:
                    del self.active_sessions['pending_verifications'][email]
                    return {'status': 'error', 'message': 'Verification code has expired'}

                # Verify code
                if verification_code != verification_data['code']:
                    return {'status': 'error', 'message': 'Invalid verification code'}

                # Code is valid, remove from pending verifications
                del self.active_sessions['pending_verifications'][email]

            # Generate a session token
            session_token = secrets.token_hex(32)

            # Store session information
            with self.session_lock:
                self.active_sessions[address] = {
                    'email': email,
                    'token': session_token,
                    'timestamp': datetime.now(),
                    'last_activity': datetime.now(),
                    'device_info': device_info
                }

            return {'status': 'success', 'message': 'Authentication successful', 'token': session_token}

        except Exception as e:
            print(f"2FA verification error: {e}")
            return {'status': 'error', 'message': f'Verification failed: {str(e)}'}

    def handle_scan_submission(self, data, address):
        """Handle scan data submission"""
        if not self.verify_session(address, data.get('token')):
            return {'status': 'error', 'message': 'Invalid session'}

        try:
            # Update last activity time
            with self.session_lock:
                if address in self.active_sessions:
                    self.active_sessions[address]['last_activity'] = datetime.now()

            # Extract and process scan data
            scan_results = data.get('scan_results', {})
            user_email = self.active_sessions[address]['email']

            # Here you would typically store the scan results in the database
            # For this implementation, we'll just acknowledge receipt

            print(f"Scan submission from {address} for user {user_email}")
            return {'status': 'success', 'message': 'Scan results stored successfully'}

        except Exception as e:
            print(f"Scan submission error: {e}")
            return {'status': 'error', 'message': f'Failed to process scan: {str(e)}'}

    def handle_apps_submission(self, data, address):
        """Handle apps data submission"""
        if not self.verify_session(address, data.get('token')):
            return {'status': 'error', 'message': 'Invalid session'}

        try:
            # Update last activity time
            with self.session_lock:
                if address in self.active_sessions:
                    self.active_sessions[address]['last_activity'] = datetime.now()

            # Extract and process apps data
            apps_data = data.get('apps_data', {})
            user_email = self.active_sessions[address]['email']

            # Here you would typically store the apps data in the database
            # For this implementation, we'll just acknowledge receipt

            print(f"Apps submission from {address} for user {user_email}")
            return {'status': 'success', 'message': 'Apps data stored successfully'}

        except Exception as e:
            print(f"Apps submission error: {e}")
            return {'status': 'error', 'message': f'Failed to process apps data: {str(e)}'}

    def handle_logout(self, data, address):
        """Handle user logout"""
        try:
            token = data.get('token')

            # Clear the session
            with self.session_lock:
                if address in self.active_sessions and self.active_sessions[address]['token'] == token:
                    print(f"Logging out user {self.active_sessions[address]['email']} from {address}")
                    del self.active_sessions[address]
                    return {'status': 'success', 'message': 'Logged out successfully'}

            return {'status': 'error', 'message': 'Invalid session for logout'}

        except Exception as e:
            print(f"Logout error: {e}")
            return {'status': 'error', 'message': f'Logout failed: {str(e)}'}

    def _check_rate_limit(self, ip_address):
        """Check if request rate is within limits"""
        current_time = datetime.now()
        if ip_address in self.request_counts:
            count, timestamp = self.request_counts[ip_address]
            if (current_time - timestamp).seconds < 60:
                if count >= self.rate_limit:
                    return False
                self.request_counts[ip_address] = (count + 1, timestamp)
            else:
                self.request_counts[ip_address] = (1, current_time)
        else:
            self.request_counts[ip_address] = (1, current_time)
        return True

    def verify_session(self, address, token):
        """Verify session is valid and active"""
        with self.session_lock:
            session = self.active_sessions.get(address)
            if not session:
                return False
            if session['token'] != token:
                return False

            # Update last activity timestamp
            session['last_activity'] = datetime.now()
            return True

    def receive_data(self, client_socket):
        """Receive data from client"""
        try:
            data = b''
            while True:
                chunk = client_socket.recv(4096)
                if not chunk:
                    break
                data += chunk
                if data.endswith(b'\n'):
                    break
            return json.loads(data.decode('utf-8'))
        except Exception as e:
            print(f"Error receiving data: {e}")
            return None

    def send_data(self, client_socket, data):
        """Send data to client"""
        try:
            message = json.dumps(data) + '\n'
            client_socket.sendall(message.encode('utf-8'))
        except Exception as e:
            print(f"Error sending data: {e}")


if __name__ == '__main__':
    print("Starting secure server...")

    # Default email credentials from the comments in your code
    default_email = "IronSystem2Fa@gmail.com"
    default_password = "qnhm llwn rrnu whpt"

    # Set environment variables if not already set
    if not os.environ.get('EMAIL_USERNAME'):
        os.environ['EMAIL_USERNAME'] = default_email

    if not os.environ.get('EMAIL_PASSWORD'):
        os.environ['EMAIL_PASSWORD'] = default_password

    print(f"Using email: {os.environ.get('EMAIL_USERNAME')} for 2FA")

    server = SecureServer()
    server.start()