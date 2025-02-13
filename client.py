import socket
import json
import getpass
import re
import ssl
import platform
import uuid
import hashlib
from datetime import datetime  # Added missing import
from scan_file.scanner_final import FileScanner
from apps.apps_interact import AppsInterface


class SecureClient:
    def __init__(self, host='localhost', port=5000):
        self.host = host
        self.port = port
        self.socket = None
        self.session_token = None
        self.file_scanner = FileScanner()
        self.apps_interface = AppsInterface()

        # Create SSL context
        self.ssl_context = ssl.create_default_context()
        self.ssl_context.check_hostname = True
        self.ssl_context.verify_mode = ssl.CERT_REQUIRED
        # Load certificate with proper error handling
        try:
            self.ssl_context.load_verify_locations("server.crt")
        except Exception as e:
            print(f"Error loading certificate: {e}")
            raise

    def connect(self):
        try:
            base_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket = self.ssl_context.wrap_socket(base_socket,
                                                       server_hostname=self.host)
            self.socket.connect((self.host, self.port))
            return True
        except Exception as e:
            print(f"Secure connection error: {e}")
            return False

    def register(self):
        print("\n=== Secure Registration ===")
        try:
            name = input("Enter your name: ")
            while True:
                email = input("Enter your email: ")
                if self._validate_email(email):
                    break
                print("Invalid email format. Please try again.")

            while True:
                phone = input("Enter your phone number (with country code, e.g., +1234567890): ")
                if self._validate_phone(phone):
                    break
                print("Invalid phone format. Please try again.")

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
                'phone_number': phone,
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
        print("\n=== Secure Login ===")
        try:
            email = input("Enter your email: ")
            password = getpass.getpass("Enter your password: ")
            verification_method = input("Preferred verification method (email/sms): ").lower()

            device_info = self._get_device_info()
            response = self._send_command('login', {
                'email': email,
                'password': password,
                'verification_method': verification_method,
                'device_info': device_info
            })

            if response['status'] == 'success':
                print("Please check your email/phone for verification code.")
                attempts = 0
                while attempts < 3:
                    code = input("Enter verification code: ")
                    verify_response = self._send_command('verify_2fa', {
                        'email': email,
                        'code': code,
                        'address': self.socket.getsockname(),
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
            return False
        except Exception as e:
            print(f"Login error: {e}")
            return False

    def run_scan(self):
        if not self._check_session():
            return False

        print("\n=== Secure File Scanner ===")
        try:
            file_selector = self.file_scanner.select_files()
            scan_results = []

            for file_path in file_selector:
                result = self.file_scanner.scan_file(file_path)
                scan_results.append(result)

            device_info = self._get_device_info()
            response = self._send_command('submit_scan', {
                'token': self.session_token,
                'scan_results': scan_results,
                'device_info': device_info
            })

            if response['status'] == 'success':
                print("Scan results securely uploaded!")
                return True
            else:
                print(f"Failed to upload scan results: {response['message']}")
                return False
        except Exception as e:
            print(f"Scan error: {e}")
            return False

    def check_apps(self):
        if not self._check_session():
            return False

        print("\n=== Secure Apps Check ===")
        try:
            updates = self.apps_interface.check_updates()
            installed = self.apps_interface.list_installed()

            device_info = self._get_device_info()
            response = self._send_command('submit_apps', {
                'token': self.session_token,
                'apps_data': {
                    'updates_available': updates,
                    'installed_apps': installed
                },
                'device_info': device_info
            })

            if response['status'] == 'success':
                print("Apps data securely uploaded!")
                return True
            else:
                print(f"Failed to upload apps data: {response['message']}")
                return False
        except Exception as e:
            print(f"Apps check error: {e}")
            return False

    def _send_command(self, command, data):
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
            self.socket.settimeout(30)  # 30 second timeout
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
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(pattern, email) is not None

    def _validate_phone(self, phone):
        pattern = r'^\+\d{10,15}$'
        return re.match(pattern, phone) is not None

    def _validate_password(self, password):
        """Validate password strength"""
        if len(password) < 8:
            return False
        if not re.search(r'[A-Z]', password):
            return False
        if not re.search(r'[a-z]', password):
            return False
        if not re.search(r'\d', password):
            return False
        if not re.search(r'[!@#$%^&*(),.?":{}|<>]', password):
            return False
        return True

    def _get_device_info(self):
        """Collect device information for security tracking"""
        try:
            return {
                'platform': platform.system(),
                'platform_version': platform.version(),
                'machine': platform.machine(),
                'processor': platform.processor(),
                'hostname': platform.node(),
                'mac_address': ':'.join(['{:02x}'.format((uuid.getnode() >> elements) & 0xff)
                                         for elements in range(0, 8 * 6, 8)][::-1])
            }
        except:
            return None

    def _check_session(self):
        """Check if session is valid"""
        if not self.session_token:
            print("Please login first!")
            return False
        return True

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
            except:
                pass
            finally:
                self.socket.close()
                self.session_token = None