import socket
import json
import threading
import os
import secrets
import ssl
from datetime import datetime
from DB_and_related.databses import SecureDatabaseManager
from DB_and_related.two_factor_auth import AuthSystem
from server_and_client.cert_generator import generate_self_signed_cert


class SecureServer:
    def __init__(self, host='0.0.0.0', port=5000):
        self.host = host
        self.port = port

        # Generate SSL certificates if they don't exist
        if not os.path.exists("server.crt") or not os.path.exists("server.key"):
            generate_self_signed_cert()

        # Create SSL context
        try:
            self.ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            self.ssl_context.load_cert_chain(certfile="server.crt", keyfile="server.key")
        except Exception as e:
            print(f"Error setting up SSL context: {e}")
            raise

        # Create secure socket
        try:
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server_socket.bind((self.host, self.port))
            self.server_socket.listen(5)
        except Exception as e:
            print(f"Error setting up server socket: {e}")
            raise

        # Initialize secure database and auth system
        try:
            encryption_key = secrets.token_bytes(32)  # In production, load from secure storage
            self.db_manager = SecureDatabaseManager(encryption_key=encryption_key)
        except Exception as e:
            print(f"Error initializing database: {e}")
            raise

        try:
            email_config = {
                'sender': 'your-email@gmail.com',
                'password': 'your-app-password'
            }
            twilio_config = {
                'sid': 'your-twilio-sid',
                'token': 'your-twilio-token',
                'phone': 'your-twilio-phone'
            }
            self.auth_system = AuthSystem(email_config, twilio_config, self.db_manager)
        except Exception as e:
            print(f"Error initializing auth system: {e}")
            raise

        # Secure session management
        self.active_sessions = {}
        self.session_lock = threading.Lock()

        # Rate limiting
        self.request_counts = {}
        self.rate_limit = 100  # requests per minute
        self.cleanup_thread = threading.Thread(target=self._cleanup_sessions)
        self.cleanup_thread.daemon = True
        self.cleanup_thread.start()

        print("Server initialized successfully!")

    def start(self):
        print(f"Secure server started on {self.host}:{self.port}")
        try:
            while True:
                client_socket, address = self.server_socket.accept()
                if self._check_rate_limit(address[0]):
                    secure_socket = self.ssl_context.wrap_socket(client_socket, server_side=True)
                    client_thread = threading.Thread(target=self.handle_client,
                                                     args=(secure_socket, address))
                    client_thread.start()
                else:
                    client_socket.close()
        except Exception as e:
            print(f"Server error: {e}")
        finally:
            self.server_socket.close()

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
                else:
                    response = {'status': 'error', 'message': 'Invalid command'}

                self.send_data(client_socket, response)

        except Exception as e:
            print(f"Error handling client {address}: {e}")
        finally:
            with self.session_lock:
                if address in self.active_sessions:
                    del self.active_sessions[address]
            client_socket.close()

    def handle_registration(self, data, address):
        if not self._validate_request_data(data):
            return {'status': 'error', 'message': 'Invalid request data'}

        success, message = self.auth_system.register_user(
            data['name'],
            data['email'],
            data['phone_number'],
            data['password']
        )

        # Log registration attempt
        self.db_manager.log_auth_attempt(
            None, 'registration', success, address[0],
            data.get('device_info'), None
        )

        return {'status': 'success' if success else 'error', 'message': message}

    def handle_login(self, data, address):
        if not self._validate_request_data(data):
            return {'status': 'error', 'message': 'Invalid request data'}

        success, message = self.auth_system.login(
            data['email'],
            data['password'],
            data.get('verification_method', 'email')
        )

        user = self.db_manager.get_user_by_email(data['email'])
        if user:
            self.db_manager.log_auth_attempt(
                user[0], 'login', success, address[0],
                data.get('device_info'), data.get('verification_method')
            )

        return {'status': 'success' if success else 'error', 'message': message}

    def handle_2fa_verification(self, data, address):
        if not self._validate_request_data(data):
            return {'status': 'error', 'message': 'Invalid request data'}

        success, message = self.auth_system.verify_2fa(
            data['email'],
            data['code']
        )

        if success:
            session_token = secrets.token_hex(32)
            with self.session_lock:
                self.active_sessions[address] = {
                    'email': data['email'],
                    'token': session_token,
                    'timestamp': datetime.now(),
                    'last_activity': datetime.now()
                }
            return {'status': 'success', 'token': session_token}
        return {'status': 'error', 'message': message}

    def handle_scan_submission(self, data, address):
        if not self.verify_session(address, data.get('token')):
            return {'status': 'error', 'message': 'Invalid session'}

        try:
            success = self.db_manager.store_scan_results(
                self.active_sessions[address]['email'],
                data['scan_results']
            )
            return {
                'status': 'success' if success else 'error',
                'message': 'Scan results stored successfully' if success else 'Failed to store results'
            }
        except Exception as e:
            return {'status': 'error', 'message': str(e)}

    def handle_apps_submission(self, data, address):
        if not self.verify_session(address, data.get('token')):
            return {'status': 'error', 'message': 'Invalid session'}

        try:
            success = self.db_manager.store_apps_data(
                self.active_sessions[address]['email'],
                data['apps_data']
            )
            return {
                'status': 'success' if success else 'error',
                'message': 'Apps data stored successfully' if success else 'Failed to store data'
            }
        except Exception as e:
            return {'status': 'error', 'message': str(e)}

    def _validate_request_data(self, data):
        """Validate incoming request data"""
        required_fields = {
            'register': ['name', 'email', 'phone_number', 'password'],
            'login': ['email', 'password'],
            'verify_2fa': ['email', 'code'],
            'submit_scan': ['token', 'scan_results'],
            'submit_apps': ['token', 'apps_data']
        }

        command = data.get('command')
        if command not in required_fields:
            return False

        return all(field in data for field in required_fields[command])

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

    def _cleanup_sessions(self):
        """Clean up expired sessions"""
        while True:
            try:
                current_time = datetime.now()
                with self.session_lock:
                    expired = [addr for addr, session in self.active_sessions.items()
                               if (current_time - session['last_activity']).seconds > 1800]
                    for addr in expired:
                        del self.active_sessions[addr]
                time.sleep(300)  # Run every 5 minutes
            except Exception:
                continue

    def verify_session(self, address, token):
        """Verify session with additional security checks"""
        with self.session_lock:
            session = self.active_sessions.get(address)
            if not session:
                return False
            if session['token'] != token:
                return False
            if (datetime.now() - session['timestamp']).seconds > 7200:  # 2 hour timeout
                del self.active_sessions[address]
                return False
            session['last_activity'] = datetime.now()
            return True

    def receive_data(self, client_socket):
        """Receive data with timeout and size limits"""
        try:
            client_socket.settimeout(30)  # 30 second timeout
            data = b''
            while len(data) < 1048576:  # 1MB size limit
                chunk = client_socket.recv(4096)
                if not chunk:
                    break
                data += chunk
                if data.endswith(b'\n'):
                    break
            return json.loads(data.decode('utf-8'))
        except Exception:
            return None

    def send_data(self, client_socket, data):
        """Send data with timeout"""
        try:
            client_socket.settimeout(30)
            message = json.dumps(data) + '\n'
            client_socket.sendall(message.encode('utf-8'))
        except Exception as e:
            print(f"Error sending data: {e}")


if __name__ == '__main__':
    server = SecureServer()
    server.start()