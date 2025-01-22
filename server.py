import socket
import ssl
import threading
import json
import os
import time  # Added this import
from datetime import datetime, timedelta
import secrets
from DB_and_related.databses import DatabaseManager
from DB_and_related.two_factor_auth import AuthSystem
from secure_functions import SecurityFunctions


class SecureServer:
    def __init__(self, host='172.20.132.160', port=5555):
        self.host = host
        self.port = port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.clients = {}  # Store connected clients
        self.db_manager = DatabaseManager()
        self.security = SecurityFunctions(host)
        self.session_tokens = {}
        self.blocked_ips = set()

        # Initialize auth system
        self._init_auth_system()

        # Set socket options
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        self.socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 60)

    def _init_auth_system(self):
        """Initialize authentication system"""
        try:
            email_config = {
                'sender': os.getenv('EMAIL_SENDER'),
                'password': os.getenv('EMAIL_PASSWORD')
            }
            twilio_config = {
                'sid': os.getenv('TWILIO_SID'),
                'token': os.getenv('TWILIO_TOKEN'),
                'phone': os.getenv('TWILIO_PHONE')
            }
            self.auth_system = AuthSystem(email_config, twilio_config, self.db_manager)
        except Exception as e:
            print(f"Failed to initialize auth system: {e}")
            raise

    def _generate_session_token(self):
        """Generate secure session token"""
        return secrets.token_urlsafe(32)

    def authenticate_client(self, client_socket, addr):
        """Handle client authentication"""
        try:
            if not self.security.rate_limiter.is_allowed(addr[0]):
                client_socket.send("Rate limit exceeded".encode('utf-8'))
                return False

            if addr[0] in self.blocked_ips:
                client_socket.send("Access denied".encode('utf-8'))
                return False

            auth_data = self.security.decrypt_data(client_socket.recv(4096))
            auth_info = json.loads(auth_data)

            success, message = self.auth_system.login(
                auth_info.get('email', ''),
                auth_info.get('password', '')
            )

            if success:
                session_token = self._generate_session_token()
                self.session_tokens[addr] = {
                    'token': session_token,
                    'expires': datetime.now() + timedelta(hours=1)
                }

                self.clients[addr] = {
                    'socket': client_socket,
                    'email': auth_info['email'],
                    'session_token': session_token,
                    'last_activity': datetime.now()
                }

                response = self.security.encrypt_data(json.dumps({
                    'status': 'success',
                    'session_token': session_token
                }))
                client_socket.send(response)
                print(f"Client {addr[0]} authenticated successfully")
                return True
            else:
                client_socket.send(self.security.encrypt_data("Authentication failed"))
                return False

        except Exception as e:
            print(f"Authentication error: {e}")
            return False

    def handle_client(self, client_socket, addr):
        """Handle client commands"""
        print(f"New connection from {addr[0]}")

        if not self.authenticate_client(client_socket, addr):
            client_socket.close()
            return

        try:
            while True:
                if not self._verify_session(addr):
                    raise Exception("Session expired")

                encrypted_command = client_socket.recv(2048)
                if not encrypted_command:
                    break

                command = self.security.decrypt_data(encrypted_command)
                response = self.security.send_command(command, client_socket)

                if response == "DISCONNECTED":
                    break
                elif response:
                    if addr in self.clients:
                        self.clients[addr]['last_activity'] = datetime.now()
                    client_socket.send(self.security.encrypt_data("Success"))
                else:
                    client_socket.send(self.security.encrypt_data("Failed"))

        except Exception as e:
            print(f"Client error: {e}")
        finally:
            self._cleanup_client(addr)

    def _verify_session(self, addr):
        """Verify session validity"""
        if addr not in self.session_tokens:
            return False
        session = self.session_tokens[addr]
        if datetime.now() > session['expires']:
            del self.session_tokens[addr]
            return False
        return True

    def _cleanup_client(self, addr):
        """Clean up client resources"""
        if addr in self.clients:
            self.clients[addr]['socket'].close()
            del self.clients[addr]
        if addr in self.session_tokens:
            del self.session_tokens[addr]
        print(f"Client {addr[0]} disconnected")

    def broadcast_command(self, command):
        """Broadcast command to all clients"""
        disconnected_clients = []
        for addr, client_info in self.clients.items():
            try:
                response = self.security.send_command(command, client_info['socket'])
                if response == "DISCONNECTED":
                    disconnected_clients.append(addr)
                elif response:
                    client_info['socket'].send(self.security.encrypt_data("Success"))
                else:
                    client_info['socket'].send(self.security.encrypt_data("Failed"))
            except Exception:
                disconnected_clients.append(addr)

        for addr in disconnected_clients:
            self._cleanup_client(addr)

    def start(self):
        """Start the secure server"""
        try:
            self.security.generate_self_signed_cert()
            context = self.security.create_ssl_context()

            self.socket.bind((self.host, self.port))
            self.socket.listen(5)
            print(f"Server listening on {self.host}:{self.port}")

            # Start maintenance thread
            maintenance_thread = threading.Thread(target=self._maintenance_loop)
            maintenance_thread.daemon = True
            maintenance_thread.start()

            # Start command input thread
            command_thread = threading.Thread(target=self.command_input_loop)
            command_thread.daemon = True
            command_thread.start()

            while True:
                client_socket, addr = self.socket.accept()
                secure_socket = context.wrap_socket(client_socket, server_side=True)

                thread = threading.Thread(
                    target=self.handle_client,
                    args=(secure_socket, addr)
                )
                thread.start()

        except Exception as e:
            print(f"Server error: {e}")
        finally:
            self.cleanup()

    def _maintenance_loop(self):
        """Periodic maintenance tasks"""
        while True:
            try:
                current_time = datetime.now()

                # Clean expired sessions
                expired_sessions = [addr for addr, session in self.session_tokens.items()
                                    if current_time > session['expires']]
                for addr in expired_sessions:
                    self._cleanup_client(addr)

                # Clean inactive clients
                inactive_threshold = current_time - timedelta(minutes=30)
                inactive_clients = [addr for addr, client in self.clients.items()
                                    if client['last_activity'] < inactive_threshold]
                for addr in inactive_clients:
                    self._cleanup_client(addr)

                time.sleep(60)
            except Exception as e:
                print(f"Maintenance error: {e}")

    def command_input_loop(self):
        """Command input loop"""
        while True:
            try:
                command = input("Enter command to broadcast (or 'quit' to exit): ")
                if command.lower() == 'quit':
                    break
                if command:
                    print(f"Broadcasting command: {command}")
                    self.broadcast_command(command)
            except Exception as e:
                print(f"Command input error: {e}")

    def cleanup(self):
        """Clean up server resources"""
        for addr in list(self.clients.keys()):
            self._cleanup_client(addr)
        self.socket.close()
        self.db_manager.close()
        print("Server shutdown complete")


if __name__ == "__main__":
    server = SecureServer()
    print("[STARTING] Server is starting...")
    server.start()