import socket
import ssl
from OpenSSL import crypto
import time
import json
from cryptography.fernet import Fernet


class RateLimit:
    def __init__(self, max_requests=5, time_window=60):
        self.max_requests = max_requests
        self.time_window = time_window
        self.requests = {}

    def is_allowed(self, ip):
        current_time = time.time()
        if ip in self.requests:
            requests = [req for req in self.requests[ip] if current_time - req < self.time_window]
            self.requests[ip] = requests
            if len(requests) >= self.max_requests:
                return False
        else:
            self.requests[ip] = []
        self.requests[ip].append(current_time)
        return True


class SecurityFunctions:
    def __init__(self, host='172.20.132.160'):
        self.host = host
        self.encryption_key = Fernet.generate_key()
        self.cipher_suite = Fernet(self.encryption_key)
        self.rate_limiter = RateLimit()

    def generate_self_signed_cert(self):
        """Generate self-signed certificate and key"""
        try:
            k = crypto.PKey()
            k.generate_key(crypto.TYPE_RSA, 2048)

            cert = crypto.X509()
            cert.get_subject().C = "US"
            cert.get_subject().ST = "Network"
            cert.get_subject().L = "Socket"
            cert.get_subject().O = "Secure Communication"
            cert.get_subject().OU = "TLS Server"
            cert.get_subject().CN = self.host
            cert.set_serial_number(1000)
            cert.gmtime_adj_notBefore(0)
            cert.gmtime_adj_notAfter(365 * 24 * 60 * 60)  # Valid for one year
            cert.set_issuer(cert.get_subject())
            cert.set_pubkey(k)
            cert.sign(k, 'sha256')

            with open("server.crt", "wb") as cert_file:
                cert_file.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
            with open("server.key", "wb") as key_file:
                key_file.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, k))

            return True
        except Exception:
            return False

    def validate_command(self, command):
        """Validate and sanitize commands"""
        forbidden = ['rm', 'mkfs', 'dd', 'format', '>', 'sudo']

        try:
            if not command or len(command) > 1000:
                return False, "Invalid command length"

            if any(cmd in command.lower() for cmd in forbidden):
                return False, "Command not allowed"

            dangerous_chars = ['&', '|', ';', '$', '`']
            if any(char in command for char in dangerous_chars):
                return False, "Invalid command characters"

            return True, command
        except Exception:
            return False, "Command validation error"

    def send_command(self, command, client_socket):
        """Send command to client and get response"""
        try:
            is_valid, validated_command = self.validate_command(command)
            if not is_valid:
                return None

            encrypted_command = self.encrypt_data(validated_command)
            client_socket.send(encrypted_command)

            response = client_socket.recv(4096)
            decrypted_response = self.decrypt_data(response)

            if decrypted_response == "DISCONNECTED":
                return "DISCONNECTED"

            return decrypted_response
        except Exception:
            return None

    def encrypt_data(self, data):
        """Encrypt data"""
        try:
            if isinstance(data, str):
                data = data.encode()
            return self.cipher_suite.encrypt(data)
        except Exception as e:
            raise e

    def decrypt_data(self, encrypted_data):
        """Decrypt data"""
        try:
            decrypted = self.cipher_suite.decrypt(encrypted_data)
            return decrypted.decode()
        except Exception as e:
            raise e

    def create_ssl_context(self):
        """Create SSL context with secure configuration"""
        try:
            context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            context.load_cert_chain(certfile="server.crt", keyfile="server.key")
            context.minimum_version = ssl.TLSVersion.TLSv1_3
            context.set_ciphers('ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384')
            context.options |= ssl.OP_NO_COMPRESSION
            context.options |= ssl.OP_CIPHER_SERVER_PREFERENCE
            return context
        except Exception as e:
            raise e