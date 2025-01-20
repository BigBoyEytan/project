import socket
import ssl
from OpenSSL import crypto

HOST = '172.20.132.160'
PORT = 5555
CERTFILE = 'server.crt'
KEYFILE = 'server.key'
FORMAT = 'UTF-8'
DISCONNECT_MESSAGE = "!DISCONNECT"

# Create SSL context
context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
context.load_cert_chain(certfile=CERTFILE, keyfile=KEYFILE)


def generate_self_signed_cert():
    """
    Generate self-signed certificate and key if they don't exist.
    In production, use properly signed certificates.
    """
    from datetime import datetime, timedelta

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
    cert.get_subject().CN = HOST
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


def send_command(msg, conn):
    try:
        message = msg
        conn.send(message.encode(FORMAT))
        msg = conn.recv(1024).decode(FORMAT)
        if msg == DISCONNECT_MESSAGE:
            return "DISCONNECTED"
        else:
            return msg
    except Exception as e:
        print(f"Error sending command: {e}")
        return None
