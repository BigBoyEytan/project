import socket
import ssl
import threading
import os

# TLS Configuration
HOST = '172.20.132.160'
PORT = 5555
CERTFILE = 'server.crt'
KEYFILE = 'server.key'

FORMAT = 'UTF-8'
DISCONNECT_MESSAGE = "!DISCONNECT"

# Create a socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind((HOST, PORT))

# Create SSL context
context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
context.load_cert_chain(certfile=CERTFILE, keyfile=KEYFILE)


def generate_self_signed_cert():
    """
    Generate self-signed certificate and key if they don't exist.
    In production, use properly signed certificates.
    """
    from OpenSSL import crypto
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


def handle_client(conn, addr):
    print(f"[NEW CONNECTION] {addr} connected.")
    connected = True
    while connected:
        try:
            comand_to_client = input("enter command to run on client: ")
            if comand_to_client == "connect":
                # Implement connect logic
                pass
            elif comand_to_client == "get updates":
                # Implement get updates logic
                pass
            elif comand_to_client == "update apps":
                # Implement update apps logic
                pass
            elif comand_to_client == "check files":
                # Implement check files logic
                pass
            else:
                print("No such command, TRY AGAIN!")
        except Exception as e:
            print(f"Error handling client: {e}")
            connected = False


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


def start():
    # Generate self-signed cert if not exists
    try:
        generate_self_signed_cert()
    except ImportError:
        print("OpenSSL is required to generate self-signed certificates. Please install it.")
        return

    # Listen for connections
    s.listen(5)
    print(f"[LISTENING] Server is listening on {HOST}:{PORT}")

    while True:
        try:
            # Accept a plain socket connection
            client_socket, addr = s.accept()
            print(f"Connection from {addr}")

            # Wrap the socket with SSL
            secure_socket = context.wrap_socket(client_socket, server_side=True)

            # Start a thread to handle the client
            thread = threading.Thread(target=handle_client, args=(secure_socket, addr))
            thread.start()
        except Exception as e:
            print(f"Error accepting connection: {e}")


if __name__ == "__main__":
    start()