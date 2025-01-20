
import socket
import ssl
import threading
import os


from secure_functions import generate_self_signed_cert, send_command

#apps
from apps.list_installed_apps import get_installed_apps, display_installed_apps
from apps.check_for_updates import get_updatable_apps, display_updatable_apps
from apps.upgrade_apps import upgrade_apps

# scan file
from scan_file.check_file_info import FileInformationEngine
from scan_file.check_Suspicious_Content import SuspiciousContentEngine
from scan_file.check_virustotal import VirusTotalEngine

HOST = '172.20.132.160'
PORT = 5555
FORMAT = 'UTF-8'
DISCONNECT_MESSAGE = "!DISCONNECT"

# Create a socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind((HOST, PORT))


def handle_client(conn, addr):
    print(f"[NEW CONNECTION] {addr} connected.")
    connected = True
    while connected:
        try:
            command_from_client = conn.recv(1024).decode(FORMAT)

            if command_from_client == "get updatable apps":
                print("Fetching updatable apps...")
                pass

            elif command_from_client == "get installed apps":
                print("Fetching installed apps...")
                pass

            elif command_from_client == "update apps":
                print("Requesting apps to update...")
                pass

            elif command_from_client == "check files":
                print("Checking files for potential threats...")
                pass

            else:
                conn.send("Invalid command. Please try again.".encode(FORMAT))

        except Exception as e:
            print(f"Error handling client: {e}")
            connected = False


def start():
    # Generate self-signed cert if not exists
    try:
        generate_self_signed_cert()
    except Exception as e:
        print(f"Error generating self-signed certificate: {e}")
        return

    # Create SSL context
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile="server.crt", keyfile="server.key")  # Load your certificate and key

    s.listen()
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
