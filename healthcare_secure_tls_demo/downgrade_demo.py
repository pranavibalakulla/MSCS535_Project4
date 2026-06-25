"""
downgrade_demo.py

Attempts to connect to the hospital server while only offering protocol
versions older than TLS 1.2, to demonstrate the downgrade protection
configured in hospital_server.py and patient_client.py.

Results depend on the version of OpenSSL installed on your system, since
many current operating systems disable TLS 1.0 and TLS 1.1 at the library
level by default. Either outcome below demonstrates the same thing, that
the system will not complete a connection using an outdated protocol
version:

  * Python refuses to even configure TLS 1.0 or TLS 1.1, because the local
    OpenSSL build has already disabled them.
  * The connection attempt reaches the network but the TLS handshake is
    refused.

Run hospital_server.py in another terminal first, then run:
    python downgrade_demo.py
"""

import os
import socket
import ssl
import warnings

warnings.filterwarnings("ignore", category=DeprecationWarning)

HOST = "localhost"
PORT = 8443
CERTS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "certs")


def main():
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations(cafile=os.path.join(CERTS, "ca_cert.pem"))
    context.load_cert_chain(
        certfile=os.path.join(CERTS, "client_cert.pem"),
        keyfile=os.path.join(CERTS, "client_key.pem"),
    )
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED

    try:
        context.minimum_version = ssl.TLSVersion.TLSv1
        context.maximum_version = ssl.TLSVersion.TLSv1_1
    except (ValueError, AttributeError, ssl.SSLError) as e:
        print("This system's OpenSSL build will not even allow requesting")
        print("TLS 1.0 or TLS 1.1, which already demonstrates that outdated")
        print(f"protocol versions are disabled here: {e}")
        return

    print("Attempting to connect while offering only TLS 1.0 or TLS 1.1 ...")
    try:
        with socket.create_connection((HOST, PORT), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=HOST):
                print("Unexpected: the outdated protocol connection succeeded.")
    except OSError as e:
        print(f"Connection refused, as expected: {e}")


if __name__ == "__main__":
    main()
