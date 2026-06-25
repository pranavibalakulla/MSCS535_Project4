"""
rogue_server.py

Simulates an attacker controlled server so the man in the middle protections
in patient_client.py can be tested directly. This script never intercepts
real network traffic and never touches hospital_server.py. It only listens
on its own local port so the patient application's validation and pinning
logic can be exercised against an untrusted endpoint, which is a safe way to
test these protections without affecting any other system.

Usage:
    python rogue_server.py untrusted

        Uses a self signed certificate that is not part of the hospital
        trust chain. This is used to demonstrate certificate validation
        rejecting an unknown issuer.

    python rogue_server.py ca_signed

        Uses a certificate that is signed by the real hospital CA but
        issued to a different identity than the real server. This is used
        to demonstrate that certificate pinning still rejects a validly
        signed but unexpected certificate.

Run patient_client.py 8444 in another terminal afterward to connect to
whichever mode this script is running in. Stop with Ctrl+C.
"""

import os
import socket
import ssl
import sys

HOST = "localhost"
PORT = 8444
CERTS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "certs")

MODES = {
    "untrusted": ("rogue_untrusted_cert.pem", "rogue_untrusted_key.pem"),
    "ca_signed": ("rogue_signed_cert.pem", "rogue_signed_key.pem"),
}


def main():
    if len(sys.argv) != 2 or sys.argv[1] not in MODES:
        print("Usage: python rogue_server.py [untrusted|ca_signed]")
        sys.exit(1)

    mode = sys.argv[1]
    cert_file, key_file = MODES[mode]

    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(
        certfile=os.path.join(CERTS, cert_file),
        keyfile=os.path.join(CERTS, key_file),
    )
    # This rogue server does not request a client certificate, since the
    # point of this test is to observe how the client reacts to the
    # server's identity, not to test mutual authentication here.

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((HOST, PORT))
        sock.listen(5)
        print(f"Rogue test server ({mode} mode) listening on https://{HOST}:{PORT}")
        print("This is a local test endpoint only.")
        print("Run patient_client.py 8444 in another terminal. Press Ctrl+C to stop.")

        while True:
            conn, addr = sock.accept()
            print(f"\nIncoming connection from {addr}")
            try:
                tls_conn = context.wrap_socket(conn, server_side=True)
                with tls_conn:
                    print("TLS handshake completed with the connecting client.")
                    try:
                        tls_conn.recv(4096)
                    except Exception:
                        pass
            except ssl.SSLError as e:
                print(f"Handshake failed: {e}")
                conn.close()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nRogue test server stopped.")
