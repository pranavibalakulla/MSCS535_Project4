"""
patient_client.py

The patient application side of the Healthcare Patient Data Exchange System.
This script performs the protections described in the project paper:

  * Validates the hospital server certificate against the trusted hospital
    certificate authority and checks the hostname (certificate validation).
  * Compares the server certificate against a pinned value stored locally
    (certificate pinning).
  * Presents its own client certificate so the hospital server can verify
    the identity of the application (mutual authentication).
  * Refuses to negotiate below TLS 1.2 (protocol downgrade protection).
  * Sends one sample patient record once the secure channel is established,
    matching SendPatientData in the paper.

Run with:
    python patient_client.py

This script can also be pointed at a different port, which is used to test
the man in the middle protections against rogue_server.py:

    python patient_client.py 8444
"""

import hashlib
import json
import os
import socket
import ssl
import sys

HOST = "localhost"
DEFAULT_PORT = 8443
CERTS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "certs")

SAMPLE_PATIENT_RECORD = {
    "patientId": "PT-204891",
    "name": "Jordan Avery",
    "dateOfBirth": "1987-05-14",
    "diagnosis": "Type 2 diabetes, routine follow up",
    "visitDate": "2026-06-24",
}


def load_pinned_hash():
    with open(os.path.join(CERTS, "pinned_server_key.txt")) as f:
        return f.read().strip()


def hash_of_peer_certificate(tls_socket):
    der_cert = tls_socket.getpeercert(binary_form=True)
    return hashlib.sha256(der_cert).hexdigest()


def build_client_context():
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations(cafile=os.path.join(CERTS, "ca_cert.pem"))
    context.load_cert_chain(
        certfile=os.path.join(CERTS, "client_cert.pem"),
        keyfile=os.path.join(CERTS, "client_key.pem"),
    )
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    return context


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_PORT
    context = build_client_context()
    pinned_hash = load_pinned_hash()

    print(f"Connecting to {HOST}:{port} ...")
    try:
        sock = socket.create_connection((HOST, port), timeout=5)
    except OSError as e:
        print(f"Could not reach {HOST}:{port}. Is the server running? ({e})")
        return

    with sock:
        try:
            tls_sock = context.wrap_socket(sock, server_hostname=HOST)
        except ssl.SSLError as e:
            print(f"Certificate validation failed. Connection refused: {e}")
            return

        with tls_sock:
            print("Certificate validation passed. The server identity was confirmed.")
            print(f"Negotiated protocol: {tls_sock.version()}")
            print(f"Negotiated cipher suite: {tls_sock.cipher()[0]}")

            actual_hash = hash_of_peer_certificate(tls_sock)
            if actual_hash != pinned_hash:
                print("Certificate pinning check failed.")
                print(f"  Expected hash: {pinned_hash}")
                print(f"  Received hash: {actual_hash}")
                print("The certificate presented does not match the pinned value.")
                print("Possible man in the middle attack detected. Closing connection.")
                return
            print("Certificate pinning check passed. The server matches the pinned identity.")

            print("Sending patient record...")
            tls_sock.send(json.dumps(SAMPLE_PATIENT_RECORD).encode("utf-8"))

            response = tls_sock.recv(4096)
            acknowledgment = json.loads(response.decode("utf-8"))
            print("Received acknowledgment from hospital server:")
            print(json.dumps(acknowledgment, indent=2))


if __name__ == "__main__":
    main()
