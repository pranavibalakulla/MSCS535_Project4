"""
hospital_server.py

A minimal TLS server that represents the hospital side of the Healthcare
Patient Data Exchange System described in the project paper. It:

  * Presents a certificate signed by the trusted hospital certificate
    authority (TLS handshake and server authentication).
  * Requires the connecting client to present its own certificate, which
    is verified against the same trusted authority (mutual authentication).
  * Refuses any connection that negotiates below TLS 1.2 (protection
    against protocol downgrade attacks).
  * Receives one JSON patient record per connection, prints it, and sends
    back an acknowledgment, matching ReceivePatientData in the paper.

Run with:
    python hospital_server.py

Stop with Ctrl+C.
"""

import json
import os
import socket
import ssl

HOST = "localhost"
PORT = 8443
CERTS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "certs")


def build_server_context():
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(
        certfile=os.path.join(CERTS, "server_cert.pem"),
        keyfile=os.path.join(CERTS, "server_key.pem"),
    )
    context.load_verify_locations(cafile=os.path.join(CERTS, "ca_cert.pem"))
    context.verify_mode = ssl.CERT_REQUIRED            # mutual authentication
    context.minimum_version = ssl.TLSVersion.TLSv1_2   # downgrade protection
    return context


def handle_connection(tls_socket, address):
    print(f"\nIncoming connection from {address}")
    print(f"Negotiated protocol: {tls_socket.version()}")
    print(f"Negotiated cipher suite: {tls_socket.cipher()[0]}")

    client_cert = tls_socket.getpeercert()
    subject = dict(x[0] for x in client_cert["subject"])
    print(f"Client certificate verified for identity: {subject.get('commonName')}")

    raw = tls_socket.recv(4096)
    patient_record = json.loads(raw.decode("utf-8"))
    print("Received patient record:")
    print(json.dumps(patient_record, indent=2))

    acknowledgment = {"status": "received", "patientId": patient_record.get("patientId")}
    tls_socket.send(json.dumps(acknowledgment).encode("utf-8"))
    print("Acknowledgment sent. Connection closed.")


def main():
    context = build_server_context()
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((HOST, PORT))
        sock.listen(5)
        print(f"Hospital server listening on https://{HOST}:{PORT}")
        print("Waiting for the patient application to connect. Press Ctrl+C to stop.")

        while True:
            conn, addr = sock.accept()
            try:
                tls_conn = context.wrap_socket(conn, server_side=True)
            except ssl.SSLError as e:
                print(f"\nRejected an incoming connection from {addr}: {e}")
                conn.close()
                continue
            with tls_conn:
                try:
                    handle_connection(tls_conn, addr)
                except Exception as e:
                    print(f"Error while handling connection: {e}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nServer stopped.")
