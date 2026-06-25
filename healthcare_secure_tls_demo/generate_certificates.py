"""
generate_certificates.py

Creates a small local certificate authority and the certificates needed to
run the Healthcare Patient Data Exchange System demo.

This script writes the following files into the certs folder:

    ca_cert.pem               Trusted root certificate (the "Hospital CA")
    ca_key.pem                Private key for the CA (kept only for this demo)
    server_cert.pem           Certificate for the hospital server
    server_key.pem            Private key for the hospital server
    client_cert.pem           Certificate for the patient application
    client_key.pem            Private key for the patient application
    rogue_untrusted_cert.pem  A self signed certificate with no trusted chain
    rogue_untrusted_key.pem   Private key for the untrusted rogue certificate
    rogue_signed_cert.pem     A certificate signed by the real CA but issued
                              to a different identity, simulating an attacker
                              who somehow obtained a validly signed certificate
    rogue_signed_key.pem      Private key for that certificate
    pinned_server_key.txt     SHA256 hash of the real server certificate,
                              used by the client for certificate pinning

Run with:
    python generate_certificates.py
"""

import datetime
import hashlib
import os

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

OUT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "certs")
os.makedirs(OUT_DIR, exist_ok=True)


def new_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def save_key(key, filename):
    path = os.path.join(OUT_DIR, filename)
    with open(path, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))


def save_cert(cert, filename):
    path = os.path.join(OUT_DIR, filename)
    with open(path, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))


def build_name(common_name):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])


def self_signed_ca(common_name="Hospital Network Root CA"):
    key = new_key()
    name = build_name(common_name)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )
    return key, cert


def issue_cert(common_name, ca_key, ca_cert, san_dns=None, self_signed=False):
    key = new_key()
    subject = build_name(common_name)
    issuer = subject if self_signed else ca_cert.subject
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc) - datetime.timedelta(days=1))
        .not_valid_after(datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=825))
    )
    if san_dns:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(san_dns)]),
            critical=False,
        )
    signing_key = key if self_signed else ca_key
    cert = builder.sign(signing_key, hashes.SHA256())
    return key, cert


def pinned_hash_of(cert):
    der_bytes = cert.public_bytes(serialization.Encoding.DER)
    return hashlib.sha256(der_bytes).hexdigest()


def main():
    print("Creating the trusted hospital certificate authority...")
    ca_key, ca_cert = self_signed_ca()
    save_key(ca_key, "ca_key.pem")
    save_cert(ca_cert, "ca_cert.pem")

    print("Issuing the hospital server certificate...")
    server_key, server_cert = issue_cert("localhost", ca_key, ca_cert, san_dns="localhost")
    save_key(server_key, "server_key.pem")
    save_cert(server_cert, "server_cert.pem")

    print("Issuing the patient application client certificate...")
    client_key, client_cert = issue_cert("patient-application-01", ca_key, ca_cert)
    save_key(client_key, "client_key.pem")
    save_cert(client_cert, "client_cert.pem")

    print("Creating an untrusted self signed certificate to simulate an impostor server...")
    rogue_key, rogue_cert = issue_cert(
        "attacker-server", None, None, san_dns="localhost", self_signed=True
    )
    save_key(rogue_key, "rogue_untrusted_key.pem")
    save_cert(rogue_cert, "rogue_untrusted_cert.pem")

    print("Creating a certificate signed by the real CA but issued to a different identity...")
    rogue_signed_key, rogue_signed_cert = issue_cert(
        "attacker-server", ca_key, ca_cert, san_dns="localhost"
    )
    save_key(rogue_signed_key, "rogue_signed_key.pem")
    save_cert(rogue_signed_cert, "rogue_signed_cert.pem")

    pin = pinned_hash_of(server_cert)
    with open(os.path.join(OUT_DIR, "pinned_server_key.txt"), "w") as f:
        f.write(pin + "\n")

    print("\nDone. Certificates were written to the certs folder.")
    print(f"Pinned hash for the real hospital server certificate: {pin}")


if __name__ == "__main__":
    main()
