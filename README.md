# Healthcare Patient Data Exchange System - Reference Implementation

This is a small, runnable Python implementation of the design described in
the project paper "Secure Communication System for Healthcare Patient Data
Exchange." It uses Python's built-in `ssl` module to perform a real TLS 1.3
handshake, real certificate validation, real mutual authentication, and real
encryption, so the behavior you see on screen matches the pseudocode in the
paper rather than just simulating it.

It is intended to run entirely on your own machine, on `localhost`. Nothing
here connects to the internet or to any other computer.

## What each file does

| File                      | Role in the paper                                          |
|----------------------------|-------------------------------------------------------------|
| `generate_certificates.py` | Creates a local certificate authority and all certificates  |
| `hospital_server.py`       | The hospital server (ReceivePatientData, TLS server side)   |
| `patient_client.py`        | The patient application (SendPatientData, TLS client side)  |
| `rogue_server.py`          | A safe, local stand in for an attacker, used only to test the protections below |
| `downgrade_demo.py`        | Tests the protocol downgrade protection                     |

Note on encryption: once the TLS handshake completes, Python's `ssl` module
automatically encrypts and authenticates everything sent over the socket
using AES, exactly as described in Pseudocode 3 of the paper. The code does
not call an AES function directly because TLS is already doing that work at
the record layer; this matches how real applications use TLS in practice.

## Requirements

* Python 3.9 or newer (check with `python3 --version`)
* The `cryptography` package, used only one time, to generate certificates

Install the one dependency:

```
pip install -r requirements.txt
```

If that command fails, try `pip3` instead of `pip`, or add
`--break-system-packages` at the end of the command.

## Step 1: Generate certificates

Run this once, from inside the project folder:

```
python generate_certificates.py
```

This creates a `certs` folder containing a local certificate authority, a
certificate for the hospital server, a certificate for the patient
application, and two "rogue" certificates used only for the attack tests in
Step 3. It also prints the pinned certificate hash that `patient_client.py`
will check against.

## Step 2: Run the normal, successful exchange

This is the test that demonstrates the TLS handshake and the data exchange
described in Pseudocode 1 through 3 of the paper.

Open two terminals in the project folder.

Terminal A:
```
python hospital_server.py
```

Terminal B:
```
python patient_client.py
```

Terminal B should print the negotiated TLS version, the negotiated cipher
suite, a confirmation that certificate validation and certificate pinning
both passed, and the acknowledgment sent back by the server. Terminal A
should print the connection details and the patient record it received.

This is your evidence for the general pseudocode section and the TLS
section.

Leave the server running, or stop it with Ctrl+C before moving on.

## Step 3: Test the man in the middle protections

These tests use `rogue_server.py` as a safe, local stand in for an attacker.
You do not need `hospital_server.py` running for these two tests; they use a
separate port, 8444, on your own machine.

### Test A: an untrusted certificate

Terminal A:
```
python rogue_server.py untrusted
```

Terminal B:
```
python patient_client.py 8444
```

Terminal B should refuse the connection with a certificate verification
error, since this certificate was not issued by the trusted hospital
certificate authority. This demonstrates the VerifyServerCertificate logic
in Pseudocode 4.

Stop the rogue server with Ctrl+C before the next test.

### Test B: a validly signed certificate with the wrong identity

Terminal A:
```
python rogue_server.py ca_signed
```

Terminal B:
```
python patient_client.py 8444
```

This time, certificate validation will pass, because this certificate really
was signed by the trusted hospital certificate authority. Certificate
pinning then catches the mismatch and the connection is still refused. This
demonstrates exactly why certificate pinning is included as a second layer
of protection in Pseudocode 5, on top of certificate validation alone.

failure, including the two different hash values it prints.

Stop the rogue server with Ctrl+C when finished.

## Step 4: Test protocol downgrade protection (optional)

With `hospital_server.py` still running from Step 2, run in a new terminal:

```
python downgrade_demo.py
```

Depending on how your operating system's version of OpenSSL is configured,
you will see either a local refusal to even offer TLS 1.0 or TLS 1.1, or a
handshake failure reported by the server. Either result demonstrates the
downgrade protection in Pseudocode 7.


