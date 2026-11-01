"""
Module D: TLS Certificate Analyzer
====================================
What it does:
    Establishes a TLS connection to a specified host and port, retrieves the
    server's certificate, validates the certificate chain and hostname, and
    returns structured details including TLS version, cipher suite, certificate
    subject/issuer, validity period and Subject Alternative Names.

Why it is required:
    In a DNS hijacking scenario, if an attacker redirects a domain to their own
    server, TLS certificate validation is the last line of defence.  A valid
    certificate for the correct hostname can only be obtained from a trusted
    Certificate Authority.  Python's default SSL context verifies the certificate
    chain against the system's CA trust store and checks that the hostname matches
    the certificate — exactly the verification step a user's browser performs.

INS concept:
    TLS handshake (RFC 8446), X.509 certificates, certificate chain of trust,
    hostname verification, cipher suites, authenticated encryption.

Cryptographic technique:
    Asymmetric key exchange (ECDHE/RSA) for session key establishment,
    symmetric authenticated encryption (AES-GCM / ChaCha20-Poly1305) for data,
    digital signatures on certificates (RSA/ECDSA) verified against CA public keys.

Limitations:
    - Validation uses the machine's configured CA trust store; a compromised or
      custom trust store can make forged certificates appear valid.
    - A valid certificate proves the server holds a private key for the domain at
      the moment of connection; it does not prove the website is benign.
    - Certificate transparency logs and OCSP/CRL revocation checking are beyond
      the scope of this module.
    - Hostname mismatch test endpoints depend on external services (badssl.com)
      which may be unavailable.
"""

import socket
import ssl
from datetime import datetime, timezone, timedelta
from typing import Optional


# Well-known TLS test endpoints for demonstration purposes
TEST_ENDPOINTS = {
    "valid_https": ("example.com", 443),
    "expired_cert": ("expired.badssl.com", 443),
    "hostname_mismatch": ("wrong.host.badssl.com", 443),
    "self_signed": ("self-signed.badssl.com", 443),
    "revoked": ("revoked.badssl.com", 443),
}

# TLS version security classification
TLS_VERSION_STATUS = {
    "SSLv2": "INSECURE — deprecated, must not be used",
    "SSLv3": "INSECURE — deprecated, vulnerable to POODLE",
    "TLSv1": "WEAK — deprecated in RFC 8996",
    "TLSv1.1": "WEAK — deprecated in RFC 8996",
    "TLSv1.2": "ACCEPTABLE — widely deployed, considered secure with strong cipher suites",
    "TLSv1.3": "STRONG — current standard; improved handshake and forward secrecy by default",
}


def _parse_cert_name(name_tuples) -> dict:
    """
    Convert the nested tuple structure returned by getpeercert() into a flat dict.

    Python's ssl module returns certificate name fields as a tuple of tuples of
    two-tuples, e.g. ((('commonName', 'example.com'),),).
    """
    if not name_tuples:
        return {}
    result = {}
    for rdn in name_tuples:
        for key, value in rdn:
            result[key] = value
    return result


def _parse_san(san_tuples) -> list:
    """Parse Subject Alternative Name entries into a list of strings."""
    if not san_tuples:
        return []
    return [f"{t}: {v}" for t, v in san_tuples]


def _days_until_expiry(not_after_str: Optional[str]) -> Optional[int]:
    """Return the number of days until certificate expiry, or None if unparsable."""
    if not not_after_str:
        return None
    try:
        expiry = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
        expiry = expiry.replace(tzinfo=timezone.utc)
        now = datetime.now(timezone.utc)
        return (expiry - now).days
    except ValueError:
        return None


def _classify_expiry(days: Optional[int]) -> str:
    """Return a human-readable expiry status."""
    if days is None:
        return "Unknown"
    if days < 0:
        return f"EXPIRED {abs(days)} day(s) ago"
    if days <= 7:
        return f"CRITICAL — expires in {days} day(s)"
    if days <= 30:
        return f"WARNING — expires in {days} day(s)"
    return f"OK — expires in {days} day(s)"


def inspect_tls(hostname: str, port: int = 443,
                custom_ca_bundle: Optional[str] = None) -> dict:
    """
    Connect to ``hostname:port`` over TLS using Python's default certificate
    verification.  Certificate verification is NEVER disabled.

    Parameters
    ----------
    hostname        : Server hostname (used for both connection and SNI/hostname check).
    port            : TCP port to connect to (default: 443).
    custom_ca_bundle: Optional path to a PEM CA bundle (uses system store if None).

    Returns
    -------
    dict with fields: verified, tls_version, tls_version_status, cipher,
                      certificate (subject, issuer, SANs, validity), error.
    """
    hostname = hostname.strip()
    if not hostname:
        raise ValueError("Hostname must not be empty.")
    if not (1 <= port <= 65535):
        raise ValueError(f"Port {port} is outside the valid range 1–65535.")

    # Build a default SSL context — this enables certificate and hostname verification
    context = ssl.create_default_context()
    if custom_ca_bundle:
        context.load_verify_locations(cafile=custom_ca_bundle)

    result = {
        "hostname": hostname,
        "port": port,
        "verified": False,
        "tls_version": None,
        "tls_version_status": None,
        "cipher": None,
        "certificate": None,
        "days_until_expiry": None,
        "expiry_status": None,
        "error": None,
        "error_type": None,
    }

    try:
        with socket.create_connection((hostname, port), timeout=8) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as tls:
                cert = tls.getpeercert()
                cipher_info = tls.cipher()
                version = tls.version()

                not_after = cert.get("notAfter")
                days = _days_until_expiry(not_after)

                result["verified"] = True
                result["tls_version"] = version
                result["tls_version_status"] = TLS_VERSION_STATUS.get(
                    version, f"Unknown version: {version}"
                )
                result["cipher"] = {
                    "name": cipher_info[0] if cipher_info else None,
                    "protocol": cipher_info[1] if cipher_info else None,
                    "bits": cipher_info[2] if cipher_info else None,
                }
                result["certificate"] = {
                    "subject": _parse_cert_name(cert.get("subject")),
                    "issuer": _parse_cert_name(cert.get("issuer")),
                    "serial_number": cert.get("serialNumber"),
                    "not_before": cert.get("notBefore"),
                    "not_after": not_after,
                    "subject_alt_names": _parse_san(cert.get("subjectAltName")),
                    "version": cert.get("version"),
                    "ocsp_urls": cert.get("OCSP", []),
                    "ca_issuers": cert.get("caIssuers", []),
                }
                result["days_until_expiry"] = days
                result["expiry_status"] = _classify_expiry(days)

    except ssl.SSLCertVerificationError as exc:
        result["error"] = str(exc)
        result["error_type"] = "CertificateVerificationError"
        result["error_explanation"] = (
            "The TLS library could not verify the server's certificate.  "
            "Common causes: expired certificate, certificate issued by an "
            "untrusted CA, or hostname does not match the certificate."
        )
    except ssl.SSLError as exc:
        result["error"] = str(exc)
        result["error_type"] = "SSLError"
        result["error_explanation"] = (
            "A TLS/SSL protocol error occurred during the handshake."
        )
    except socket.timeout:
        result["error"] = f"Connection to {hostname}:{port} timed out after 8 seconds."
        result["error_type"] = "Timeout"
    except OSError as exc:
        result["error"] = str(exc)
        result["error_type"] = "NetworkError"
        result["error_explanation"] = (
            "Could not establish a network connection to the host.  "
            "Check the hostname and port."
        )

    return result


def get_tls_explanation() -> dict:
    """
    Return structured explanations of TLS/certificate concepts for UI display.
    """
    return {
        "What is TLS?": (
            "Transport Layer Security (RFC 8446) is a cryptographic protocol that "
            "provides confidentiality, integrity and authentication for network "
            "connections.  It is the 'S' in HTTPS."
        ),
        "TLS handshake": (
            "The client and server negotiate a cipher suite, exchange public keys "
            "or key-agreement parameters (e.g. ECDHE), authenticate the server via "
            "its certificate, and derive shared session keys — all before any "
            "application data is transmitted."
        ),
        "X.509 certificate": (
            "A digital document that binds a public key to an identity (domain name). "
            "Signed by a Certificate Authority (CA).  Browsers and OS trust stores "
            "contain a list of trusted CAs."
        ),
        "Certificate chain validation": (
            "The server's certificate is signed by an intermediate CA, which is "
            "signed by a root CA.  The client validates the full chain up to a "
            "trusted root in its trust store."
        ),
        "Hostname verification": (
            "Python's ssl module checks that the hostname you connected to matches "
            "the Common Name or Subject Alternative Names in the certificate.  A "
            "mismatch indicates you may be talking to the wrong server."
        ),
        "Relevance to DNS hijacking": (
            "If an attacker redirects a domain via DNS to their server, TLS "
            "certificate validation will fail — the attacker cannot obtain a "
            "legitimate certificate for the victim's domain from a trusted CA "
            "(assuming no CA compromise).  This mismatch warning must never be "
            "bypassed by users."
        ),
    }
