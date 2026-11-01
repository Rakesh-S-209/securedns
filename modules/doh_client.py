"""
Module C: DNS over HTTPS (DoH) Client
======================================
What it does:
    Performs DNS queries through Cloudflare's and Google's DNS-over-HTTPS (DoH)
    endpoints using the RFC 8484 wire-format method.  Returns structured records
    and explains the difference between traditional DNS (UDP/53) and DoH.

Why it is required:
    Traditional DNS traffic is sent as plaintext over UDP port 53 and is visible
    to any network observer — ISP, router, or on-path attacker.  An attacker who
    controls a router can see every domain a client resolves and can modify DNS
    responses.  DoH wraps the DNS query in an HTTPS request, encrypting it from
    the client to the resolver and making it indistinguishable from ordinary HTTPS
    traffic.  This prevents passive eavesdropping and on-path modification of the
    DNS query and response.

INS concept:
    DNS-over-HTTPS (RFC 8484), encryption of DNS transport, comparison of
    traditional DNS vs. encrypted DNS channels, HTTPS/TLS as a transport-layer
    protection mechanism.

Cryptographic technique:
    TLS 1.2/1.3 — the HTTPS session protecting the DoH request encrypts the DNS
    query and response using symmetric authenticated encryption (e.g. AES-GCM),
    with keys established via an asymmetric key exchange (ECDHE).

Limitations:
    - DoH encrypts the client-to-resolver channel only.  It does not protect the
      communication between the DoH resolver and authoritative nameservers.
    - DoH does not authenticate DNS responses cryptographically.  A compromised
      DoH resolver can still return forged answers.  DNSSEC is required for
      end-to-end data authenticity (Module B).
    - Using a third-party DoH resolver transfers DNS query privacy from the ISP
      to that resolver provider.
    - Wireshark visibility demonstration: traditional DNS queries over UDP/53
      appear in plaintext in a Wireshark capture; DoH traffic appears as TLS
      application data with no visible query content.
"""

import base64
import time
import dns.message
import dns.rdatatype
import dns.rcode
import dns.flags
import requests

# Supported DoH endpoint configurations
DOH_PROVIDERS = {
    "Cloudflare": {
        "url": "https://cloudflare-dns.com/dns-query",
        "description": "Cloudflare 1.1.1.1 DNS-over-HTTPS endpoint",
    },
    "Google": {
        "url": "https://dns.google/dns-query",
        "description": "Google 8.8.8.8 DNS-over-HTTPS endpoint",
    },
}

DEFAULT_PROVIDER = "Cloudflare"
REQUEST_TIMEOUT = 8  # seconds


def _encode_dns_query(domain: str, record_type: str, dnssec: bool = False) -> bytes:
    """
    Build a DNS query in wire format.

    Parameters
    ----------
    domain      : Domain name to query.
    record_type : DNS record type string (e.g. 'A').
    dnssec      : If True, set the DO bit requesting DNSSEC records.
    """
    query = dns.message.make_query(domain, record_type, want_dnssec=dnssec)
    return query.to_wire()


def _send_doh_request(wire: bytes, provider: str = DEFAULT_PROVIDER) -> tuple[requests.Response, float]:
    """
    Send a DNS wire-format query to the specified DoH provider.

    Returns (requests.Response, elapsed_ms)
    """
    if provider not in DOH_PROVIDERS:
        raise ValueError(
            f"Unknown DoH provider '{provider}'. "
            f"Supported: {', '.join(DOH_PROVIDERS.keys())}"
        )

    url = DOH_PROVIDERS[provider]["url"]
    encoded = base64.urlsafe_b64encode(wire).rstrip(b"=").decode("ascii")

    start = time.perf_counter()
    response = requests.get(
        url,
        params={"dns": encoded},
        headers={"accept": "application/dns-message"},
        timeout=REQUEST_TIMEOUT,
    )
    elapsed = (time.perf_counter() - start) * 1000
    response.raise_for_status()
    return response, elapsed


def doh_query(domain: str, record_type: str = "A",
              provider: str = DEFAULT_PROVIDER) -> dict:
    """
    Perform a DNS lookup for ``domain`` using DNS-over-HTTPS.

    This query travels over an encrypted HTTPS connection to the DoH resolver,
    preventing passive observers from reading or modifying the DNS query.

    Parameters
    ----------
    domain      : Domain name to resolve.
    record_type : DNS record type to query (default: A).
    provider    : DoH provider key from DOH_PROVIDERS (default: Cloudflare).

    Returns
    -------
    dict with answers, timing, RCODE and DoH-specific metadata.
    """
    domain = domain.strip().rstrip(".")
    if not domain:
        raise ValueError("Domain name must not be empty.")

    record_type = record_type.upper()

    wire = _encode_dns_query(domain, record_type)
    response, elapsed_ms = _send_doh_request(wire, provider)

    msg = dns.message.from_wire(response.content)
    rcode = dns.rcode.to_text(msg.rcode())

    answers = []
    for rrset in msg.answer:
        answers.append({
            "name": rrset.name.to_text(),
            "type": dns.rdatatype.to_text(rrset.rdtype),
            "records": [r.to_text() for r in rrset],
        })

    return {
        "domain": domain,
        "record_type": record_type,
        "provider": provider,
        "provider_url": DOH_PROVIDERS[provider]["url"],
        "transport": "DNS-over-HTTPS (RFC 8484) via TLS",
        "dns_rcode": rcode,
        "http_status": response.status_code,
        "elapsed_ms": round(elapsed_ms, 2),
        "answers": answers,
        "encryption": (
            "Query and response are encrypted inside an HTTPS/TLS session. "
            "A Wireshark capture on port 443 will show TLS application data — "
            "the DNS query content is not visible to network observers."
        ),
    }


def compare_doh_vs_traditional(domain: str, record_type: str = "A",
                                traditional_resolver: str = "8.8.8.8") -> dict:
    """
    Compare a DoH query result with a traditional DNS query for the same domain.

    This helps illustrate the transport difference:
    - Traditional DNS: plaintext UDP/53 (visible in Wireshark)
    - DoH: encrypted HTTPS/443 (content not visible in Wireshark)

    Parameters
    ----------
    domain               : Domain name to query.
    record_type          : Record type (default: A).
    traditional_resolver : IP of the traditional UDP resolver (default: 8.8.8.8).

    Returns
    -------
    dict with both results and transport comparison notes.
    """
    import dns.resolver
    import dns.exception

    domain = domain.strip().rstrip(".")
    if not domain:
        raise ValueError("Domain name must not be empty.")

    # --- DoH query ---
    doh_result = doh_query(domain, record_type, DEFAULT_PROVIDER)

    # --- Traditional DNS query ---
    r = dns.resolver.Resolver(configure=False)
    r.nameservers = [traditional_resolver]
    r.timeout = 4
    r.lifetime = 8

    trad_start = time.perf_counter()
    try:
        answer = r.resolve(domain, record_type, raise_on_no_answer=False)
        trad_elapsed = (time.perf_counter() - trad_start) * 1000
        trad_answers = [x.to_text() for x in answer] if answer.rrset else []
        trad_error = None
    except Exception as exc:
        trad_elapsed = (time.perf_counter() - trad_start) * 1000
        trad_answers = []
        trad_error = str(exc)

    return {
        "domain": domain,
        "record_type": record_type,
        "doh": {
            "provider": DEFAULT_PROVIDER,
            "transport": "HTTPS/TLS (port 443) — encrypted",
            "answers": doh_result["answers"],
            "elapsed_ms": doh_result["elapsed_ms"],
            "wireshark_visibility": (
                "DNS content NOT visible — traffic appears as TLS Application Data"
            ),
        },
        "traditional_dns": {
            "resolver": traditional_resolver,
            "transport": "UDP/53 — unencrypted plaintext",
            "answers": trad_answers,
            "elapsed_ms": round(trad_elapsed, 2),
            "error": trad_error,
            "wireshark_visibility": (
                "DNS content IS visible — query domain and response IPs "
                "appear in plaintext in a Wireshark capture on UDP port 53"
            ),
        },
        "transport_comparison": {
            "channel_confidentiality": {
                "DoH": "Encrypted by TLS — ISP and on-path observers cannot read queries",
                "Traditional DNS": "Plaintext — ISP, router and on-path observers can read queries",
            },
            "data_authenticity": {
                "DoH": "No — DoH does not cryptographically sign DNS records",
                "Traditional DNS": "No — unsigned unless DNSSEC is deployed on the domain",
                "Note": "DNSSEC is required for record-level authentication regardless of transport",
            },
            "resolver_trust": {
                "DoH": "You trust the DoH provider (e.g. Cloudflare) not to return forged answers",
                "Traditional DNS": "You trust the configured resolver (ISP or custom) not to lie",
            },
        },
    }


def get_doh_explanation() -> dict:
    """
    Return structured explanations of DoH concepts for UI display.
    """
    return {
        "What is DoH?": (
            "DNS-over-HTTPS (RFC 8484) sends DNS queries as HTTPS GET requests "
            "to a compatible resolver.  The query and response travel inside a "
            "TLS-encrypted HTTPS connection, making them indistinguishable from "
            "regular web traffic."
        ),
        "How does traditional DNS work?": (
            "Standard DNS uses UDP (or TCP) on port 53.  Queries and responses "
            "are transmitted as plaintext.  Any device on the network path — "
            "ISP, router, or attacker — can read and modify them."
        ),
        "What threat does DoH address?": (
            "DoH prevents passive eavesdropping on DNS queries (query privacy) "
            "and on-path modification of DNS messages in transit "
            "(transport-level integrity)."
        ),
        "What DoH does NOT address": (
            "DoH does not authenticate the content of DNS records.  A compromised "
            "or malicious DoH resolver can still return forged IP addresses.  "
            "DNSSEC is required to cryptographically authenticate record content."
        ),
        "Wireshark evidence": (
            "In a packet capture on UDP/53, DNS queries are fully visible: you can "
            "read the queried domain, record type and all returned IP addresses.  "
            "In a capture on TCP/443, DoH traffic appears as TLS Application Data — "
            "the DNS content is encrypted and not readable."
        ),
    }
