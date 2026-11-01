"""
Module B: DNSSEC Validator
==========================
What it does:
    Queries a domain's DNS records through Cloudflare's DNS-over-HTTPS endpoint
    with DNSSEC records requested and reports the AD (Authenticated Data) flag
    returned by the validating resolver.  Also queries an unsigned domain for
    comparison and provides human-readable explanations of DNSSEC states.

Why it is required:
    Traditional DNS responses carry no cryptographic signature.  An attacker who
    controls a router or a resolver can substitute a forged answer undetected.
    DNSSEC adds a chain of cryptographic signatures anchored at the DNS root so
    that a validating resolver can detect tampering.

INS concept:
    DNSSEC (RFC 4033/4034/4035), digital signatures in DNS, chain of trust from
    IANA root to authoritative zone, AD flag semantics.

Cryptographic technique:
    Asymmetric (public-key) signatures: zone owners sign RRsets with their private
    key (RRSIG records).  Resolvers verify signatures using public keys published
    in DNSKEY records and validate the delegation chain via DS records.

Limitations:
    - This module reports the AD flag as supplied by Cloudflare's validating
      resolver over HTTPS.  It does NOT perform independent local chain validation
      (which would require running Unbound or a similar DNSSEC-validating daemon).
    - AD=0 is NOT automatically an attack indicator: the domain may simply be
      unsigned, the resolver may not validate, or the response may be classified
      as Insecure by the resolver.
    - DoH protects the client-to-Cloudflare channel but does not make Cloudflare
      itself a trustworthy validator if Cloudflare were compromised.
"""

import base64
import dns.message
import dns.flags
import dns.rdatatype
import dns.rcode
import requests

# Cloudflare DNS-over-HTTPS endpoint (RFC 8484 wire-format)
DOH_ENDPOINT = "https://cloudflare-dns.com/dns-query"

# Well-known signed and unsigned domains for reference comparisons
SIGNED_REFERENCE = "cloudflare.com"
UNSIGNED_REFERENCE = "example.com"


def _build_doh_query(domain: str, record_type: str = "A") -> bytes:
    """Construct a DNSSEC-requesting DNS wire-format message."""
    query = dns.message.make_query(domain, record_type, want_dnssec=True)
    return query.to_wire()


def _post_doh_query(wire: bytes, timeout: int = 8) -> dns.message.Message:
    """Send a DNS wire-format query to the DoH endpoint and parse the response."""
    encoded = base64.urlsafe_b64encode(wire).rstrip(b"=").decode("ascii")
    response = requests.get(
        DOH_ENDPOINT,
        params={"dns": encoded},
        headers={"accept": "application/dns-message"},
        timeout=timeout,
    )
    response.raise_for_status()
    return dns.message.from_wire(response.content)


def _extract_answers(msg: dns.message.Message) -> list:
    """Parse the answer section into a serializable list."""
    answers = []
    for rrset in msg.answer:
        answers.append({
            "name": rrset.name.to_text(),
            "type": dns.rdatatype.to_text(rrset.rdtype),
            "records": [r.to_text() for r in rrset],
        })
    return answers


def _dnssec_state_label(ad: bool, rcode: str) -> str:
    """
    Map the AD flag and RCODE to a human-readable DNSSEC state label.

    DNSSEC resolvers classify responses as:
      Secure       — signed, valid chain of trust, AD=1
      Insecure     — domain is unsigned or in an unsigned delegation; AD=0
      Bogus        — signatures present but validation fails; resolver returns SERVFAIL
      Indeterminate — cannot determine (e.g. resolver did not validate)
    """
    if rcode == "SERVFAIL":
        return "Bogus — resolver returned SERVFAIL; signatures may be invalid"
    if ad:
        return "Secure — resolver reports a valid DNSSEC chain of trust (AD=1)"
    return "Insecure / Indeterminate — domain may be unsigned or resolver did not validate"


def validate_dnssec_doh(domain: str, record_type: str = "A") -> dict:
    """
    Query ``domain`` for ``record_type`` via Cloudflare DoH with DNSSEC requested.
    Report the AD flag, DNSSEC state and full answer section.

    IMPORTANT: The AD flag is reported as supplied by Cloudflare's resolver.
    This is NOT independent local DNSSEC chain validation.

    Parameters
    ----------
    domain      : Domain name to validate.
    record_type : DNS record type to query (default: A).

    Returns
    -------
    dict with ad_flag, dnssec_state, answers and interpretation.
    """
    name = domain.strip().rstrip(".")
    if not name:
        raise ValueError("Domain name must not be empty.")

    wire = _build_doh_query(name, record_type)
    msg = _post_doh_query(wire)

    ad = bool(msg.flags & dns.flags.AD)
    rcode = dns.rcode.to_text(msg.rcode())
    state = _dnssec_state_label(ad, rcode)
    answers = _extract_answers(msg)

    if ad:
        interpretation = (
            "AD=1: Cloudflare's validating resolver reports that this response "
            "was authenticated using DNSSEC.  The zone is signed and the "
            "resolver verified the full chain of trust from the DNS root to "
            "this answer.  Note: this is the resolver's assertion, not "
            "independent cryptographic verification performed locally."
        )
    elif rcode == "SERVFAIL":
        interpretation = (
            "SERVFAIL received.  This commonly indicates that the resolver "
            "attempted DNSSEC validation and detected an inconsistency "
            "(Bogus state).  It can also indicate a DNS infrastructure problem "
            "unrelated to DNSSEC.  Investigate the domain's DNSSEC configuration."
        )
    else:
        interpretation = (
            "AD=0: The resolver did not authenticate this response via DNSSEC.  "
            "The domain may not be signed, it may fall under an unsigned "
            "delegation, or the resolver may not have been able to validate the "
            "chain.  This is not automatically an attack indicator."
        )

    return {
        "domain": name,
        "record_type": record_type,
        "resolver": "Cloudflare DNS-over-HTTPS (cloudflare-dns.com)",
        "dns_rcode": rcode,
        "ad_flag": ad,
        "dnssec_state": state,
        "answers": answers,
        "interpretation": interpretation,
        "caveat": (
            "Result reported by Cloudflare's resolver, not by independent "
            "local cryptographic validation."
        ),
    }


def explain_dnssec_concepts() -> dict:
    """
    Return a structured explanation of core DNSSEC concepts for display in the UI.
    """
    return {
        "DNSKEY": (
            "Public key record published by a zone.  Used to verify RRSIG "
            "signatures on other records in the zone."
        ),
        "RRSIG": (
            "Cryptographic signature over a resource record set (RRset).  "
            "Created by the zone operator's private key and verified against DNSKEY."
        ),
        "DS (Delegation Signer)": (
            "A hash of a child zone's DNSKEY, published in the parent zone.  "
            "Creates the delegation link in the chain of trust."
        ),
        "Chain of trust": (
            "Starts at the IANA root key (trust anchor), then DS records in "
            "each parent zone verify the DNSKEY of the child zone, down to the "
            "queried domain."
        ),
        "AD flag": (
            "Set by a validating resolver to indicate that the data in the "
            "answer section has been verified using DNSSEC.  Defined in RFC 4035."
        ),
        "Secure": "All signatures valid; complete chain of trust to the root.",
        "Insecure": (
            "Domain is not signed or falls under an unsigned delegation.  "
            "Not necessarily an attack."
        ),
        "Bogus": (
            "Signatures present but validation fails.  Resolver returns SERVFAIL.  "
            "Warrants investigation."
        ),
        "Indeterminate": (
            "Resolver could not determine validation status — e.g. it does not "
            "support DNSSEC validation."
        ),
    }
