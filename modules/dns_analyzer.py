"""
Module A: DNS Analyzer
======================
What it does:
    Performs DNS record lookups (A, AAAA, MX, NS, TXT, CNAME), displays returned
    records and TTL, measures response time, compares answers from two independent
    resolvers, and flags differences for investigation.

Why it is required:
    DNS hijacking attacks redirect users by substituting legitimate DNS answers with
    attacker-controlled ones.  Comparing answers from independent resolvers can surface
    inconsistencies that warrant further investigation.

INS concept:
    DNS protocol, UDP port 53, DNS record types, resolver infrastructure, cache
    poisoning and DNS spoofing as a precursor to AiTM (Adversary-in-the-Middle) attacks.

Cryptographic technique:
    None at this layer — traditional DNS provides no cryptographic authenticity.
    This module demonstrates exactly why DNSSEC (Module B) is necessary.

Limitations:
    - Resolver answer differences are investigation indicators only.
    - CDNs, geographic routing, per-resolver caching and legitimate configuration
      changes can produce different answers without any attack being present.
    - This module cannot determine whether a router or ISP resolver has been
      compromised; it can only surface observable differences.
"""

import time
import dns.resolver
import dns.exception

# Default resolver used for single lookups
DEFAULT_RESOLVER = "1.1.1.1"

# Well-known public resolvers used for comparison
CLOUDFLARE_RESOLVER = "1.1.1.1"
GOOGLE_RESOLVER = "8.8.8.8"

# Supported record types
SUPPORTED_RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME"]


def _make_resolver(resolver_ip: str) -> dns.resolver.Resolver:
    """Create a dnspython Resolver pointed at a single nameserver."""
    r = dns.resolver.Resolver(configure=False)
    r.nameservers = [resolver_ip]
    r.timeout = 4      # per-query timeout (seconds)
    r.lifetime = 8     # total lifetime across retries (seconds)
    return r


def lookup_records(domain: str, record_type: str, resolver_ip: str = DEFAULT_RESOLVER) -> dict:
    """
    Resolve ``record_type`` DNS records for ``domain`` using ``resolver_ip``.

    Parameters
    ----------
    domain      : Fully-qualified or relative domain name.
    record_type : One of A, AAAA, MX, NS, TXT, CNAME.
    resolver_ip : IP address of the nameserver to query (default: 1.1.1.1).

    Returns
    -------
    dict with keys: domain, record_type, resolver, elapsed_ms, answers, ttl,
                    canonical_name.
    """
    domain = domain.strip().rstrip(".")
    if not domain:
        raise ValueError("Domain name must not be empty.")

    record_type = record_type.upper()
    if record_type not in SUPPORTED_RECORD_TYPES:
        raise ValueError(
            f"Unsupported record type '{record_type}'. "
            f"Supported: {', '.join(SUPPORTED_RECORD_TYPES)}"
        )

    r = _make_resolver(resolver_ip)

    start = time.perf_counter()
    try:
        answer = r.resolve(domain, record_type, raise_on_no_answer=False)
    except dns.resolver.NXDOMAIN:
        raise ValueError(f"Domain '{domain}' does not exist (NXDOMAIN).")
    except dns.resolver.NoNameservers:
        raise ConnectionError(
            f"No name servers available or all refused the query for '{domain}'."
        )
    except dns.exception.Timeout:
        raise TimeoutError(
            f"DNS query for '{domain}' timed out after 8 seconds."
        )
    elapsed = (time.perf_counter() - start) * 1000  # milliseconds

    values = []
    ttl = None
    if answer.rrset:
        values = [x.to_text() for x in answer]
        ttl = answer.rrset.ttl

    return {
        "domain": domain,
        "record_type": record_type,
        "resolver": resolver_ip,
        "elapsed_ms": round(elapsed, 2),
        "answers": values,
        "ttl": ttl,
        "canonical_name": str(answer.canonical_name),
    }


def compare_resolvers(domain: str, resolver1: str = CLOUDFLARE_RESOLVER,
                      resolver2: str = GOOGLE_RESOLVER) -> dict:
    """
    Query A records for ``domain`` from two independent resolvers and report
    whether the answer sets match.

    Differences are investigation indicators, not proof of DNS hijacking.
    Legitimate reasons for differences include CDN geographic routing, per-resolver
    caching and load-balancing configurations.

    Parameters
    ----------
    domain    : Domain name to compare.
    resolver1 : First resolver IP  (default: Cloudflare 1.1.1.1).
    resolver2 : Second resolver IP (default: Google 8.8.8.8).

    Returns
    -------
    dict with both answer sets, a ``same_answer`` boolean and an interpretation.
    """
    domain = domain.strip().rstrip(".")
    if not domain:
        raise ValueError("Domain name must not be empty.")

    result1 = lookup_records(domain, "A", resolver1)
    result2 = lookup_records(domain, "A", resolver2)

    aa = sorted(result1["answers"])
    bb = sorted(result2["answers"])

    differences = list(set(aa) - set(bb)) + list(set(bb) - set(aa))

    if aa == bb:
        interpretation = (
            "Both resolvers returned identical A records. "
            "No resolver discrepancy detected."
        )
    else:
        interpretation = (
            "The resolver answers differ. This is a signal to investigate "
            "further. Common legitimate causes include CDN geographic routing, "
            "per-resolver caching, and load balancing. "
            "Differences alone do not confirm DNS hijacking."
        )

    return {
        "domain": domain,
        "resolver_1": resolver1,
        "resolver_1_answers": aa,
        "resolver_1_elapsed_ms": result1["elapsed_ms"],
        "resolver_1_ttl": result1["ttl"],
        "resolver_2": resolver2,
        "resolver_2_answers": bb,
        "resolver_2_elapsed_ms": result2["elapsed_ms"],
        "resolver_2_ttl": result2["ttl"],
        "same_answer": aa == bb,
        "differing_records": differences,
        "interpretation": interpretation,
    }


def simulated_lookup(domain: str, expected_ip: str, returned_ip: str) -> dict:
    """
    Local educational simulation of a DNS mismatch.

    Compares an expected IP address with a simulated resolver response.
    No network packets are sent; no real DNS configuration is altered.

    Parameters
    ----------
    domain      : Test domain name (label only).
    expected_ip : The IP address that a legitimate resolver should return.
    returned_ip : The IP address the simulated (potentially hijacked) resolver returns.

    Returns
    -------
    dict with mismatch flag and security interpretation.
    """
    mismatch = expected_ip.strip() != returned_ip.strip()

    if mismatch:
        interpretation = (
            "SIMULATED MISMATCH: The IP address returned by the DNS resolver differs "
            "from the expected value. In a real attack scenario (e.g. router compromise "
            "or cache poisoning), this could redirect users to attacker-controlled "
            "infrastructure. Users connecting to the returned IP over HTTPS would then "
            "see a TLS certificate warning if the attacker lacks a valid certificate for "
            "the domain — a warning that should never be bypassed."
        )
        severity = "HIGH — investigate immediately in a real environment"
    else:
        interpretation = (
            "No mismatch: The simulated resolver returned the expected IP address. "
            "DNS resolution appears consistent with expectations."
        )
        severity = "NONE — responses match"

    return {
        "domain": domain,
        "expected_ip": expected_ip.strip(),
        "simulated_returned_ip": returned_ip.strip(),
        "mismatch": mismatch,
        "severity": severity,
        "interpretation": interpretation,
        "note": (
            "This is a local educational simulation only. "
            "No network DNS response was forged and no system configuration was modified."
        ),
    }
