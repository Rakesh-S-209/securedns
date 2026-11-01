"""
Module E: DNS Hijacking Attack Simulator
=========================================
What it does:
    Provides a controlled, purely local simulation of DNS hijacking scenarios.
    Users input an expected IP address and a simulated attacker-returned IP address.
    The module compares the values, classifies the mismatch type, generates a
    security interpretation, and explains what a real attacker would do at each
    stage of a DNS hijacking attack chain.

Why it is required:
    Understanding *how* DNS hijacking works helps students and security practitioners
    recognise early indicators and evaluate the effectiveness of countermeasures.
    A safe simulation exercises the detection logic without touching real DNS
    infrastructure, forging any packets, or modifying any network configuration.

INS concept:
    DNS cache poisoning, router firmware compromise, DNS response spoofing,
    Adversary-in-the-Middle (AiTM), Forest Blizzard SOHO router campaign.

Cryptographic technique:
    This module *demonstrates the absence* of cryptographic protection in standard
    DNS — and explains how DNSSEC (Module B) and TLS (Module D) would be required
    to detect or prevent the attack at their respective layers.

Limitations:
    - This is a local comparison only.  No DNS packets are forged.  No real DNS
      configuration is modified.  No network traffic is generated.
    - It does not simulate packet-level transaction ID prediction (Kaminsky attack).
    - It does not model router firmware vulnerabilities.
    - Real DNS hijacking detection requires continuous monitoring, not a one-shot
      comparison.
    - A mismatch in a live environment could have benign causes; this simulator
      uses programmer-supplied values for controlled demonstration only.
"""

import ipaddress
from typing import Optional


# ──────────────────────────────────────────────────────────────────────────────
# IP address utilities
# ──────────────────────────────────────────────────────────────────────────────

def _validate_ip(ip: str, label: str) -> str:
    """Validate that ``ip`` is a syntactically valid IPv4 or IPv6 address."""
    ip = ip.strip()
    if not ip:
        raise ValueError(f"{label} IP address must not be empty.")
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        raise ValueError(
            f"'{ip}' is not a valid IP address for {label}. "
            "Enter a valid IPv4 (e.g. 192.0.2.10) or IPv6 address."
        )
    return ip


def _classify_ip(ip: str) -> str:
    """Return a classification label for an IP address."""
    addr = ipaddress.ip_address(ip)
    # Check documentation ranges BEFORE the generic is_private check because
    # Python's ipaddress marks 192.0.2.0/24 etc. as private in some versions.
    if addr in ipaddress.ip_network("192.0.2.0/24"):
        return "Documentation (TEST-NET-1, RFC 5737)"
    if addr in ipaddress.ip_network("198.51.100.0/24"):
        return "Documentation (TEST-NET-2, RFC 5737)"
    if addr in ipaddress.ip_network("203.0.113.0/24"):
        return "Documentation (TEST-NET-3, RFC 5737)"
    if addr.is_private:
        return "Private / RFC 1918"
    if addr.is_loopback:
        return "Loopback"
    if addr.is_link_local:
        return "Link-local"
    if addr.is_multicast:
        return "Multicast"
    # Documentation ranges
    if addr in ipaddress.ip_network("192.0.2.0/24"):
        return "Documentation (TEST-NET-1, RFC 5737)"
    if addr in ipaddress.ip_network("198.51.100.0/24"):
        return "Documentation (TEST-NET-2, RFC 5737)"
    if addr in ipaddress.ip_network("203.0.113.0/24"):
        return "Documentation (TEST-NET-3, RFC 5737)"
    return "Public / Routable"


# ──────────────────────────────────────────────────────────────────────────────
# Core simulation function
# ──────────────────────────────────────────────────────────────────────────────

def simulate_dns_hijack(domain: str, expected_ip: str,
                        simulated_returned_ip: str,
                        description: Optional[str] = None) -> dict:
    """
    Simulate a DNS hijacking scenario by comparing an expected IP address with
    a simulated DNS resolver response.

    This function performs a local comparison only.  No network packets are sent,
    no DNS server is contacted, and no system configuration is changed.

    Parameters
    ----------
    domain               : Domain name being simulated (label only).
    expected_ip          : The IP address a legitimate resolver should return.
    simulated_returned_ip: The IP address the simulated (hijacked) resolver returns.
    description          : Optional scenario description (displayed in results).

    Returns
    -------
    dict with mismatch flag, severity, attack chain, countermeasures and notes.
    """
    domain = domain.strip().rstrip(".")
    if not domain:
        raise ValueError("Domain name must not be empty.")

    expected_ip = _validate_ip(expected_ip, "Expected")
    returned_ip = _validate_ip(simulated_returned_ip, "Simulated Returned")

    mismatch = expected_ip != returned_ip

    expected_class = _classify_ip(expected_ip)
    returned_class = _classify_ip(returned_ip)

    if mismatch:
        severity = "HIGH"
        severity_label = "⚠️  HIGH — Investigate immediately in a real environment"
        interpretation = (
            f"The DNS resolver returned '{returned_ip}' instead of the expected "
            f"'{expected_ip}' for domain '{domain}'.  "
            "In a real scenario this could indicate:\n"
            "• A compromised router or ISP resolver substituting a forged DNS response.\n"
            "• DNS cache poisoning (e.g. Kaminsky-style attack).\n"
            "• An attacker-operated resolver configured to redirect the domain.\n\n"
            "A user connecting to the returned IP would be directed to attacker-controlled "
            "infrastructure.  If the attacker presents a TLS certificate that does not "
            "match the domain, the browser/OS will show a certificate warning — which "
            "must never be bypassed."
        )
    else:
        severity = "NONE"
        severity_label = "✅  NONE — Responses match"
        interpretation = (
            f"The simulated resolver returned the expected IP address '{expected_ip}' "
            f"for domain '{domain}'.  No DNS mismatch detected in this simulation."
        )

    attack_chain = [
        {
            "step": 1,
            "title": "Initial Compromise",
            "description": (
                "Attacker exploits a vulnerability in a SOHO router (e.g. weak "
                "credentials, unpatched firmware) to gain administrative access.  "
                "In the Forest Blizzard campaign, compromised routers were used as "
                "operational relay boxes to obscure attacker infrastructure."
            ),
            "mitigations": ["Change default router credentials", "Apply firmware updates"],
        },
        {
            "step": 2,
            "title": "DNS Configuration Manipulation",
            "description": (
                "Attacker modifies the router's DNS server setting from a legitimate "
                "resolver to an attacker-controlled resolver.  All clients using the "
                "router for DNS resolution now receive attacker-supplied answers."
            ),
            "mitigations": [
                "Use DNSSEC-validating resolvers",
                "Configure client-side DoH/DoT to bypass router DNS",
                "Monitor router DNS settings",
            ],
        },
        {
            "step": 3,
            "title": "DNS Response Substitution",
            "description": (
                "When a victim queries the target domain, the attacker's resolver "
                "returns a forged IP address pointing to attacker-controlled infrastructure.  "
                "Without DNSSEC, the client has no way to detect the substitution."
            ),
            "mitigations": [
                "DNSSEC: cryptographic signatures allow a validating resolver to detect forged records",
                "Compare responses from independent resolvers (DNS Analyzer module)",
            ],
        },
        {
            "step": 4,
            "title": "Traffic Interception",
            "description": (
                "Victim's browser connects to the attacker's server.  "
                "For HTTP sites, the attacker sees plaintext traffic immediately.  "
                "For HTTPS sites, a TLS certificate warning is presented if the "
                "attacker cannot obtain a legitimate certificate for the domain."
            ),
            "mitigations": [
                "NEVER bypass TLS certificate warnings",
                "TLS certificate pinning (advanced)",
                "HSTS (HTTP Strict Transport Security) preloading",
            ],
        },
        {
            "step": 5,
            "title": "Adversary-in-the-Middle / Credential Harvest",
            "description": (
                "If the user bypasses the TLS warning (or the attacker has a "
                "fraudulently obtained certificate), the attacker can present a "
                "cloned site to harvest credentials or deliver malware."
            ),
            "mitigations": [
                "Multi-factor authentication (limits impact of stolen credentials)",
                "Browser certificate transparency checks",
                "End-to-end encryption beyond the transport layer",
            ],
        },
    ]

    countermeasures_summary = {
        "DNSSEC": (
            "Adds cryptographic signatures to DNS records.  A DNSSEC-validating "
            "resolver can detect a forged response.  Effective at Step 3."
        ),
        "DoH / DoT": (
            "Encrypts the client-to-resolver channel.  Prevents on-path DNS "
            "manipulation if the client uses a trusted external resolver directly, "
            "bypassing a compromised router resolver.  Effective at Step 2/3."
        ),
        "TLS Certificate Validation": (
            "Even after a successful DNS redirect, a valid certificate for the "
            "domain is required.  Certificate warnings indicate a possible attack.  "
            "Effective at Step 4."
        ),
        "Router Security": (
            "Changing default credentials, updating firmware, and monitoring "
            "DNS settings prevent the initial compromise.  Effective at Step 1/2."
        ),
    }

    return {
        "simulation": True,
        "domain": domain,
        "description": description or "Manual DNS hijacking simulation",
        "expected_ip": expected_ip,
        "expected_ip_class": expected_class,
        "simulated_returned_ip": returned_ip,
        "returned_ip_class": returned_class,
        "mismatch": mismatch,
        "severity": severity,
        "severity_label": severity_label,
        "interpretation": interpretation,
        "attack_chain": attack_chain,
        "countermeasures": countermeasures_summary,
        "disclaimer": (
            "LOCAL SIMULATION ONLY — No network packets were sent, "
            "no DNS server was queried or modified, and no real system "
            "configuration was altered.  This is a purely educational "
            "comparison of user-supplied values."
        ),
    }


def simulate_multiple_scenarios() -> list:
    """
    Return a set of pre-built simulation scenarios for demonstration purposes.

    These use RFC 5737 documentation address ranges and do not represent real domains.
    """
    scenarios = [
        {
            "name": "No attack — consistent resolution",
            "domain": "portal.example.test",
            "expected_ip": "192.0.2.10",
            "simulated_returned_ip": "192.0.2.10",
            "note": "Normal case: resolver returns the expected address.",
        },
        {
            "name": "DNS hijack — redirected to attacker IP",
            "domain": "portal.example.test",
            "expected_ip": "192.0.2.10",
            "simulated_returned_ip": "198.51.100.25",
            "note": (
                "Attacker scenario: resolver returns a different IP.  "
                "User would be directed to attacker-controlled infrastructure."
            ),
        },
        {
            "name": "Internal router DNS substitution",
            "domain": "update.example.test",
            "expected_ip": "203.0.113.50",
            "simulated_returned_ip": "192.168.1.100",
            "note": (
                "Attacker redirects to an internal host on the LAN.  "
                "Common in SOHO router compromise scenarios."
            ),
        },
    ]

    results = []
    for s in scenarios:
        r = simulate_dns_hijack(s["domain"], s["expected_ip"],
                                s["simulated_returned_ip"], s["name"])
        r["scenario_note"] = s["note"]
        results.append(r)
    return results
