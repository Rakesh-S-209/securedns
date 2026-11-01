# SecureDNS — A Cryptographic Framework for Detecting DNS Hijacking and Securing Internet Communication

An Internet and Network Security (INS) college project demonstrating DNS hijacking
indicators, DNSSEC validation, DNS-over-HTTPS, and TLS certificate inspection
through a professional Streamlit dashboard.

> **Important limitations**
> - Resolver answer differences are investigation **indicators only** — CDN geographic routing,
>   per-resolver caching and load balancing can cause legitimate differences.
> - DNSSEC status is reported using Cloudflare's AD flag. This is the resolver's validation
>   result, not independent local DNSSEC chain validation.
> - DoH protects the client-to-resolver channel only; it does not make the resolver trustworthy.
> - TLS inspection validates the certificate chain and hostname using the machine's CA trust store.
> - The attack simulator is a local comparison. No packets are forged and no DNS is modified.
> - A valid TLS certificate does not prove a website is benign.

---

## Quick Start

### Windows (PowerShell)
```powershell
# 1. Navigate to the project
cd "path\to\SecureDNS"

# 2. Create and activate a virtual environment
py -m venv .venv
.venv\Scripts\Activate.ps1

# 3. Install dependencies
python -m pip install --upgrade pip
pip install -r requirements.txt

# 4. Launch the dashboard
streamlit run app.py
```

### Kali Linux / Ubuntu (Bash)
```bash
# 1. Install prerequisites
sudo apt update
sudo apt install -y python3-venv python3-pip

# 2. Navigate to the project
cd /path/to/SecureDNS

# 3. Create and activate a virtual environment
python3 -m venv .venv
source .venv/bin/activate

# 4. Install dependencies
python -m pip install --upgrade pip
pip install -r requirements.txt

# 5. Launch the dashboard
streamlit run app.py
```

Open the URL printed by Streamlit — usually **http://localhost:8501**.

---

## Running Tests
```bash
pytest -v tests/
```
All 50 tests mock network dependencies and run without internet access.

---

## Project Structure
```
SecureDNS/
├── app.py                      # Streamlit dashboard (Module F)
├── requirements.txt
├── README.md
├── .gitignore
├── modules/
│   ├── __init__.py
│   ├── dns_analyzer.py         # Module A: DNS lookup & resolver comparison
│   ├── dnssec_validator.py     # Module B: DNSSEC validation via DoH
│   ├── doh_client.py           # Module C: DNS-over-HTTPS client
│   ├── tls_analyzer.py         # Module D: TLS certificate inspector
│   └── attack_simulator.py     # Module E: DNS hijacking simulator
├── tests/
│   ├── __init__.py
│   └── test_modules.py         # 50 automated tests (all modules)
├── results/                    # Test run output files
└── docs/
    ├── TEAM_PLAN.md
    └── REPORT_DRAFT.md
```

---

## Module Summary

| Module | File | Purpose | INS Concept |
|--------|------|---------|-------------|
| A — DNS Analyzer | `dns_analyzer.py` | DNS lookup, resolver comparison, discrepancy detection | DNS protocol, UDP/53, resolver infrastructure |
| B — DNSSEC Validator | `dnssec_validator.py` | DNSSEC status via validating resolver; AD flag explanation | DNSSEC chain of trust, RRSIG/DNSKEY/DS records |
| C — DoH Client | `doh_client.py` | Encrypted DNS-over-HTTPS queries; transport comparison | RFC 8484, TLS-encrypted DNS channel |
| D — TLS Analyzer | `tls_analyzer.py` | TLS connection inspection, certificate chain validation | X.509 certificates, TLS handshake, cipher suites |
| E — Attack Simulator | `attack_simulator.py` | Safe local DNS hijacking simulation; attack chain | AiTM, DNS spoofing, Forest Blizzard case study |

---

## Safe Test Inputs

| Module | Input | Notes |
|--------|-------|-------|
| DNS Analyzer | `example.com`, `cloudflare.com` | Basic lookup |
| Resolver Compare | `cloudflare.com` with 1.1.1.1 vs 8.8.8.8 | CDNs may produce different answers legitimately |
| DNSSEC | `cloudflare.com` (signed), `example.com` (may be unsigned) | Observe AD=1 vs AD=0 |
| DoH | `example.com`, `cloudflare.com` | Compare with traditional DNS |
| TLS — valid | `example.com:443` | Should succeed |
| TLS — expired | `expired.badssl.com:443` | Expected validation failure |
| TLS — mismatch | `wrong.host.badssl.com:443` | Expected validation failure |
| Simulator | Expected: `192.0.2.10`, Returned: `198.51.100.25` | RFC 5737 documentation ranges |

*Use only on systems and networks you own or are authorized to test.*

---

## Wireshark Evidence Instructions

To capture DNS traffic for your report:

1. Open Wireshark and select your active network interface.
2. **Traditional DNS (plaintext):** Apply filter `udp.port == 53`.
   - In the app, run a DNS lookup. You will see the query domain and response IPs in plaintext.
3. **DNS-over-HTTPS (encrypted):** Apply filter `tcp.port == 443 && tls`.
   - In the app, run a DoH query. The DNS content is encrypted — you see only TLS Application Data.
4. Take screenshots of both captures. The contrast demonstrates why DoH improves query privacy.

---

## Team Responsibilities

| Member | Deliverables |
|--------|-------------|
| Member 1 | DNS Analyzer module, incident timeline, Wireshark evidence (UDP/53) |
| Member 2 | DNSSEC/DoH module, AD-flag interpretation, signed vs unsigned domain comparison |
| Member 3 | TLS Analyzer module, certificate screenshots, expired/mismatch test evidence |
| Member 4 | Streamlit integration, requirements, GitHub repo, test log, final report/presentation |

---

## Known Limitations

1. DNSSEC validation is resolver-reported via Cloudflare, not independent local chain validation.
2. DoH encrypts client-to-resolver only; the resolver itself must be trusted.
3. DNS resolver differences may have entirely benign causes.
4. TLS inspection depends on the host machine's CA trust store.
5. The attack simulator is a local comparison — no packets are forged.
6. Wireshark evidence must be collected manually outside this application.
7. No real router DNS configuration is read or modified.
8. Public resolver rate-limiting may occasionally cause query failures.

---

## References

- RFC 4033/4034/4035 — DNS Security Extensions (DNSSEC)
- RFC 8484 — DNS Queries over HTTPS (DoH)
- RFC 8446 — TLS 1.3
- RFC 5737 — IPv4 Address Blocks Reserved for Documentation
- Microsoft MSTIC — Forest Blizzard / APT28 / STRONTIUM advisory
- FBI / DOJ / NCSC joint advisory on SOHO router compromise
