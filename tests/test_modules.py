"""
SecureDNS — Automated Test Suite
==================================
Covers all five modules.  Network dependencies are mocked so tests run
reliably without internet access.

Test groups:
    TestDNSAnalyzer       — Module A: DNS Analyzer
    TestDNSSECValidator   — Module B: DNSSEC Validator
    TestDoHClient         — Module C: DNS over HTTPS Client
    TestTLSAnalyzer       — Module D: TLS Certificate Analyzer
    TestAttackSimulator   — Module E: DNS Hijacking Simulator
"""

import pytest
import unittest.mock as mock
import socket
import ssl
import dns.resolver
import dns.exception
import dns.message
import dns.rdatatype
import dns.flags

# ─────────────────────────────────────────────────────────────────────────────
# Helpers shared across tests
# ─────────────────────────────────────────────────────────────────────────────

def _make_mock_doh_response(ad: bool = True, rcode_name: str = "NOERROR",
                            answers: list = None) -> mock.MagicMock:
    """
    Build a mock dns.message.Message that looks like a Cloudflare DoH reply.
    """
    msg = mock.MagicMock()
    msg.flags = dns.flags.AD if ad else 0
    msg.rcode.return_value = dns.rcode.from_text(rcode_name)

    if answers is None:
        answers = []
    msg.answer = answers
    return msg


# ─────────────────────────────────────────────────────────────────────────────
# Module A: DNS Analyzer
# ─────────────────────────────────────────────────────────────────────────────

class TestDNSAnalyzer:
    """Tests for modules/dns_analyzer.py"""

    # ── lookup_records ────────────────────────────────────────────────────────

    def test_lookup_a_record_returns_dict(self):
        """A successful A-record lookup returns a dict with expected keys."""
        from modules.dns_analyzer import lookup_records
        with mock.patch("dns.resolver.Resolver.resolve") as mock_resolve:
            rrset = mock.MagicMock()
            rrset.ttl = 300
            rrset.__iter__ = lambda s: iter([mock.MagicMock(to_text=lambda: "93.184.216.34")])
            ans = mock.MagicMock()
            ans.rrset = rrset
            ans.canonical_name = mock.MagicMock()
            ans.canonical_name.__str__ = lambda s: "example.com."
            mock_resolve.return_value = ans

            result = lookup_records("example.com", "A", "1.1.1.1")

        assert isinstance(result, dict)
        assert result["domain"] == "example.com"
        assert result["record_type"] == "A"
        assert result["resolver"] == "1.1.1.1"
        assert "answers" in result
        assert "elapsed_ms" in result
        assert "ttl" in result

    def test_lookup_empty_domain_raises(self):
        """An empty domain name raises ValueError."""
        from modules.dns_analyzer import lookup_records
        with pytest.raises(ValueError, match="empty"):
            lookup_records("", "A")

    def test_lookup_unsupported_record_type_raises(self):
        """An unsupported record type raises ValueError."""
        from modules.dns_analyzer import lookup_records
        with pytest.raises(ValueError, match="Unsupported"):
            lookup_records("example.com", "BOGUS")

    def test_lookup_nxdomain_raises_value_error(self):
        """NXDOMAIN is converted to a descriptive ValueError."""
        from modules.dns_analyzer import lookup_records
        with mock.patch("dns.resolver.Resolver.resolve",
                        side_effect=dns.resolver.NXDOMAIN()):
            with pytest.raises(ValueError, match="NXDOMAIN"):
                lookup_records("does-not-exist.example.invalid", "A")

    def test_lookup_timeout_raises_timeout_error(self):
        """A DNS timeout is converted to TimeoutError."""
        from modules.dns_analyzer import lookup_records
        with mock.patch("dns.resolver.Resolver.resolve",
                        side_effect=dns.exception.Timeout()):
            with pytest.raises(TimeoutError):
                lookup_records("example.com", "A")

    def test_lookup_no_nameservers_raises_connection_error(self):
        """NoNameservers is converted to ConnectionError."""
        from modules.dns_analyzer import lookup_records
        with mock.patch("dns.resolver.Resolver.resolve",
                        side_effect=dns.resolver.NoNameservers()):
            with pytest.raises(ConnectionError):
                lookup_records("example.com", "A")

    # ── compare_resolvers ──────────────────────────────────────────────────────

    def test_compare_resolvers_matching(self):
        """compare_resolvers reports same_answer=True when both return identical records."""
        from modules.dns_analyzer import compare_resolvers
        from modules.dns_analyzer import lookup_records

        mock_result = {
            "answers": ["93.184.216.34"],
            "elapsed_ms": 12.0,
            "ttl": 3600,
        }
        with mock.patch("modules.dns_analyzer.lookup_records",
                        return_value=mock_result):
            result = compare_resolvers("example.com", "1.1.1.1", "8.8.8.8")

        assert result["same_answer"] is True
        assert result["differing_records"] == []

    def test_compare_resolvers_differing(self):
        """compare_resolvers reports same_answer=False when answers differ."""
        from modules.dns_analyzer import compare_resolvers

        def side_effect(domain, record_type, resolver_ip):
            if resolver_ip == "1.1.1.1":
                return {"answers": ["1.2.3.4"], "elapsed_ms": 10.0, "ttl": 300}
            return {"answers": ["9.9.9.9"], "elapsed_ms": 15.0, "ttl": 300}

        with mock.patch("modules.dns_analyzer.lookup_records",
                        side_effect=side_effect):
            result = compare_resolvers("example.com", "1.1.1.1", "8.8.8.8")

        assert result["same_answer"] is False
        assert len(result["differing_records"]) > 0
        assert "indicator" in result["interpretation"].lower() or \
               "differ" in result["interpretation"].lower()

    def test_compare_resolvers_empty_domain_raises(self):
        """compare_resolvers raises ValueError for an empty domain."""
        from modules.dns_analyzer import compare_resolvers
        with pytest.raises(ValueError):
            compare_resolvers("")

    # ── simulated_lookup ───────────────────────────────────────────────────────

    def test_simulation_detects_mismatch(self):
        """simulated_lookup returns mismatch=True when IPs differ."""
        from modules.dns_analyzer import simulated_lookup
        result = simulated_lookup("test.example", "192.0.2.1", "198.51.100.1")
        assert result["mismatch"] is True

    def test_simulation_no_mismatch(self):
        """simulated_lookup returns mismatch=False when IPs are identical."""
        from modules.dns_analyzer import simulated_lookup
        result = simulated_lookup("test.example", "192.0.2.1", "192.0.2.1")
        assert result["mismatch"] is False

    def test_simulation_strips_whitespace(self):
        """simulated_lookup correctly strips leading/trailing whitespace from IPs."""
        from modules.dns_analyzer import simulated_lookup
        result = simulated_lookup("test.example", "  192.0.2.1  ", "192.0.2.1  ")
        assert result["mismatch"] is False

    def test_simulation_has_note(self):
        """simulated_lookup result always includes a note about local-only simulation."""
        from modules.dns_analyzer import simulated_lookup
        result = simulated_lookup("test.example", "192.0.2.1", "198.51.100.1")
        assert "note" in result
        assert "simulation" in result["note"].lower()


# ─────────────────────────────────────────────────────────────────────────────
# Module B: DNSSEC Validator
# ─────────────────────────────────────────────────────────────────────────────

class TestDNSSECValidator:
    """Tests for modules/dnssec_validator.py"""

    def _mock_requests_get(self, ad: bool = True, rcode_name: str = "NOERROR"):
        """Return a context manager that mocks requests.get for DoH queries."""
        mock_resp = mock.MagicMock()
        mock_resp.status_code = 200
        mock_resp.raise_for_status = mock.MagicMock()

        # Build a minimal DNS wire-format reply
        msg = dns.message.make_response(
            dns.message.make_query("example.com", "A")
        )
        if ad:
            msg.flags |= dns.flags.AD
        mock_resp.content = msg.to_wire()
        return mock_resp

    def test_validate_dnssec_ad_set(self):
        """validate_dnssec_doh returns ad_flag=True when resolver sets AD bit."""
        from modules.dnssec_validator import validate_dnssec_doh
        mock_resp = self._mock_requests_get(ad=True)
        with mock.patch("requests.get", return_value=mock_resp):
            result = validate_dnssec_doh("cloudflare.com")
        assert result["ad_flag"] is True
        assert "Secure" in result["dnssec_state"]

    def test_validate_dnssec_ad_not_set(self):
        """validate_dnssec_doh returns ad_flag=False when AD bit is clear."""
        from modules.dnssec_validator import validate_dnssec_doh
        mock_resp = self._mock_requests_get(ad=False)
        with mock.patch("requests.get", return_value=mock_resp):
            result = validate_dnssec_doh("example.com")
        assert result["ad_flag"] is False
        assert "Insecure" in result["dnssec_state"] or \
               "Indeterminate" in result["dnssec_state"]

    def test_validate_dnssec_empty_domain_raises(self):
        """validate_dnssec_doh raises ValueError for an empty domain."""
        from modules.dnssec_validator import validate_dnssec_doh
        with pytest.raises(ValueError, match="empty"):
            validate_dnssec_doh("")

    def test_validate_dnssec_http_error_propagates(self):
        """An HTTP error from the DoH endpoint propagates as an exception."""
        from modules.dnssec_validator import validate_dnssec_doh
        import requests as req_lib
        mock_resp = mock.MagicMock()
        mock_resp.raise_for_status.side_effect = req_lib.HTTPError("503")
        with mock.patch("requests.get", return_value=mock_resp):
            with pytest.raises(req_lib.HTTPError):
                validate_dnssec_doh("example.com")

    def test_validate_dnssec_result_contains_caveat(self):
        """Result always includes a caveat about resolver-reported validation."""
        from modules.dnssec_validator import validate_dnssec_doh
        mock_resp = self._mock_requests_get(ad=True)
        with mock.patch("requests.get", return_value=mock_resp):
            result = validate_dnssec_doh("cloudflare.com")
        assert "caveat" in result
        assert "cloudflare" in result["caveat"].lower() or \
               "resolver" in result["caveat"].lower()

    def test_explain_dnssec_concepts_returns_dict(self):
        """explain_dnssec_concepts returns a non-empty dict."""
        from modules.dnssec_validator import explain_dnssec_concepts
        concepts = explain_dnssec_concepts()
        assert isinstance(concepts, dict)
        assert len(concepts) > 0
        assert "AD flag" in concepts


# ─────────────────────────────────────────────────────────────────────────────
# Module C: DoH Client
# ─────────────────────────────────────────────────────────────────────────────

class TestDoHClient:
    """Tests for modules/doh_client.py"""

    def _mock_doh_response(self, answers_text: list = None):
        """Build a mock requests.Response for a successful DoH query."""
        query = dns.message.make_query("example.com", "A")
        msg = dns.message.make_response(query)
        mock_resp = mock.MagicMock()
        mock_resp.status_code = 200
        mock_resp.raise_for_status = mock.MagicMock()
        mock_resp.content = msg.to_wire()
        return mock_resp

    def test_doh_query_returns_dict(self):
        """doh_query returns a dict with transport and DNS metadata."""
        from modules.doh_client import doh_query
        mock_resp = self._mock_doh_response()
        with mock.patch("requests.get", return_value=mock_resp):
            result = doh_query("example.com", "A", "Cloudflare")
        assert isinstance(result, dict)
        assert result["transport"] == "DNS-over-HTTPS (RFC 8484) via TLS"
        assert "encryption" in result
        assert result["provider"] == "Cloudflare"

    def test_doh_query_empty_domain_raises(self):
        """doh_query raises ValueError for an empty domain."""
        from modules.doh_client import doh_query
        with pytest.raises(ValueError, match="empty"):
            doh_query("", "A")

    def test_doh_query_unknown_provider_raises(self):
        """doh_query raises ValueError for an unknown provider."""
        from modules.doh_client import doh_query
        with pytest.raises(ValueError, match="Unknown"):
            doh_query("example.com", "A", "UnknownProvider")

    def test_doh_query_network_error_propagates(self):
        """A network-level requests exception propagates from doh_query."""
        from modules.doh_client import doh_query
        import requests as req_lib
        with mock.patch("requests.get",
                        side_effect=req_lib.ConnectionError("Network unreachable")):
            with pytest.raises(req_lib.ConnectionError):
                doh_query("example.com", "A")

    def test_doh_query_timeout_propagates(self):
        """A requests.Timeout propagates from doh_query."""
        from modules.doh_client import doh_query
        import requests as req_lib
        with mock.patch("requests.get",
                        side_effect=req_lib.Timeout("DoH timed out")):
            with pytest.raises(req_lib.Timeout):
                doh_query("example.com", "A")

    def test_get_doh_explanation_returns_dict(self):
        """get_doh_explanation returns a non-empty dict."""
        from modules.doh_client import get_doh_explanation
        exp = get_doh_explanation()
        assert isinstance(exp, dict)
        assert len(exp) >= 4
        assert "What is DoH?" in exp

    def test_doh_providers_defined(self):
        """DOH_PROVIDERS contains at least Cloudflare and Google."""
        from modules.doh_client import DOH_PROVIDERS
        assert "Cloudflare" in DOH_PROVIDERS
        assert "Google" in DOH_PROVIDERS
        for name, cfg in DOH_PROVIDERS.items():
            assert "url" in cfg
            assert cfg["url"].startswith("https://")


# ─────────────────────────────────────────────────────────────────────────────
# Module D: TLS Analyzer
# ─────────────────────────────────────────────────────────────────────────────

class TestTLSAnalyzer:
    """Tests for modules/tls_analyzer.py"""

    def _mock_valid_tls_connection(self):
        """Build a mock TLS socket that simulates a valid certificate."""
        mock_tls = mock.MagicMock()
        mock_tls.version.return_value = "TLSv1.3"
        mock_tls.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
        mock_tls.getpeercert.return_value = {
            "subject": ((("commonName", "example.com"),),),
            "issuer": ((("organizationName", "DigiCert Inc"),),
                       (("commonName", "DigiCert TLS RSA SHA256 2020 CA1"),),),
            "notBefore": "Jan 29 00:00:00 2024 GMT",
            "notAfter": "Jan 28 23:59:59 2025 GMT",
            "subjectAltName": (("DNS", "example.com"), ("DNS", "www.example.com")),
            "serialNumber": "ABCDEF1234567890",
            "version": 3,
            "OCSP": ("http://ocsp.digicert.com",),
            "caIssuers": ("http://cacerts.digicert.com/issuer.crt",),
        }
        return mock_tls

    def test_inspect_tls_valid_certificate(self):
        """inspect_tls returns verified=True for a valid mocked TLS connection."""
        from modules.tls_analyzer import inspect_tls
        mock_tls = self._mock_valid_tls_connection()

        with mock.patch("socket.create_connection") as mock_conn, \
             mock.patch("ssl.SSLContext.wrap_socket", return_value=mock_tls):
            mock_sock = mock.MagicMock()
            mock_conn.return_value.__enter__ = mock.Mock(return_value=mock_sock)
            mock_conn.return_value.__exit__ = mock.Mock(return_value=False)
            mock_tls.__enter__ = mock.Mock(return_value=mock_tls)
            mock_tls.__exit__ = mock.Mock(return_value=False)

            result = inspect_tls("example.com", 443)

        assert result["verified"] is True
        assert result["tls_version"] == "TLSv1.3"
        assert result["error"] is None
        assert result["certificate"] is not None

    def test_inspect_tls_invalid_certificate(self):
        """inspect_tls returns verified=False and captures the error on cert failure."""
        from modules.tls_analyzer import inspect_tls
        with mock.patch("socket.create_connection") as mock_conn, \
             mock.patch("ssl.SSLContext.wrap_socket",
                        side_effect=ssl.SSLCertVerificationError("certificate verify failed")):
            mock_sock = mock.MagicMock()
            mock_conn.return_value.__enter__ = mock.Mock(return_value=mock_sock)
            mock_conn.return_value.__exit__ = mock.Mock(return_value=False)

            result = inspect_tls("expired.badssl.com", 443)

        assert result["verified"] is False
        assert result["error"] is not None
        assert result["error_type"] == "CertificateVerificationError"

    def test_inspect_tls_hostname_mismatch(self):
        """inspect_tls returns verified=False for a hostname mismatch."""
        from modules.tls_analyzer import inspect_tls
        with mock.patch("socket.create_connection") as mock_conn, \
             mock.patch("ssl.SSLContext.wrap_socket",
                        side_effect=ssl.SSLCertVerificationError(
                            "hostname 'wrong.host.badssl.com' doesn't match"
                        )):
            mock_sock = mock.MagicMock()
            mock_conn.return_value.__enter__ = mock.Mock(return_value=mock_sock)
            mock_conn.return_value.__exit__ = mock.Mock(return_value=False)

            result = inspect_tls("wrong.host.badssl.com", 443)

        assert result["verified"] is False
        assert "CertificateVerification" in result.get("error_type", "")

    def test_inspect_tls_timeout(self):
        """inspect_tls returns verified=False and captures Timeout."""
        from modules.tls_analyzer import inspect_tls
        with mock.patch("socket.create_connection",
                        side_effect=socket.timeout("timed out")):
            result = inspect_tls("example.com", 443)

        assert result["verified"] is False
        assert result["error_type"] == "Timeout"

    def test_inspect_tls_network_error(self):
        """inspect_tls returns verified=False for a network connection error."""
        from modules.tls_analyzer import inspect_tls
        with mock.patch("socket.create_connection",
                        side_effect=OSError("Connection refused")):
            result = inspect_tls("unreachable.example.invalid", 443)

        assert result["verified"] is False
        assert result["error_type"] == "NetworkError"

    def test_inspect_tls_empty_hostname_raises(self):
        """inspect_tls raises ValueError for an empty hostname."""
        from modules.tls_analyzer import inspect_tls
        with pytest.raises(ValueError, match="empty"):
            inspect_tls("")

    def test_inspect_tls_invalid_port_raises(self):
        """inspect_tls raises ValueError for an out-of-range port."""
        from modules.tls_analyzer import inspect_tls
        with pytest.raises(ValueError, match="valid range"):
            inspect_tls("example.com", 99999)

    def test_inspect_tls_tls13_status(self):
        """TLSv1.3 is labelled STRONG in tls_version_status."""
        from modules.tls_analyzer import TLS_VERSION_STATUS
        assert "STRONG" in TLS_VERSION_STATUS["TLSv1.3"]

    def test_inspect_tls_tls10_deprecated(self):
        """TLSv1 is labelled WEAK in tls_version_status."""
        from modules.tls_analyzer import TLS_VERSION_STATUS
        assert "WEAK" in TLS_VERSION_STATUS["TLSv1"]

    def test_get_tls_explanation_returns_dict(self):
        """get_tls_explanation returns a non-empty dict."""
        from modules.tls_analyzer import get_tls_explanation
        exp = get_tls_explanation()
        assert isinstance(exp, dict)
        assert len(exp) >= 5


# ─────────────────────────────────────────────────────────────────────────────
# Module E: Attack Simulator
# ─────────────────────────────────────────────────────────────────────────────

class TestAttackSimulator:
    """Tests for modules/attack_simulator.py"""

    def test_simulate_mismatch_detected(self):
        """simulate_dns_hijack detects a mismatch between expected and returned IPs."""
        from modules.attack_simulator import simulate_dns_hijack
        result = simulate_dns_hijack(
            "portal.example.test", "192.0.2.10", "198.51.100.25"
        )
        assert result["mismatch"] is True
        assert result["severity"] == "HIGH"
        # interpretation describes the returned IP differing from expected
        assert ("returned" in result["interpretation"].lower() or
                "mismatch" in result["interpretation"].lower() or
                "differ" in result["interpretation"].lower())

    def test_simulate_no_mismatch(self):
        """simulate_dns_hijack reports no mismatch when IPs are identical."""
        from modules.attack_simulator import simulate_dns_hijack
        result = simulate_dns_hijack(
            "portal.example.test", "192.0.2.10", "192.0.2.10"
        )
        assert result["mismatch"] is False
        assert result["severity"] == "NONE"

    def test_simulate_invalid_expected_ip_raises(self):
        """simulate_dns_hijack raises ValueError for an invalid expected IP."""
        from modules.attack_simulator import simulate_dns_hijack
        with pytest.raises(ValueError, match="not a valid IP"):
            simulate_dns_hijack("test.example", "not_an_ip", "192.0.2.1")

    def test_simulate_invalid_returned_ip_raises(self):
        """simulate_dns_hijack raises ValueError for an invalid returned IP."""
        from modules.attack_simulator import simulate_dns_hijack
        with pytest.raises(ValueError, match="not a valid IP"):
            simulate_dns_hijack("test.example", "192.0.2.1", "999.999.999.999")

    def test_simulate_empty_domain_raises(self):
        """simulate_dns_hijack raises ValueError for an empty domain."""
        from modules.attack_simulator import simulate_dns_hijack
        with pytest.raises(ValueError, match="empty"):
            simulate_dns_hijack("", "192.0.2.1", "198.51.100.1")

    def test_simulate_result_contains_attack_chain(self):
        """Result includes an attack_chain with 5 steps."""
        from modules.attack_simulator import simulate_dns_hijack
        result = simulate_dns_hijack(
            "test.example", "192.0.2.1", "198.51.100.1"
        )
        assert "attack_chain" in result
        assert len(result["attack_chain"]) == 5

    def test_simulate_result_contains_countermeasures(self):
        """Result includes a countermeasures dict with DNSSEC listed."""
        from modules.attack_simulator import simulate_dns_hijack
        result = simulate_dns_hijack(
            "test.example", "192.0.2.1", "198.51.100.1"
        )
        assert "countermeasures" in result
        assert "DNSSEC" in result["countermeasures"]

    def test_simulate_disclaimer_present(self):
        """Result always includes a disclaimer about the local-only simulation."""
        from modules.attack_simulator import simulate_dns_hijack
        result = simulate_dns_hijack(
            "test.example", "192.0.2.1", "192.0.2.1"
        )
        assert "disclaimer" in result
        assert "simulation" in result["disclaimer"].upper() or \
               "LOCAL" in result["disclaimer"].upper()

    def test_simulate_ipv6_addresses(self):
        """simulate_dns_hijack accepts valid IPv6 addresses."""
        from modules.attack_simulator import simulate_dns_hijack
        result = simulate_dns_hijack(
            "test.example",
            "2001:db8::1",
            "2001:db8::2",
        )
        assert result["mismatch"] is True

    def test_simulate_multiple_scenarios_returns_list(self):
        """simulate_multiple_scenarios returns a list of 3 pre-built scenarios."""
        from modules.attack_simulator import simulate_multiple_scenarios
        scenarios = simulate_multiple_scenarios()
        assert isinstance(scenarios, list)
        assert len(scenarios) == 3

    def test_simulate_multiple_scenarios_first_is_no_mismatch(self):
        """First pre-built scenario has no mismatch (control scenario)."""
        from modules.attack_simulator import simulate_multiple_scenarios
        scenarios = simulate_multiple_scenarios()
        assert scenarios[0]["mismatch"] is False

    def test_simulate_multiple_scenarios_second_is_mismatch(self):
        """Second pre-built scenario has a mismatch (hijack scenario)."""
        from modules.attack_simulator import simulate_multiple_scenarios
        scenarios = simulate_multiple_scenarios()
        assert scenarios[1]["mismatch"] is True

    def test_ip_classification_private(self):
        """_classify_ip correctly labels private address space."""
        from modules.attack_simulator import _classify_ip
        assert "Private" in _classify_ip("192.168.1.100")
        assert "Private" in _classify_ip("10.0.0.1")

    def test_ip_classification_documentation(self):
        """_classify_ip correctly labels RFC 5737 documentation ranges."""
        from modules.attack_simulator import _classify_ip
        assert "Documentation" in _classify_ip("192.0.2.1")
        assert "Documentation" in _classify_ip("198.51.100.1")
        assert "Documentation" in _classify_ip("203.0.113.1")
