"""
SecureDNS — Streamlit Dashboard
================================
A cryptographic framework for detecting DNS hijacking and securing internet
communication.  Built as an Internet and Network Security (INS) college project.

Modules integrated:
    A — DNS Analyzer
    B — DNSSEC Validator
    C — DNS over HTTPS (DoH) Client
    D — TLS Certificate Analyzer
    E — DNS Hijacking Simulator
    F — Integrated Dashboard (this file)
"""

import streamlit as st
import plotly.graph_objects as go
import plotly.express as px
import pandas as pd
import time
import json
from datetime import datetime

# ──────────────────────────────────────────────────────────────────────────────
# Page configuration — must be the first Streamlit command
# ──────────────────────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="SecureDNS",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ──────────────────────────────────────────────────────────────────────────────
# Custom CSS — cybersecurity dark theme
# ──────────────────────────────────────────────────────────────────────────────
st.markdown("""
<style>
    /* ── Base ──────────────────────────────────────────────── */
    .stApp {
        background-color: #0d1117;
        color: #c9d1d9;
    }
    .stSidebar {
        background-color: #161b22 !important;
    }

    /* ── Typography ─────────────────────────────────────────── */
    h1, h2, h3, h4 { color: #58a6ff; }
    .stMarkdown p { color: #c9d1d9; line-height: 1.7; }

    /* ── Metric cards ───────────────────────────────────────── */
    [data-testid="metric-container"] {
        background-color: #161b22;
        border: 1px solid #30363d;
        border-radius: 8px;
        padding: 12px 16px;
    }
    [data-testid="stMetricLabel"] { color: #8b949e; }
    [data-testid="stMetricValue"] { color: #58a6ff; }

    /* ── Buttons ─────────────────────────────────────────────── */
    .stButton > button {
        background-color: #1f6feb;
        color: #ffffff;
        border: none;
        border-radius: 6px;
        font-weight: 600;
        padding: 0.45rem 1.2rem;
        transition: background-color 0.2s;
    }
    .stButton > button:hover { background-color: #388bfd; }

    /* ── Status banners ─────────────────────────────────────── */
    .status-secure {
        background-color: #0d2818;
        border-left: 4px solid #3fb950;
        padding: 10px 16px;
        border-radius: 4px;
        color: #3fb950;
        margin: 8px 0;
    }
    .status-warning {
        background-color: #2b2000;
        border-left: 4px solid #d29922;
        padding: 10px 16px;
        border-radius: 4px;
        color: #d29922;
        margin: 8px 0;
    }
    .status-danger {
        background-color: #2d1117;
        border-left: 4px solid #f85149;
        padding: 10px 16px;
        border-radius: 4px;
        color: #f85149;
        margin: 8px 0;
    }
    .status-info {
        background-color: #0c1929;
        border-left: 4px solid #58a6ff;
        padding: 10px 16px;
        border-radius: 4px;
        color: #58a6ff;
        margin: 8px 0;
    }

    /* ── Cards ───────────────────────────────────────────────── */
    .module-card {
        background-color: #161b22;
        border: 1px solid #30363d;
        border-radius: 8px;
        padding: 16px 20px;
        margin: 8px 0;
    }

    /* ── Tables ──────────────────────────────────────────────── */
    .stDataFrame { background-color: #161b22; }
    .stDataFrame th { background-color: #1f6feb !important; color: #fff !important; }

    /* ── Expanders ────────────────────────────────────────────── */
    .streamlit-expanderHeader {
        background-color: #161b22;
        color: #58a6ff;
        border: 1px solid #30363d;
        border-radius: 6px;
    }

    /* ── Divider ─────────────────────────────────────────────── */
    hr { border-color: #30363d; }

    /* ── Code blocks ─────────────────────────────────────────── */
    code { background-color: #161b22; color: #79c0ff; }
</style>
""", unsafe_allow_html=True)


# ──────────────────────────────────────────────────────────────────────────────
# Helper utilities
# ──────────────────────────────────────────────────────────────────────────────

def status_box(level: str, message: str):
    """Render a coloured status banner. level: 'secure'|'warning'|'danger'|'info'."""
    st.markdown(
        f'<div class="status-{level}">{message}</div>',
        unsafe_allow_html=True,
    )


def section_header(icon: str, title: str, subtitle: str = ""):
    """Render a consistent section header."""
    st.markdown(f"## {icon} {title}")
    if subtitle:
        st.markdown(f"<p style='color:#8b949e;margin-top:-8px;'>{subtitle}</p>",
                    unsafe_allow_html=True)


def safe_json(data: dict):
    """Display a dict as collapsible JSON."""
    with st.expander("Raw result (JSON)", expanded=False):
        st.json(data)


def _input_domain(label: str = "Domain name", default: str = "example.com",
                  key: str = "domain") -> str:
    return st.text_input(label, default, key=key).strip().rstrip(".")


# ──────────────────────────────────────────────────────────────────────────────
# Sidebar navigation
# ──────────────────────────────────────────────────────────────────────────────

with st.sidebar:
    st.markdown("""
    <div style='text-align:center;padding:16px 0 8px;'>
        <span style='font-size:2.2rem;'>🔐</span><br>
        <span style='color:#58a6ff;font-size:1.25rem;font-weight:700;'>SecureDNS</span><br>
        <span style='color:#8b949e;font-size:0.8rem;'>INS Project</span>
    </div>
    """, unsafe_allow_html=True)
    st.divider()

    page = st.radio(
        "Navigate to",
        options=[
            "🏠  Home",
            "🔍  DNS Analyzer",
            "🛡️  DNSSEC Validation",
            "🔒  DNS over HTTPS",
            "📜  TLS Certificate Analyzer",
            "⚠️  Attack Simulator",
            "📊  Test Results",
            "ℹ️  About",
        ],
        label_visibility="collapsed",
    )

    st.divider()
    st.markdown(
        "<p style='color:#8b949e;font-size:0.75rem;text-align:center;'>"
        "Educational prototype only.<br>Use only on systems you are<br>"
        "authorized to test.</p>",
        unsafe_allow_html=True,
    )


# ──────────────────────────────────────────────────────────────────────────────
# Page: Home
# ──────────────────────────────────────────────────────────────────────────────

if page == "🏠  Home":
    st.markdown("""
    <div style='text-align:center;padding:32px 0 16px;'>
        <span style='font-size:3.5rem;'>🔐</span>
        <h1 style='color:#58a6ff;margin:8px 0 4px;'>SecureDNS</h1>
        <p style='color:#8b949e;font-size:1.1rem;'>
            A Cryptographic Framework for Detecting DNS Hijacking<br>
            and Securing Internet Communication
        </p>
    </div>
    """, unsafe_allow_html=True)

    status_box("info",
               "⚠️  Educational prototype — results are diagnostic indicators, "
               "not proof of network compromise.  Use only on systems you own "
               "or are authorized to test.")

    st.divider()

    # Overview cards
    cols = st.columns(3)
    with cols[0]:
        st.markdown("""
        <div class='module-card'>
            <h4>🔍 DNS Analyzer</h4>
            <p style='color:#8b949e;font-size:0.9rem;'>
            Look up A, AAAA, MX, NS, TXT and CNAME records.
            Compare responses from Cloudflare and Google to surface discrepancies.
            </p>
        </div>""", unsafe_allow_html=True)
    with cols[1]:
        st.markdown("""
        <div class='module-card'>
            <h4>🛡️ DNSSEC Validation</h4>
            <p style='color:#8b949e;font-size:0.9rem;'>
            Check DNSSEC status via a validating DNS-over-HTTPS resolver.
            Understand Secure, Insecure and Bogus states.
            </p>
        </div>""", unsafe_allow_html=True)
    with cols[2]:
        st.markdown("""
        <div class='module-card'>
            <h4>🔒 DNS over HTTPS</h4>
            <p style='color:#8b949e;font-size:0.9rem;'>
            Send DNS queries over an encrypted HTTPS channel.
            Compare traditional DNS visibility with DoH.
            </p>
        </div>""", unsafe_allow_html=True)

    cols2 = st.columns(3)
    with cols2[0]:
        st.markdown("""
        <div class='module-card'>
            <h4>📜 TLS Analyzer</h4>
            <p style='color:#8b949e;font-size:0.9rem;'>
            Inspect TLS version, cipher suite and certificate details.
            Validate hostname and certificate chain.
            </p>
        </div>""", unsafe_allow_html=True)
    with cols2[1]:
        st.markdown("""
        <div class='module-card'>
            <h4>⚠️ Attack Simulator</h4>
            <p style='color:#8b949e;font-size:0.9rem;'>
            Local simulation of DNS hijacking.
            Explore the attack chain and countermeasures.
            </p>
        </div>""", unsafe_allow_html=True)
    with cols2[2]:
        st.markdown("""
        <div class='module-card'>
            <h4>📊 Test Results</h4>
            <p style='color:#8b949e;font-size:0.9rem;'>
            Run the automated test suite and view a security summary
            of all modules.
            </p>
        </div>""", unsafe_allow_html=True)

    st.divider()

    # Case study
    section_header("🕵️", "Case Study: Forest Blizzard SOHO Router Campaign")
    st.markdown("""
    **Forest Blizzard** (STRONTIUM, APT28) is a Russian state-sponsored threat actor
    attributed to the GRU 85th Main Special Service Center.

    In a widely-reported campaign, the group compromised **Small Office/Home Office (SOHO)
    routers** used by organisations globally.  Key techniques included:

    - Exploiting default or weak credentials on router management interfaces.
    - Modifying DNS server settings to redirect victim traffic through attacker-controlled resolvers.
    - Using compromised routers as operational relay points to obscure attack infrastructure.
    - Enabling Adversary-in-the-Middle (AiTM) interception opportunities when users ignored TLS certificate warnings.

    **Why this matters for DNS security:**
    - Traditional DNS provides no cryptographic authentication — a forged DNS answer is indistinguishable from a legitimate one without DNSSEC.
    - An attacker who controls the resolver controls which IP addresses clients receive.
    - TLS certificate validation at the browser/OS level is the last line of cryptographic defence.

    > *Sources: Microsoft MSTIC, FBI, DOJ, NCSC advisory on Forest Blizzard / APT28 SOHO router operations.*
    """)

    st.divider()

    # Protocol overview diagram
    section_header("🗺️", "Layered Security Model")
    fig = go.Figure()
    layers = [
        ("Application", "HTTPS / TLS certificate validation", "#1f6feb"),
        ("Transport / DNS Security", "DNSSEC — cryptographic record authentication", "#388bfd"),
        ("DNS Transport Channel", "DoH / DoT — encrypted query channel", "#58a6ff"),
        ("DNS Resolution", "DNS Analyzer — resolver comparison & monitoring", "#79c0ff"),
        ("Network Infrastructure", "Router security — firmware, credentials", "#a5d6ff"),
    ]
    for i, (layer, desc, color) in enumerate(reversed(layers)):
        fig.add_trace(go.Bar(
            x=[1],
            y=[layer],
            orientation='h',
            marker_color=color,
            name=f"{layer}: {desc}",
            hovertemplate=f"<b>{layer}</b><br>{desc}<extra></extra>",
        ))
    fig.update_layout(
        barmode='stack',
        paper_bgcolor='#0d1117',
        plot_bgcolor='#0d1117',
        font=dict(color='#c9d1d9'),
        height=280,
        showlegend=True,
        legend=dict(
            bgcolor='#161b22',
            bordercolor='#30363d',
            font=dict(size=11),
            x=1.01,
        ),
        margin=dict(l=0, r=0, t=8, b=8),
        xaxis=dict(showticklabels=False, showgrid=False, zeroline=False),
        yaxis=dict(showgrid=False),
    )
    st.plotly_chart(fig, use_container_width=True)


# ──────────────────────────────────────────────────────────────────────────────
# Page: DNS Analyzer
# ──────────────────────────────────────────────────────────────────────────────

elif page == "🔍  DNS Analyzer":
    from modules.dns_analyzer import (
        lookup_records, compare_resolvers, SUPPORTED_RECORD_TYPES
    )

    section_header("🔍", "DNS Analyzer",
                   "Inspect DNS records and compare resolver responses.")

    status_box("info",
               "ℹ️  Traditional DNS provides no cryptographic authentication.  "
               "Differences between resolvers are investigation indicators only — "
               "CDN geographic routing, caching and load balancing can produce "
               "legitimate differences.")

    # ── Single lookup ──────────────────────────────────────
    st.markdown("### Single DNS Lookup")
    col1, col2, col3 = st.columns([3, 2, 2])
    with col1:
        domain_a = _input_domain(default="example.com", key="dns_single_domain")
    with col2:
        record_type = st.selectbox("Record type", SUPPORTED_RECORD_TYPES, key="dns_rt")
    with col3:
        resolver_ip = st.text_input("Resolver IP", "1.1.1.1", key="dns_resolver")

    if st.button("🔍 Resolve", key="btn_resolve"):
        with st.spinner("Querying resolver..."):
            try:
                result = lookup_records(domain_a, record_type, resolver_ip)
                m1, m2, m3 = st.columns(3)
                m1.metric("Resolver", result["resolver"])
                m2.metric("Response Time", f"{result['elapsed_ms']} ms")
                m3.metric("TTL", f"{result['ttl']} s" if result["ttl"] is not None else "N/A")

                if result["answers"]:
                    df = pd.DataFrame({"Record": result["answers"]})
                    st.dataframe(df, use_container_width=True, hide_index=True)
                    if result.get("canonical_name") and result["canonical_name"] != domain_a + ".":
                        st.markdown(
                            f"**Canonical name:** `{result['canonical_name']}`  "
                            f"*(CNAME chain present)*"
                        )
                else:
                    status_box("warning",
                               f"No {record_type} records found for '{domain_a}'.")
                safe_json(result)
            except Exception as e:
                status_box("danger", f"DNS lookup failed: {e}")

    st.divider()

    # ── Resolver comparison ────────────────────────────────
    st.markdown("### Resolver Comparison")
    st.markdown(
        "<p style='color:#8b949e;'>Queries A records from two independent resolvers "
        "and compares the answer sets.</p>",
        unsafe_allow_html=True,
    )
    col_a, col_b, col_c = st.columns([3, 2, 2])
    with col_a:
        cmp_domain = _input_domain("Domain to compare", "cloudflare.com", "dns_cmp_domain")
    with col_b:
        res1 = st.text_input("Resolver 1", "1.1.1.1", key="res1")
    with col_c:
        res2 = st.text_input("Resolver 2", "8.8.8.8", key="res2")

    if st.button("⚖️ Compare Resolvers", key="btn_compare"):
        with st.spinner("Querying both resolvers..."):
            try:
                cmp = compare_resolvers(cmp_domain, res1, res2)

                col_r1, col_r2 = st.columns(2)
                with col_r1:
                    st.markdown(f"**Resolver 1 — {cmp['resolver_1']}**")
                    for a in cmp["resolver_1_answers"]:
                        st.code(a)
                    st.caption(
                        f"Response time: {cmp['resolver_1_elapsed_ms']} ms  |  "
                        f"TTL: {cmp['resolver_1_ttl']} s"
                    )
                with col_r2:
                    st.markdown(f"**Resolver 2 — {cmp['resolver_2']}**")
                    for a in cmp["resolver_2_answers"]:
                        st.code(a)
                    st.caption(
                        f"Response time: {cmp['resolver_2_elapsed_ms']} ms  |  "
                        f"TTL: {cmp['resolver_2_ttl']} s"
                    )

                if cmp["same_answer"]:
                    status_box("secure",
                               "✅ Both resolvers returned identical A records. "
                               "No discrepancy detected.")
                else:
                    status_box("warning",
                               "⚠️  The answer sets differ.  This is an investigation "
                               "indicator.  Common legitimate causes: CDN geographic "
                               "routing, per-resolver caching, load balancing.  "
                               "Differences alone do NOT confirm DNS hijacking.")
                    st.markdown("**Differing records:**")
                    for d in cmp["differing_records"]:
                        st.code(d)

                # Visual bar chart of response times
                fig = go.Figure([
                    go.Bar(
                        x=[f"Resolver 1 ({res1})", f"Resolver 2 ({res2})"],
                        y=[cmp["resolver_1_elapsed_ms"], cmp["resolver_2_elapsed_ms"]],
                        marker_color=["#1f6feb", "#388bfd"],
                        text=[f"{cmp['resolver_1_elapsed_ms']} ms",
                              f"{cmp['resolver_2_elapsed_ms']} ms"],
                        textposition="outside",
                    )
                ])
                fig.update_layout(
                    title="Resolver Response Time Comparison",
                    yaxis_title="Response time (ms)",
                    paper_bgcolor="#0d1117",
                    plot_bgcolor="#161b22",
                    font=dict(color="#c9d1d9"),
                    height=280,
                    margin=dict(l=0, r=0, t=40, b=0),
                )
                st.plotly_chart(fig, use_container_width=True)
                safe_json(cmp)

            except Exception as e:
                status_box("danger", f"Comparison failed: {e}")

    st.divider()
    with st.expander("💡 DNS Concepts Explained"):
        st.markdown("""
        | Record | Purpose |
        |--------|---------|
        | **A** | Maps a domain to an IPv4 address |
        | **AAAA** | Maps a domain to an IPv6 address |
        | **MX** | Mail exchange servers for the domain |
        | **NS** | Authoritative nameservers for the zone |
        | **TXT** | Arbitrary text; used for SPF, DKIM, domain verification |
        | **CNAME** | Alias — points to another domain name |

        **TTL (Time-to-Live):** Number of seconds resolvers and clients may cache this record.
        A very short TTL can indicate dynamic infrastructure or an active attack attempt.

        **Why compare resolvers?**
        An attacker who controls a resolver or a router's DNS setting returns only the
        records *they* supply to clients using that resolver.  An independent public
        resolver that caches the authoritative answer provides a comparison point.
        """)


# ──────────────────────────────────────────────────────────────────────────────
# Page: DNSSEC Validation
# ──────────────────────────────────────────────────────────────────────────────

elif page == "🛡️  DNSSEC Validation":
    from modules.dnssec_validator import (
        validate_dnssec_doh, explain_dnssec_concepts
    )

    section_header("🛡️", "DNSSEC Validation",
                   "Check DNSSEC status via Cloudflare's validating resolver over DoH.")

    status_box("warning",
               "⚠️  The AD (Authenticated Data) flag is reported by Cloudflare's "
               "resolver — not by independent local cryptographic validation.  "
               "AD=0 does NOT automatically indicate an attack: the domain may "
               "simply be unsigned, or the resolver may not have validated it.")

    col_d, col_rt = st.columns([3, 2])
    with col_d:
        dnssec_domain = _input_domain("Domain to validate", "cloudflare.com", "dnssec_domain")
    with col_rt:
        dnssec_rt = st.selectbox("Record type", ["A", "AAAA", "MX", "NS"], key="dnssec_rt")

    if st.button("🛡️ Validate DNSSEC", key="btn_dnssec"):
        with st.spinner("Querying Cloudflare DoH with DNSSEC request..."):
            try:
                result = validate_dnssec_doh(dnssec_domain, dnssec_rt)

                m1, m2, m3 = st.columns(3)
                m1.metric("Domain", result["domain"])
                m2.metric("RCODE", result["dns_rcode"])
                m3.metric("AD Flag", "✅ SET (AD=1)" if result["ad_flag"] else "⬜ NOT SET (AD=0)")

                if result["ad_flag"]:
                    status_box("secure",
                               f"✅  {result['dnssec_state']}")
                elif result["dns_rcode"] == "SERVFAIL":
                    status_box("danger",
                               f"🔴  {result['dnssec_state']}")
                else:
                    status_box("warning",
                               f"⚠️  {result['dnssec_state']}")

                st.markdown(f"**Interpretation:** {result['interpretation']}")
                st.caption(f"⚠️  {result['caveat']}")

                if result["answers"]:
                    st.markdown("**Answer section:**")
                    for a in result["answers"]:
                        with st.container():
                            st.markdown(
                                f"**{a['name']}** &nbsp;&nbsp; `{a['type']}`"
                            )
                            for rec in a["records"]:
                                st.code(rec)

                safe_json(result)
            except Exception as e:
                status_box("danger", f"DNSSEC/DoH query failed: {e}")

    st.divider()

    with st.expander("📚 DNSSEC Concepts"):
        concepts = explain_dnssec_concepts()
        for term, explanation in concepts.items():
            st.markdown(f"**{term}**")
            st.markdown(f"{explanation}")
            st.divider()

    with st.expander("🔗 DNSSEC Chain of Trust — Diagram"):
        st.markdown("""
        ```
        Root (.)
          ↓  DS record in root zone verifies
        .com (TLD)
          ↓  DS record in .com zone verifies
        example.com (authoritative zone)
          ↓  DNSKEY signs
        RRSIG on A record for example.com
          ↓  client / validating resolver checks
        Validated answer
        ```
        Each delegation link is secured by a DS record (a hash of the child's DNSKEY)
        published in the parent zone.  The chain anchors at the IANA root trust anchor.
        """)


# ──────────────────────────────────────────────────────────────────────────────
# Page: DNS over HTTPS
# ──────────────────────────────────────────────────────────────────────────────

elif page == "🔒  DNS over HTTPS":
    from modules.doh_client import (
        doh_query, compare_doh_vs_traditional, get_doh_explanation, DOH_PROVIDERS
    )

    section_header("🔒", "DNS over HTTPS",
                   "Send DNS queries over an encrypted HTTPS channel.")

    status_box("info",
               "ℹ️  DoH encrypts the client-to-resolver channel.  It does not "
               "cryptographically authenticate DNS records (that requires DNSSEC) "
               "and does not make the resolver itself trustworthy.")

    tabs_doh = st.tabs(["Single DoH Query", "DoH vs Traditional DNS Comparison"])

    with tabs_doh[0]:
        st.markdown("### Single DoH Query")
        col1, col2, col3 = st.columns([3, 2, 2])
        with col1:
            doh_domain = _input_domain("Domain", "example.com", "doh_domain")
        with col2:
            doh_rt = st.selectbox("Record type", ["A", "AAAA", "MX", "NS", "TXT"], key="doh_rt")
        with col3:
            doh_provider = st.selectbox("DoH Provider", list(DOH_PROVIDERS.keys()),
                                        key="doh_provider")

        if st.button("🔒 Query via DoH", key="btn_doh"):
            with st.spinner("Sending encrypted DNS query..."):
                try:
                    result = doh_query(doh_domain, doh_rt, doh_provider)

                    m1, m2, m3 = st.columns(3)
                    m1.metric("Provider", result["provider"])
                    m2.metric("RCODE", result["dns_rcode"])
                    m3.metric("Response Time", f"{result['elapsed_ms']} ms")

                    status_box("secure",
                               f"✅  Query completed over {result['transport']}")
                    status_box("info",
                               f"🔒  {result['encryption']}")

                    if result["answers"]:
                        st.markdown("**Answer section:**")
                        for a in result["answers"]:
                            st.markdown(f"**{a['name']}** `{a['type']}`")
                            for r in a["records"]:
                                st.code(r)
                    else:
                        status_box("warning", "No records returned.")

                    safe_json(result)
                except Exception as e:
                    status_box("danger", f"DoH query failed: {e}")

    with tabs_doh[1]:
        st.markdown("### DoH vs Traditional DNS Comparison")
        st.markdown(
            "Queries the same domain via both DoH (encrypted) and traditional "
            "UDP/53 DNS (plaintext) to compare results and transport characteristics."
        )
        col1, col2 = st.columns([3, 2])
        with col1:
            cmp_domain = _input_domain("Domain", "example.com", "doh_cmp_domain")
        with col2:
            trad_resolver = st.text_input("Traditional resolver IP", "8.8.8.8",
                                          key="trad_res")

        if st.button("⚖️ Compare Transports", key="btn_doh_cmp"):
            with st.spinner("Querying both transports..."):
                try:
                    cmp = compare_doh_vs_traditional(cmp_domain,
                                                     traditional_resolver=trad_resolver)

                    col_doh, col_trad = st.columns(2)
                    with col_doh:
                        st.markdown("#### 🔒 DNS over HTTPS")
                        st.markdown(f"**Provider:** {cmp['doh']['provider']}")
                        st.markdown(f"**Transport:** {cmp['doh']['transport']}")
                        st.markdown(f"**Response time:** {cmp['doh']['elapsed_ms']} ms")
                        status_box("secure", cmp["doh"]["wireshark_visibility"])
                        for a in cmp["doh"]["answers"]:
                            for r in a["records"]:
                                st.code(r)

                    with col_trad:
                        st.markdown("#### 📡 Traditional DNS (UDP/53)")
                        st.markdown(f"**Resolver:** {cmp['traditional_dns']['resolver']}")
                        st.markdown(f"**Transport:** {cmp['traditional_dns']['transport']}")
                        st.markdown(f"**Response time:** {cmp['traditional_dns']['elapsed_ms']} ms")
                        if cmp["traditional_dns"]["error"]:
                            status_box("warning",
                                       f"Error: {cmp['traditional_dns']['error']}")
                        else:
                            status_box("warning", cmp["traditional_dns"]["wireshark_visibility"])
                            for a in cmp["traditional_dns"]["answers"]:
                                st.code(a)

                    st.divider()
                    st.markdown("#### Transport Comparison")
                    tc = cmp["transport_comparison"]
                    df_rows = []
                    for prop, vals in tc.items():
                        if isinstance(vals, dict):
                            for k, v in vals.items():
                                df_rows.append({
                                    "Property": prop,
                                    "Category": k,
                                    "Detail": v,
                                })
                    if df_rows:
                        df = pd.DataFrame(df_rows)
                        st.dataframe(df, use_container_width=True, hide_index=True)

                    safe_json(cmp)
                except Exception as e:
                    status_box("danger", f"Comparison failed: {e}")

    st.divider()
    with st.expander("📚 DoH Explained"):
        from modules.doh_client import get_doh_explanation
        for heading, text in get_doh_explanation().items():
            st.markdown(f"**{heading}**")
            st.markdown(text)
            st.divider()


# ──────────────────────────────────────────────────────────────────────────────
# Page: TLS Certificate Analyzer
# ──────────────────────────────────────────────────────────────────────────────

elif page == "📜  TLS Certificate Analyzer":
    from modules.tls_analyzer import inspect_tls, get_tls_explanation, TEST_ENDPOINTS

    section_header("📜", "TLS Certificate Analyzer",
                   "Inspect TLS connections and validate certificates.")

    status_box("info",
               "ℹ️  Certificate verification uses Python's default SSL context "
               "and the system CA trust store.  Certificate validation is never "
               "disabled.")

    col1, col2 = st.columns([4, 1])
    with col1:
        tls_host = st.text_input("Hostname", "example.com", key="tls_host").strip()
    with col2:
        tls_port = st.number_input("Port", min_value=1, max_value=65535,
                                   value=443, key="tls_port")

    st.markdown("**Quick test endpoints:**")
    qcols = st.columns(4)
    quick_names = list(TEST_ENDPOINTS.keys())
    for i, ep_name in enumerate(quick_names):
        col_i = qcols[i % 4]
        h, p = TEST_ENDPOINTS[ep_name]
        if col_i.button(ep_name.replace("_", " ").title(), key=f"quick_{ep_name}"):
            tls_host = h
            tls_port = p
            st.session_state["tls_host"] = h
            st.session_state["tls_port"] = p
            st.rerun()

    if st.button("🔍 Inspect TLS", key="btn_tls"):
        with st.spinner(f"Connecting to {tls_host}:{tls_port}..."):
            try:
                result = inspect_tls(tls_host, int(tls_port))
            except Exception as e:
                status_box("danger", f"Unexpected error: {e}")
                result = None

        if result:
            if result["verified"]:
                status_box("secure",
                           "✅  TLS certificate and hostname validation succeeded.")
            else:
                status_box("danger",
                           f"🔴  TLS validation failed: {result.get('error', 'Unknown error')}")
                if result.get("error_explanation"):
                    st.markdown(f"**Explanation:** {result['error_explanation']}")

            m1, m2, m3, m4 = st.columns(4)
            m1.metric("TLS Version", result["tls_version"] or "N/A")
            m2.metric("Verified", "✅ Yes" if result["verified"] else "❌ No")
            m3.metric("Days Until Expiry",
                      result["days_until_expiry"] if result["days_until_expiry"] is not None else "N/A")
            m4.metric("Expiry Status", result["expiry_status"] or "N/A")

            if result["tls_version"]:
                tv_status = result.get("tls_version_status", "")
                if "STRONG" in tv_status:
                    status_box("secure", f"🔐 TLS Version: {result['tls_version']} — {tv_status}")
                elif "ACCEPTABLE" in tv_status:
                    status_box("info", f"ℹ️ TLS Version: {result['tls_version']} — {tv_status}")
                else:
                    status_box("warning", f"⚠️ TLS Version: {result['tls_version']} — {tv_status}")

            if result.get("cipher"):
                c = result["cipher"]
                st.markdown(
                    f"**Cipher suite:** `{c.get('name')}` &nbsp;|&nbsp; "
                    f"Protocol: `{c.get('protocol')}` &nbsp;|&nbsp; "
                    f"Key bits: `{c.get('bits')}`"
                )

            if result.get("certificate"):
                cert = result["certificate"]
                with st.expander("📋 Certificate Details", expanded=True):
                    col_s, col_i = st.columns(2)
                    with col_s:
                        st.markdown("**Subject**")
                        for k, v in (cert.get("subject") or {}).items():
                            st.markdown(f"&nbsp;&nbsp;`{k}`: {v}")
                    with col_i:
                        st.markdown("**Issuer**")
                        for k, v in (cert.get("issuer") or {}).items():
                            st.markdown(f"&nbsp;&nbsp;`{k}`: {v}")

                    st.divider()
                    col_nb, col_na = st.columns(2)
                    col_nb.markdown(f"**Valid from:** {cert.get('not_before', 'N/A')}")
                    col_na.markdown(f"**Valid to:** {cert.get('not_after', 'N/A')}")

                    if cert.get("subject_alt_names"):
                        st.markdown("**Subject Alternative Names:**")
                        for san in cert["subject_alt_names"]:
                            st.markdown(f"- `{san}`")

            safe_json(result)

    st.divider()
    with st.expander("📚 TLS & Certificate Concepts"):
        for heading, text in get_tls_explanation().items():
            st.markdown(f"**{heading}**")
            st.markdown(text)
            st.divider()


# ──────────────────────────────────────────────────────────────────────────────
# Page: Attack Simulator
# ──────────────────────────────────────────────────────────────────────────────

elif page == "⚠️  Attack Simulator":
    from modules.attack_simulator import simulate_dns_hijack, simulate_multiple_scenarios

    section_header("⚠️", "DNS Hijacking Attack Simulator",
                   "Safe local simulation — no packets forged, no real DNS altered.")

    status_box("warning",
               "🧪  LOCAL SIMULATION ONLY — This module performs a local comparison "
               "of user-supplied values.  No DNS server is queried or modified.  "
               "No network packets are sent.  For educational use only.")

    tabs_sim = st.tabs(["Manual Simulation", "Pre-built Scenarios", "Attack Chain"])

    with tabs_sim[0]:
        st.markdown("### Manual DNS Hijacking Simulation")
        st.markdown(
            "Enter the domain, the IP address you expect from a legitimate resolver, "
            "and the IP address a potentially hijacked resolver would return."
        )
        col1, col2, col3 = st.columns(3)
        with col1:
            sim_domain = st.text_input(
                "Domain (label only)", "portal.example.test", key="sim_domain"
            )
        with col2:
            sim_expected = st.text_input(
                "Expected IP (legitimate)", "192.0.2.10", key="sim_exp"
            )
        with col3:
            sim_returned = st.text_input(
                "Simulated DNS response IP", "198.51.100.25", key="sim_ret"
            )

        if st.button("▶️ Run Simulation", key="btn_sim"):
            try:
                result = simulate_dns_hijack(sim_domain, sim_expected, sim_returned)

                m1, m2, m3 = st.columns(3)
                m1.metric("Expected IP", result["expected_ip"])
                m2.metric("Returned IP", result["simulated_returned_ip"])
                m3.metric("Mismatch", "⚠️ YES" if result["mismatch"] else "✅ NO")

                if result["mismatch"]:
                    status_box("danger", result["severity_label"])
                else:
                    status_box("secure", result["severity_label"])

                st.markdown(f"**Interpretation:**")
                st.markdown(result["interpretation"])

                col_exp, col_ret = st.columns(2)
                col_exp.markdown(
                    f"**Expected IP type:** {result['expected_ip_class']}"
                )
                col_ret.markdown(
                    f"**Returned IP type:** {result['returned_ip_class']}"
                )

                st.caption(result["disclaimer"])
                safe_json(result)
            except ValueError as e:
                status_box("danger", f"Input validation error: {e}")
            except Exception as e:
                status_box("danger", f"Simulation error: {e}")

    with tabs_sim[1]:
        st.markdown("### Pre-built Scenarios")
        st.markdown(
            "These scenarios use RFC 5737 documentation address ranges "
            "and demonstrate different DNS hijacking situations."
        )
        if st.button("▶️ Run All Scenarios", key="btn_scenarios"):
            try:
                scenarios = simulate_multiple_scenarios()
                for i, s in enumerate(scenarios):
                    with st.expander(
                        f"Scenario {i+1}: {s['description']} — "
                        f"{'⚠️ MISMATCH' if s['mismatch'] else '✅ MATCH'}",
                        expanded=(i == 0),
                    ):
                        c1, c2, c3 = st.columns(3)
                        c1.metric("Domain", s["domain"])
                        c2.metric("Expected IP", s["expected_ip"])
                        c3.metric("Returned IP", s["simulated_returned_ip"])

                        if s["mismatch"]:
                            status_box("danger", s["severity_label"])
                        else:
                            status_box("secure", s["severity_label"])

                        if s.get("scenario_note"):
                            st.markdown(f"*{s['scenario_note']}*")

                        st.markdown(s["interpretation"])
            except Exception as e:
                status_box("danger", f"Scenario error: {e}")

    with tabs_sim[2]:
        st.markdown("### DNS Hijacking Attack Chain")
        st.markdown(
            "Step-by-step breakdown of how a router-based DNS hijacking attack "
            "progresses — based on the Forest Blizzard SOHO router campaign."
        )
        if st.button("📋 Show Attack Chain", key="btn_chain"):
            try:
                # Generate with a mismatch scenario to get full chain details
                result = simulate_dns_hijack(
                    "portal.victim.example", "192.0.2.10", "198.51.100.25",
                    "Forest Blizzard style router DNS hijack"
                )
                for step in result["attack_chain"]:
                    with st.expander(
                        f"Step {step['step']}: {step['title']}", expanded=True
                    ):
                        st.markdown(step["description"])
                        if step.get("mitigations"):
                            st.markdown("**Mitigations:**")
                            for m in step["mitigations"]:
                                st.markdown(f"- {m}")

                st.divider()
                st.markdown("### Countermeasures Summary")
                for name, desc in result["countermeasures"].items():
                    st.markdown(f"**{name}**")
                    st.markdown(desc)
            except Exception as e:
                status_box("danger", f"Error: {e}")


# ──────────────────────────────────────────────────────────────────────────────
# Page: Test Results
# ──────────────────────────────────────────────────────────────────────────────

elif page == "📊  Test Results":
    section_header("📊", "Automated Test Results & Security Summary",
                   "Run the test suite and review module coverage.")

    status_box("info",
               "ℹ️  Automated tests mock network dependencies so they run reliably "
               "without internet access.  Run 'pytest -v' in the project directory "
               "for the full test output.")

    import subprocess
    import sys

    col1, col2 = st.columns([2, 1])
    with col1:
        if st.button("▶️ Run Automated Tests", key="btn_tests"):
            with st.spinner("Running pytest..."):
                try:
                    proc = subprocess.run(
                        [sys.executable, "-m", "pytest", "tests/", "-v",
                         "--tb=short", "--no-header", "-q"],
                        capture_output=True,
                        text=True,
                        timeout=60,
                    )
                    output = proc.stdout + proc.stderr
                    if proc.returncode == 0:
                        status_box("secure", "✅  All tests passed.")
                    else:
                        status_box("danger", f"🔴  Some tests failed (exit code {proc.returncode}).")
                    st.code(output, language="text")

                    # Save result
                    import os
                    os.makedirs("results", exist_ok=True)
                    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
                    fname = f"results/test_run_{ts}.txt"
                    with open(fname, "w") as f:
                        f.write(output)
                    st.caption(f"Result saved to {fname}")
                except subprocess.TimeoutExpired:
                    status_box("danger", "Test run timed out after 60 seconds.")
                except FileNotFoundError as e:
                    status_box("danger", f"Could not run pytest: {e}")

    with col2:
        st.markdown("**Run manually:**")
        st.code("pytest -v tests/", language="bash")

    st.divider()

    # Security summary matrix
    st.markdown("### Module Security Coverage")
    summary = pd.DataFrame([
        {
            "Module": "A — DNS Analyzer",
            "Threat addressed": "DNS spoofing / resolver substitution",
            "Cryptographic mechanism": "None (demonstrates the gap)",
            "INS concept": "DNS protocol, UDP/53, resolver comparison",
            "Limitation": "Differences may have benign causes",
        },
        {
            "Module": "B — DNSSEC Validator",
            "Threat addressed": "DNS record tampering / cache poisoning",
            "Cryptographic mechanism": "Public-key signatures (RRSIG/DNSKEY/DS)",
            "INS concept": "DNSSEC chain of trust, AD flag",
            "Limitation": "Resolver-reported; not independent local validation",
        },
        {
            "Module": "C — DoH Client",
            "Threat addressed": "DNS eavesdropping / transport manipulation",
            "Cryptographic mechanism": "TLS 1.3 (HTTPS session)",
            "INS concept": "RFC 8484, encrypted DNS transport",
            "Limitation": "Resolver must still be trusted",
        },
        {
            "Module": "D — TLS Analyzer",
            "Threat addressed": "Impersonation via DNS redirect",
            "Cryptographic mechanism": "X.509 certificates, ECDHE key exchange",
            "INS concept": "TLS handshake, certificate chain, hostname check",
            "Limitation": "Relies on system CA trust store",
        },
        {
            "Module": "E — Attack Simulator",
            "Threat addressed": "Educational only — no real threat",
            "Cryptographic mechanism": "Demonstrates absence of DNS authentication",
            "INS concept": "AiTM, router compromise, DNS hijack chain",
            "Limitation": "Local comparison, no packet-level simulation",
        },
    ])
    st.dataframe(summary, use_container_width=True, hide_index=True)

    st.divider()
    st.markdown("### Known Limitations")
    limitations = [
        "DNSSEC validation is resolver-reported (Cloudflare), not independently computed locally.",
        "DoH protects the client-to-resolver channel only; resolver itself must be trusted.",
        "DNS resolver differences may have completely benign causes (CDN, geography, caching).",
        "TLS certificate inspection relies on the host machine's CA trust store.",
        "The attack simulator performs a local comparison; no packets are forged.",
        "Wireshark evidence must be collected manually outside this application.",
        "No real router DNS configuration is read or modified by this application.",
        "Rate-limiting by public resolvers may cause occasional query failures.",
    ]
    for lim in limitations:
        st.markdown(f"- {lim}")


# ──────────────────────────────────────────────────────────────────────────────
# Page: About
# ──────────────────────────────────────────────────────────────────────────────

elif page == "ℹ️  About":
    section_header("ℹ️", "About SecureDNS",
                   "Project information, team, and references.")

    st.markdown("""
    ## Project Overview
    **SecureDNS** is an educational prototype developed as a college project for the
    **Internet and Network Security (INS)** course.  It demonstrates DNS hijacking
    indicators, DNSSEC validation, encrypted DNS transport (DoH), and TLS certificate
    validation using a real-world case study.

    ## Case Study
    **Forest Blizzard** (STRONTIUM / APT28) — a Russian GRU-attributed threat actor —
    compromised SOHO routers and manipulated DNS settings to redirect and intercept
    victim traffic.  This project demonstrates the technical controls that could detect
    or mitigate such an attack at different layers of the stack.

    ## Technology Stack
    | Component | Library / Tool |
    |-----------|---------------|
    | Frontend | Streamlit |
    | DNS operations | dnspython |
    | HTTPS / DoH | requests |
    | TLS inspection | Python ssl, socket |
    | Visualisations | Plotly |
    | Testing | pytest |
    | Packet analysis | Wireshark (external) |

    ## Module Summary
    | Module | Purpose |
    |--------|---------|
    | A — DNS Analyzer | Lookup, compare resolvers, surface discrepancies |
    | B — DNSSEC Validator | Report DNSSEC status via validating resolver |
    | C — DoH Client | Encrypted DNS transport via HTTPS |
    | D — TLS Analyzer | Certificate validation and connection inspection |
    | E — Attack Simulator | Safe local DNS hijacking simulation |

    ## Team
    | Member | Role |
    |--------|------|
    | Member 1 | DNS Analyzer, incident analysis, Wireshark evidence |
    | Member 2 | DNSSEC and DoH module, AD-flag interpretation |
    | Member 3 | TLS Analyzer, certificate tests, TLS evidence |
    | Member 4 | Streamlit integration, QA, report and presentation |

    ## Academic References
    - RFC 4033/4034/4035 — DNS Security Extensions (DNSSEC)
    - RFC 8484 — DNS Queries over HTTPS (DoH)
    - RFC 8446 — The Transport Layer Security (TLS) Protocol Version 1.3
    - Microsoft MSTIC advisory: *Forest Blizzard / APT28 / STRONTIUM*
    - FBI / DOJ / NCSC joint advisory on SOHO router compromise
    - RFC 5737 — IPv4 Address Blocks Reserved for Documentation

    ## Ethical Use
    This application is for educational purposes only.
    - Never use on systems or networks you do not own or are not authorised to test.
    - The attack simulator does not forge real packets or modify any DNS configuration.
    - TLS certificate verification is never disabled.
    """)

    st.divider()
    st.caption(
        f"SecureDNS INS Project — Built with Streamlit · "
        f"Python · dnspython · requests · Plotly"
    )
