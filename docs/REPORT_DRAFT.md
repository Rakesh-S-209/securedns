# SecureDNS: A Cryptographic Framework for Detecting DNS Hijacking and Securing Internet Communication

## Abstract
This project studies DNS hijacking and adversary-in-the-middle (AiTM) risks through the Forest Blizzard router-compromise case study. It develops an educational prototype that performs DNS record lookup, compares resolver answers, reports DNSSEC validation status through a validating DNS-over-HTTPS resolver, and checks TLS certificate and hostname validation. A controlled local simulation demonstrates how a manipulated DNS answer can differ from an expected answer. The prototype illustrates layered protections while emphasizing that DNSSEC, DoH and TLS address different security properties.

## 1. Introduction
DNS translates human-readable domain names into network addresses. Traditional DNS does not itself provide cryptographic authentication of ordinary responses. If a router or DNS configuration is compromised, clients may be directed to attacker-controlled infrastructure. TLS certificate validation provides a separate identity check at the application connection layer.

## 2. Case Study
Use the official Microsoft, FBI, DOJ and NCSC reporting on Forest Blizzard's compromise of SOHO routers and manipulation of DNS settings. Insert a sourced timeline and distinguish reported activity periods. Do not claim that TLS was cryptographically broken; explain that certificate warnings were presented and could be ignored.

## 3. Problem Statement
How can users and administrators detect suspicious DNS resolution behaviour and apply cryptographic controls to improve the authenticity of DNS data and security of application connections?

## 4. Objectives
1. Inspect common DNS records and resolver responses.
2. Compare answers from independent resolvers and flag differences for investigation.
3. Report DNSSEC validation status from a validating resolver.
4. demonstrate DNS queries over HTTPS.
5. Inspect TLS certificate chain and hostname validation.
6. Demonstrate a controlled DNS answer mismatch.

## 5. Proposed System
Describe the Streamlit dashboard and modules: DNS analyzer, DNSSEC/DoH validator, TLS analyzer, and local simulation. Include the architecture diagram created by the team.

## 6. Cryptographic Techniques
- DNSSEC: public-key signatures and a chain of trust for DNS data authenticity/integrity.
- DoH: HTTPS/TLS protection for the client-to-resolver DNS channel.
- TLS: certificate-chain and hostname validation, key establishment, and authenticated encryption.
Explain that DoH does not replace DNSSEC and DNSSEC does not encrypt queries.

## 7. Implementation
Document Python, Streamlit, dnspython, requests, Python ssl, and the test environment. Include screenshots and code excerpts from the actual project.

## 8. Testing and Results
Populate only after running tests. Suggested cases:
- Successful A/AAAA lookup.
- Resolver comparison with matching answers.
- Resolver comparison with differing answers (report as discrepancy only).
- DNSSEC AD=1 response.
- DNSSEC AD=0 response (do not label automatically malicious).
- Valid TLS certificate.
- Invalid/expired certificate.
- Simulated DNS mismatch and no-mismatch.
Include timestamps, test environment, measured response times and Wireshark screenshots.

## 9. Limitations
The prototype does not inspect or secure a production router, does not independently validate the DNSSEC chain locally, and does not prove malicious activity from resolver differences. The local simulation does not forge live DNS packets. TLS inspection checks the endpoint at test time and relies on the host trust store.

## 10. Conclusion
Summarize measured outcomes after tests. State which controls detect or mitigate which threat, and avoid claiming complete prevention of router compromise.

## References
Add exact titles, publication dates, URLs and access dates for official Microsoft, FBI, DOJ and NCSC incident reports, plus RFC 4033, RFC 8484 and RFC 8446. Verify every citation before submission.
