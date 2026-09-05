# Quantum.Ready

**A live scanner that tells a company what cryptography, certificates and licences it is actually running — and what it must change before a quantum computer makes today's traffic readable.**

Point it at a domain. It discovers the public estate, assesses every endpoint's
certificates and TLS configuration, works out what is quantum-vulnerable,
inventories third-party components and their licence obligations, maps the
result onto the regimes you are judged by, and produces a prioritised plan.

Built on the **Agile Mosca** research: [Mosca's inequality](#moscas-inequality)
(X + Y > Z) is the core question, and the scanner answers it with evidence
rather than assertion.

```bash
python -m quantumready scan acme.co.uk --org "Acme Ltd" --sector finance
python -m quantumready serve            # live dashboard on localhost:8080
```

---

## Why this exists

Adversaries are recording encrypted traffic today to decrypt it once
cryptographically relevant quantum computers arrive. That is **harvest now,
decrypt later**, and it means the deadline for protecting long-lived data has
already passed for many organisations.

Two quantum algorithms matter, and they matter very differently:

| | Effect | What it breaks | Severity |
|---|---|---|---|
| **Shor's algorithm** | Solves factorisation and discrete logs in polynomial time | RSA, DSA, DH, ECDSA, ECDH, Ed25519 — **all of them, completely** | Existential |
| **Grover's algorithm** | Quadratic speed-up on search | Halves symmetric strength: AES-128 → 64 bits | Manageable |

The consequence people miss: **a bigger RSA key does not help.** RSA-15360 falls
to the same algorithm as RSA-2048, just slightly later. The migration is about
replacing algorithms, not resizing keys — and AES-256 is already fine.

## What it checks

**Certificates** — full chain retrieval and parsing; key algorithm and strength;
signature algorithm; expiry and lifetime; trust and hostname validation; chain
completeness; Certificate Transparency; CA/B Forum lifetime limits; wildcard
blast radius; weak RSA exponents.

**TLS** — real protocol negotiation for SSLv3 through TLS 1.3; full cipher suite
enumeration; forward secrecy; broken, export, anonymous and NULL suites; named
group enumeration.

**Post-quantum readiness** — probes for hybrid ML-KEM key exchange
(`X25519MLKEM768` 0x11EC, `SecP256r1MLKEM768`, `SecP384r1MLKEM1024`), superseded
Kyber drafts, and standalone ML-KEM. Detects PQC certificate algorithms
(ML-DSA, SLH-DSA) when they appear.

**TLS interception** — detects when a middlebox, not the origin server, minted
the certificate you are looking at. Two independent signals: known inspection
vendor CAs, and the absence of Certificate Transparency SCTs on a locally
trusted chain.

**HTTP** — HSTS strength and preload eligibility, CSP, framing, MIME sniffing,
referrer and permissions policy, cookie flags, version disclosure, plaintext
port 80 exposure.

**DNS** — CAA, DNSSEC, SPF, DMARC policy strength, MX. Speaks the wire protocol
directly, with TCP fallback when an answer is truncated.

**Licences** — identifies third-party components and versions, maps them to SPDX
licences, and flags what actually bites: AGPL's network clause, SSPL, GPL
obligations, commercial-use restrictions, end-of-life components, and
publicly readable dependency manifests.

**Compliance** — NCSC PQC roadmap (2028/2031/2035), NIST FIPS 203/204/205 and
SP 800-131A, CNSA 2.0, PCI DSS 4.0, UK GDPR Article 32, NIS2, ISO 27001:2022
A.8.24, Cyber Essentials.

## Mosca's inequality

> **If X + Y > Z, you are already too late.**
>
> **X** — how long your data must stay confidential
> **Y** — how long migration takes
> **Z** — how long until a quantum computer can break your cryptography

```
$ python -m quantumready mosca --shelf-life 25 --migration-years 5

  X(25) + Y(5) = 30 > Z(8.4)  →  EXPOSED
```

The scanner sets a sector-appropriate default for X (healthcare 25 years,
government 30, finance 15) and lets you override everything. Z is a planning
judgement, not a measurement, so the assumption is always printed alongside the
conclusion — conservative (2030), central (2035, the NCSC deadline), or
optimistic (2040).

## Output

Four formats, all from one scan:

| Format | Use |
|---|---|
| **HTML** | Board-ready, self-contained, prints to PDF, light and dark |
| **JSON** | The canonical result; everything else is a view over it |
| **Markdown** | Drops into a ticket or pull request |
| **CycloneDX 1.6 CBOM** | Cryptographic bill of materials for your SBOM pipeline |

```bash
python -m quantumready scan acme.co.uk \
  --html-out report.html --json-out result.json --cbom-out crypto.cbom.json
```

## Live dashboard

```bash
python -m quantumready serve
```

Enter a domain and watch the scan stream in real time over server-sent events —
host discovery, each endpoint's TLS result, PQC probe outcomes — then read the
report inline and download any format.

Binds to loopback by default. It has no authentication and will scan whatever
it is given, so do not expose it publicly.

## CI gate

```bash
python -m quantumready scan acme.co.uk --fail-on high --quiet
```

Exit `0` clean, `1` when a finding at that severity or worse is present, `2` on
error.

## Install

Python 3.9+. **No runtime dependencies** — a tool that audits supply-chain and
cryptographic risk should not add either.

```bash
git clone https://github.com/DarshanC27/Quantum.Ready.git
cd Quantum.Ready
python -m quantumready scan example.com     # runs as-is
pip install -e .                            # optional, for the `quantumready` command
```

Development extras (`pytest`, and `cryptography` purely as a test oracle):

```bash
pip install -e ".[dev]"
python -m pytest
```

## Design notes

**Zero dependencies, including the X.509 parser.** The ASN.1/DER reader and
certificate parser in `quantumready/crypto/` are written from scratch and
cross-validated field-by-field against `pyca/cryptography` in the test suite.
Malformed input raises a typed error rather than crashing; recursion depth,
buffer bounds and compression-pointer loops are all guarded, because every byte
parsed comes from the host being scanned.

**The TLS client is hand-rolled.** The scanner builds ClientHello messages and
reads ServerHello directly instead of asking the local OpenSSL. This matters:
OpenSSL 3.0 has no ML-KEM, and distributions compile out SSLv3 and TLS 1.0. A
scanner that reported "not supported" because *its own* library was too old
would give the most dangerous wrong answer a security tool can give.

Post-quantum group detection uses the HelloRetryRequest mechanism — offer the
group with no key share, and a supporting server must name it in its retry
(RFC 8446 §4.1.4). This proves support without implementing the key exchange.

**Collection is separated from judgment.** Scanners in `quantumready/scan/`
produce facts. Every severity and verdict comes from `engine/rules.py`, so the
reasoning behind a finding can be reviewed in one place.

**Repeated findings are damped.** The same misconfiguration on forty hosts is
one mistake made once. Without damping, a large estate's score would be
meaningless.

## Limits

Worth stating plainly, because a report that overstates its coverage is worse
than none:

- **External view only.** Internal systems, VPNs, SSH, code signing, database
  and backup encryption, and HSMs are invisible to an external scan — and are
  usually where the hard cases live. That wider inventory is exactly what the
  NCSC 2028 discovery phase asks for.
- **Licences are detected from what a browser loads**, so this finds front-end
  components and the platform, never server-side dependencies. Reconcile it
  against your build system.
- **Scan only what you are authorised to scan.**
- **Compliance mappings are for orientation, not legal advice.**

## Repository layout

```
quantumready/
  crypto/      DER reader, X.509 parser, OID and TLS parameter registries
  scan/        Collectors: TLS, raw TLS client, HTTP, DNS, discovery, licences
  engine/      Judgment: rules, quantum classification, Mosca, scoring,
               compliance, remediation
  report/      HTML, JSON, Markdown, CycloneDX CBOM
  web/         Live dashboard
  cli.py       Command line
  server.py    HTTP API and SSE streaming
tests/         308 tests, fully offline
```

## References

- [NIST FIPS 203 — ML-KEM](https://csrc.nist.gov/pubs/fips/203/final)
- [NIST FIPS 204 — ML-DSA](https://csrc.nist.gov/pubs/fips/204/final)
- [NIST FIPS 205 — SLH-DSA](https://csrc.nist.gov/pubs/fips/205/final)
- [NCSC — Timelines for migration to post-quantum cryptography](https://www.ncsc.gov.uk/guidance/pqc-migration-timelines)
- [draft-ietf-tls-ecdhe-mlkem — hybrid key exchange](https://datatracker.ietf.org/doc/draft-ietf-tls-ecdhe-mlkem/)
- [RFC 9954 — Hybrid Key Exchange in TLS 1.3](https://datatracker.ietf.org/doc/rfc9954/)
- [CycloneDX CBOM](https://cyclonedx.org/capabilities/cbom/)

## Licence

MIT — see [LICENSE](LICENSE).
