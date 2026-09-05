"""Turning observations into findings.

Every verdict in a report is produced here, so that the reasoning behind a
severity can be reviewed in one place rather than reconstructed from
scattered collectors. Rules state what was seen, why it matters and what
to do, because a finding a reader cannot act on is just an alarm.
"""

from __future__ import annotations

import datetime as _dt
from typing import List, Optional

from ..crypto import tlsparams as tp
from ..crypto.x509 import Certificate
from ..model import CryptoAsset, Finding, LicenceRecord, ScanTarget
from ..scan.dns import DNSPosture
from ..scan.http import HTTPResult, parse_cookie_flags, parse_hsts
from ..scan.licences import LicenceScan
from ..scan.tls import TLSEndpoint
from . import quantum

# Reference material cited in findings.
REF_FIPS203 = "NIST FIPS 203 (ML-KEM): https://csrc.nist.gov/pubs/fips/203/final"
REF_FIPS204 = "NIST FIPS 204 (ML-DSA): https://csrc.nist.gov/pubs/fips/204/final"
REF_NCSC = "NCSC PQC migration timelines: https://www.ncsc.gov.uk/guidance/pqc-migration-timelines"
REF_HYBRID = "draft-ietf-tls-ecdhe-mlkem (X25519MLKEM768): https://datatracker.ietf.org/doc/draft-ietf-tls-ecdhe-mlkem/"
REF_RFC8996 = "RFC 8996, Deprecating TLS 1.0 and TLS 1.1"
REF_CABF = "CA/Browser Forum Baseline Requirements"
REF_HSTS = "RFC 6797, HTTP Strict Transport Security"

# Maximum certificate lifetime permitted by the CA/Browser Forum.
MAX_CERT_LIFETIME_DAYS = 398


def _finding(**kwargs) -> Finding:
    return Finding(**kwargs)


# --- certificates ----------------------------------------------------------


def certificate_findings(endpoint: TLSEndpoint, now: _dt.datetime) -> List[Finding]:
    findings: List[Finding] = []
    leaf = endpoint.leaf
    target = endpoint.label
    if leaf is None:
        if endpoint.reachable:
            findings.append(_finding(
                id="certificate.unreadable", title="Certificate could not be read",
                severity="high", category="certificate", target=target,
                detail="The endpoint completed a handshake but no parseable certificate was returned.",
                impact="The certificate cannot be assessed, so its key strength and expiry are unknown.",
                remediation="Check the server's certificate chain configuration.",
            ))
        return findings

    # -- validity ----------------------------------------------------------
    days = leaf.days_until_expiry(now)
    if leaf.is_expired(now):
        findings.append(_finding(
            id="certificate.expired", title="Certificate has expired",
            severity="critical", category="certificate", target=target,
            detail=f"Expired on {leaf.not_after:%d %B %Y}, {abs(days or 0)} days ago.",
            impact="Browsers and API clients reject the connection outright. This is a live outage for anyone who enforces certificate validation, and it trains users to click through security warnings.",
            remediation="Renew the certificate now and put automated renewal in place (ACME via Let's Encrypt, or your CA's automation) so expiry cannot recur.",
            evidence={"not_after": leaf.not_after.isoformat(), "days_overdue": abs(days or 0)},
            compliance=["PCI DSS 4.0 4.2.1", "ISO 27001:2022 A.8.24"],
        ))
    elif leaf.is_not_yet_valid(now):
        findings.append(_finding(
            id="certificate.not-yet-valid", title="Certificate is not yet valid",
            severity="critical", category="certificate", target=target,
            detail=f"Valid from {leaf.not_before:%d %B %Y}.",
            impact="Clients reject the certificate until its start date, and the server clock may also be wrong.",
            remediation="Reissue with a correct validity window and verify server time synchronisation.",
        ))
    elif days is not None and days <= 30:
        severity = "high" if days <= 14 else "medium"
        findings.append(_finding(
            id="certificate.expiring-soon", title=f"Certificate expires in {days} days",
            severity=severity, category="certificate", target=target,
            detail=f"Expires {leaf.not_after:%d %B %Y}.",
            impact="An unnoticed expiry causes a full outage of this service.",
            remediation="Renew now and automate renewal so this is not a calendar entry anyone has to remember.",
            evidence={"days_remaining": days},
        ))

    if leaf.lifetime_days and leaf.lifetime_days > MAX_CERT_LIFETIME_DAYS:
        findings.append(_finding(
            id="certificate.excessive-lifetime", title="Certificate lifetime exceeds the industry maximum",
            severity="medium", category="certificate", target=target,
            detail=f"Issued for {leaf.lifetime_days} days; the CA/Browser Forum maximum is {MAX_CERT_LIFETIME_DAYS}.",
            impact="Long-lived certificates extend the window in which a stolen key stays useful, and they are the main obstacle to crypto-agility: an estate that renews rarely cannot pivot quickly to post-quantum algorithms when it needs to.",
            remediation="Move to short-lived, automatically renewed certificates. Renewal you perform routinely is renewal you can repoint at a new algorithm.",
            quantum_relevant=True,
            references=[REF_CABF],
        ))

    # -- trust and identity ------------------------------------------------
    if leaf.is_self_signed:
        findings.append(_finding(
            id="certificate.self-signed", title="Certificate is self-signed",
            severity="high", category="certificate", target=target,
            detail=f"Subject and issuer are identical: {leaf.subject_display}.",
            impact="No third party vouches for this identity, so clients cannot distinguish the real server from an impostor. Users are trained to bypass the warning, which defeats TLS entirely.",
            remediation="Replace with a certificate from a publicly trusted CA, or distribute your private CA properly if this is an internal-only service.",
        ))
    elif not endpoint.trusted:
        findings.append(_finding(
            id="certificate.untrusted", title="Certificate chain is not trusted",
            severity="high", category="certificate", target=target,
            detail=f"Validation failed: {endpoint.trust_error}",
            impact="Clients enforcing validation cannot connect, and those that do not are exposed to interception.",
            remediation="Install the full chain issued by a publicly trusted CA and confirm the intermediates are current.",
        ))

    if not endpoint.hostname_matches:
        findings.append(_finding(
            id="certificate.hostname-mismatch", title="Certificate does not cover this hostname",
            severity="high", category="certificate", target=target,
            detail=f"Presented for {leaf.subject_display}; SANs: {', '.join(leaf.san_dns[:8]) or 'none'}.",
            impact="The certificate does not authenticate the name clients asked for, so it provides no assurance they reached the right server.",
            remediation=f"Reissue including {endpoint.host} in the subject alternative names.",
        ))

    if not endpoint.chain_complete:
        findings.append(_finding(
            id="certificate.incomplete-chain", title="Server does not send intermediate certificates",
            severity="medium", category="certificate", target=target,
            detail="Only the leaf certificate was presented.",
            impact="Browsers usually recover by fetching the issuer themselves, but API clients, mobile apps and older libraries frequently do not, producing failures that appear intermittent and are painful to diagnose.",
            remediation="Configure the server to send the full chain up to but excluding the root.",
        ))

    if not leaf.has_sct and not leaf.is_self_signed and not endpoint.interception_suspected:
        findings.append(_finding(
            id="certificate.no-transparency", title="Certificate carries no Certificate Transparency proof",
            severity="low", category="certificate", target=target,
            detail="No embedded signed certificate timestamps were found.",
            impact="Misissuance of this name would not be publicly detectable, and Chrome rejects publicly trusted certificates that lack SCTs.",
            remediation="Use a CA that submits to CT logs and embeds SCTs.",
        ))

    # -- key and signature strength ---------------------------------------
    key = leaf.public_key
    if key:
        assessment = quantum.assess_public_key(key.algorithm, key.size_bits, key.curve)
        if key.algorithm in ("RSA", "RSASSA-PSS") and key.size_bits < 2048:
            findings.append(_finding(
                id="certificate.weak-key", title=f"RSA key is only {key.size_bits} bits",
                severity="critical", category="certificate", target=target,
                detail=f"{assessment.algorithm} provides roughly {assessment.classical_bits} bits of classical security.",
                impact="This is breakable with conventional computing resources today. No quantum computer is required.",
                remediation="Reissue with at least RSA-3072, or preferably ECDSA P-256, and plan the move to ML-DSA.",
                evidence={"key_bits": key.size_bits, "classical_bits": assessment.classical_bits},
                compliance=["NIST SP 800-57", "PCI DSS 4.0 4.2.1"],
            ))
        elif key.algorithm == "EC" and assessment.classical_bits < 112:
            findings.append(_finding(
                id="certificate.weak-curve", title=f"Elliptic curve {key.curve} is below current strength",
                severity="high", category="certificate", target=target,
                detail=f"Provides about {assessment.classical_bits} bits classically.",
                impact="Below the 112-bit floor NIST requires for current use.",
                remediation="Reissue on P-256 or stronger.",
            ))

        if not assessment.quantum_safe and assessment.broken_by == "Shor":
            findings.append(_finding(
                id="pqc.classical-certificate-key",
                title=f"Certificate key ({assessment.algorithm}) is breakable by a quantum computer",
                severity="high", category="post-quantum", target=target,
                detail=assessment.rationale + ".",
                impact="Server authentication depends entirely on this key. Once a cryptographically relevant quantum computer exists, an attacker can derive the private key from the public certificate and impersonate this service. Unlike confidentiality, this is not a retrospective risk -- it takes effect the moment the capability exists.",
                remediation=f"Track your CA's post-quantum roadmap and plan reissuance to {assessment.replacement}. In the meantime shorten certificate lifetimes so you can pivot quickly.",
                quantum_relevant=True,
                evidence={"algorithm": assessment.algorithm, "classical_bits": assessment.classical_bits, "quantum_bits": 0},
                references=[REF_FIPS204, REF_NCSC],
                compliance=["NCSC 2035 migration", "NIST IR 8547"],
            ))

    if leaf.signature_hash in ("SHA-1", "MD5", "MD2", "MD4"):
        findings.append(_finding(
            id="certificate.broken-signature-hash",
            title=f"Certificate signed with {leaf.signature_hash}",
            severity="critical", category="certificate", target=target,
            detail=f"Signature algorithm: {leaf.signature_algorithm}.",
            impact=f"{leaf.signature_hash} is broken against collision attacks with conventional hardware, so a forged certificate for this name is achievable today.",
            remediation="Reissue with SHA-256 or SHA-384 immediately.",
            compliance=["PCI DSS 4.0 4.2.1", "NIST SP 800-131A"],
        ))

    if key and key.rsa_exponent is not None and key.rsa_exponent < 65537:
        findings.append(_finding(
            id="certificate.small-rsa-exponent", title=f"RSA public exponent is {key.rsa_exponent}",
            severity="low", category="certificate", target=target,
            detail=f"Exponent e={key.rsa_exponent}; 65537 is the standard choice.",
            impact="Small exponents have historically enabled signature forgery when verification is implemented carelessly (Bleichenbacher's attack).",
            remediation="Reissue with e=65537.",
        ))

    wildcards = [n for n in leaf.san_dns if n.startswith("*.")]
    if any(n.count(".") <= 1 for n in wildcards):
        findings.append(_finding(
            id="certificate.broad-wildcard", title="Certificate uses a very broad wildcard",
            severity="medium", category="certificate", target=target,
            detail=f"Wildcard names: {', '.join(wildcards[:5])}.",
            impact="One stolen key covers every host under the domain, so the blast radius of a compromise is the whole estate.",
            remediation="Issue per-service certificates via automation instead of sharing one wildcard key.",
        ))

    return findings


# --- TLS configuration -----------------------------------------------------


def tls_findings(endpoint: TLSEndpoint) -> List[Finding]:
    findings: List[Finding] = []
    target = endpoint.label

    if not endpoint.reachable:
        findings.append(_finding(
            id="tls.unreachable", title="Endpoint did not complete a TLS handshake",
            severity="info", category="tls", target=target,
            detail=endpoint.error or "no connection",
            impact="This host could not be assessed.",
            remediation="Confirm the host is meant to serve TLS on this port.",
        ))
        return findings

    for version in endpoint.supported_versions:
        if version in tp.DEPRECATED_VERSIONS:
            name = tp.VERSION_NAMES[version]
            severity = "critical" if version == tp.SSL_3_0 else "high"
            findings.append(_finding(
                id="tls.deprecated-version", title=f"{name} is still accepted",
                severity=severity, category="tls", target=target,
                detail=f"The server negotiated {name}.",
                impact=f"{name} is formally deprecated and carries known protocol flaws (POODLE against SSLv3; BEAST and weak MAC construction in TLS 1.0/1.1). Accepting it lets an attacker who can influence the client force a downgrade to the weakest option offered.",
                remediation="Disable everything below TLS 1.2 and prefer TLS 1.3.",
                references=[REF_RFC8996],
                compliance=["PCI DSS 4.0 4.2.1", "NCSC TLS guidance"],
            ))

    if tp.TLS_1_3 not in endpoint.supported_versions and endpoint.supported_versions:
        findings.append(_finding(
            id="tls.no-tls13", title="TLS 1.3 is not supported",
            severity="medium", category="tls", target=target,
            detail=f"Supported: {', '.join(tp.VERSION_NAMES.get(v, str(v)) for v in endpoint.supported_versions)}.",
            impact="Beyond losing TLS 1.3's faster handshake and mandatory forward secrecy, this blocks the post-quantum path entirely: hybrid ML-KEM key exchange is defined only for TLS 1.3, so a server without it cannot become quantum-safe at all.",
            remediation="Enable TLS 1.3. This is the prerequisite for every other post-quantum step on this endpoint.",
            quantum_relevant=True,
            references=[REF_HYBRID],
        ))

    suites = endpoint.all_cipher_suites
    broken, no_fs, cbc = [], [], []
    for code in suites:
        suite = tp.CIPHER_SUITES.get(code)
        if not suite:
            continue
        if suite.auth == "ANON" or suite.cipher == "NULL" or suite.bits < 112:
            broken.append(suite.name)
        elif suite.cipher.startswith("RC4") or suite.cipher.startswith("3DES") or suite.cipher.startswith("DES"):
            broken.append(suite.name)
        elif not suite.forward_secret:
            no_fs.append(suite.name)
        elif not suite.aead:
            cbc.append(suite.name)

    if broken:
        findings.append(_finding(
            id="tls.broken-ciphers", title="Broken cipher suites are offered",
            severity="critical", category="tls", target=target,
            detail=f"{len(broken)} unsafe suite(s): {', '.join(sorted(set(broken))[:6])}.",
            impact="These suites are exploitable today. Export-grade and anonymous suites remove authentication or key strength entirely (FREAK, Logjam), RC4 has practical keystream biases, and 3DES is vulnerable to Sweet32 birthday attacks on long-lived connections.",
            remediation="Restrict the cipher list to AEAD suites: TLS 1.3 defaults plus ECDHE with AES-GCM or ChaCha20-Poly1305 on TLS 1.2.",
            evidence={"suites": sorted(set(broken))},
            compliance=["PCI DSS 4.0 4.2.1", "NIST SP 800-52r2"],
        ))

    if no_fs:
        findings.append(_finding(
            id="pqc.no-forward-secrecy", title="Cipher suites without forward secrecy are offered",
            severity="critical", category="post-quantum", target=target,
            detail=f"Static key-transport suite(s): {', '.join(sorted(set(no_fs))[:6])}.",
            impact="This is the single worst configuration for harvest-now-decrypt-later. With static RSA key transport the session key is encrypted to the certificate's long-term key, so an attacker who records traffic today and later recovers that one key -- by theft, or with a quantum computer via Shor's algorithm -- decrypts every past session at once. With forward secrecy each session uses ephemeral keys, so the same compromise yields nothing retrospective.",
            remediation="Disable all static RSA key-transport suites and require ECDHE. This is the highest-value change on this endpoint and it costs nothing.",
            quantum_relevant=True,
            evidence={"suites": sorted(set(no_fs))},
            references=[REF_NCSC],
            compliance=["NCSC 2035 migration", "PCI DSS 4.0 4.2.1"],
        ))

    if cbc:
        findings.append(_finding(
            id="tls.cbc-ciphers", title="CBC-mode cipher suites are offered",
            severity="low", category="tls", target=target,
            detail=f"{len(set(cbc))} CBC suite(s) available.",
            impact="CBC construction in TLS has repeatedly produced padding-oracle attacks (Lucky13 and successors). Exploitation is fiddly but the suites offer nothing an AEAD suite does not.",
            remediation="Prefer AEAD suites and remove CBC where clients allow.",
        ))

    return findings


# --- post-quantum readiness ------------------------------------------------


def pqc_findings(endpoint: TLSEndpoint, target_info: ScanTarget) -> List[Finding]:
    findings: List[Finding] = []
    label = endpoint.label

    if not endpoint.reachable:
        return findings

    if endpoint.pqc_groups:
        standard = [g for g in endpoint.pqc_groups if g in (0x11EB, 0x11EC, 0x11ED)]
        superseded = [g for g in endpoint.pqc_groups if g in (0x6399, 0x639A)]
        if standard:
            findings.append(_finding(
                id="pqc.hybrid-enabled", title="Hybrid post-quantum key exchange is enabled",
                severity="info", category="post-quantum", target=label,
                detail=f"Server accepts {', '.join(tp.group_name(g) for g in standard)}.",
                impact="Session keys on this endpoint are protected against harvest-now-decrypt-later. The hybrid construction keeps a classical component, so security holds even if a weakness is later found in ML-KEM.",
                remediation="No action needed. Keep the classical half in place until post-quantum implementations have a longer track record.",
                quantum_relevant=True,
                references=[REF_FIPS203, REF_HYBRID],
            ))
        if superseded and not standard:
            findings.append(_finding(
                id="pqc.superseded-draft", title="Only a superseded Kyber draft is supported",
                severity="medium", category="post-quantum", target=label,
                detail=f"Server accepts {', '.join(tp.group_name(g) for g in superseded)}.",
                impact="These draft groups predate FIPS 203 and are being removed from browsers, so post-quantum protection will silently lapse as clients drop them.",
                remediation="Upgrade to X25519MLKEM768 (0x11EC), the standardised group.",
                quantum_relevant=True,
                references=[REF_HYBRID],
            ))
    else:
        note = endpoint.pqc_probe_note
        if note:
            findings.append(_finding(
                id="pqc.probe-inconclusive", title="Post-quantum support could not be determined",
                severity="info", category="post-quantum", target=label,
                detail=f"Probe did not complete: {note}",
                impact="Quantum readiness for this endpoint is unknown rather than absent.",
                remediation="Re-run from a network that permits direct TLS connections.",
                quantum_relevant=True,
            ))
        else:
            findings.append(_finding(
                id="pqc.no-hybrid-key-exchange",
                title="No post-quantum key exchange offered",
                severity="high", category="post-quantum", target=label,
                detail=(
                    "Server negotiates only classical groups"
                    + (f" ({', '.join(tp.group_name(g) for g in endpoint.classical_groups[:4])})"
                       if endpoint.classical_groups else "")
                    + "."
                ),
                impact=(
                    "Every session key on this endpoint is established with elliptic-curve or "
                    "finite-field Diffie-Hellman, both of which Shor's algorithm solves outright. "
                    "An adversary recording this traffic now can decrypt it retrospectively once a "
                    f"quantum computer exists. Because the organisation's data must stay confidential "
                    f"for {target_info.data_shelf_life_years} years, traffic captured today is still "
                    "sensitive well past the point where it becomes readable."
                ),
                remediation=(
                    "Enable hybrid X25519MLKEM768 key exchange. On most estates this is a "
                    "configuration change rather than a project: OpenSSL 3.5+, BoringSSL, AWS-LC and "
                    "Go 1.24+ support it natively, and Cloudflare, AWS CloudFront and Fastly enable "
                    "it at the edge with a toggle. Clients that do not understand the group fall back "
                    "to classical automatically, so there is no compatibility cliff."
                ),
                quantum_relevant=True,
                evidence={"classical_groups": [tp.group_name(g) for g in endpoint.classical_groups]},
                references=[REF_FIPS203, REF_HYBRID, REF_NCSC],
                compliance=["NCSC 2031 high-priority migration", "NCSC 2035 completion", "NIST IR 8547"],
            ))

    # Grover only halves symmetric strength, so AES-128 is a real but much
    # smaller problem than the public-key exposure above.
    aes128_only = False
    suites = endpoint.all_cipher_suites
    if suites:
        strengths = [tp.CIPHER_SUITES[c].bits for c in suites if c in tp.CIPHER_SUITES]
        if strengths and max(strengths) < 256:
            aes128_only = True
    if aes128_only:
        findings.append(_finding(
            id="pqc.symmetric-128-only", title="No 256-bit symmetric cipher available",
            severity="medium", category="post-quantum", target=label,
            detail="Strongest symmetric key offered is 128-bit.",
            impact="Grover's algorithm reduces a 128-bit key to roughly 64 bits of effective strength, below the accepted floor. This is far less urgent than the public-key exposure, since Grover gives only a quadratic speed-up, but it should be closed as part of the same change.",
            remediation="Offer AES-256-GCM and prefer TLS_AES_256_GCM_SHA384 on TLS 1.3.",
            quantum_relevant=True,
            compliance=["CNSA 2.0"],
        ))

    if endpoint.interception_suspected:
        findings.append(_finding(
            id="tls.interception-detected", title="TLS interception detected on the path",
            severity="info", category="tls", target=label,
            detail="; ".join(endpoint.interception_reasons),
            impact="The certificate assessed here was minted by a middlebox, not the origin server. Findings for this endpoint describe the proxy's configuration. Note also that interception terminates TLS in the middle, so the proxy sees plaintext and its own onward cryptography becomes part of your risk surface.",
            remediation="Re-run this scan from a network without TLS inspection to assess the origin, and separately confirm the inspection appliance's own TLS configuration.",
        ))

    return findings


# --- HTTP ------------------------------------------------------------------


def http_findings(result: HTTPResult, host: str) -> List[Finding]:
    findings: List[Finding] = []
    if not result.reachable:
        return findings

    hsts = parse_hsts(result.header("strict-transport-security"))
    if not hsts.present:
        findings.append(_finding(
            id="http.no-hsts", title="HTTP Strict Transport Security is not set",
            severity="high", category="http", target=host,
            detail="No Strict-Transport-Security response header.",
            impact="A browser's first request to this site can be made over plain HTTP, which an attacker on the network path can intercept and keep on HTTP, stripping TLS before the user notices. HSTS is what closes that window.",
            remediation="Send `Strict-Transport-Security: max-age=31536000; includeSubDomains` and, once confident, submit the domain to the preload list.",
            references=[REF_HSTS],
            compliance=["OWASP ASVS 14.4", "NCSC web security guidance"],
        ))
    elif not hsts.adequate:
        findings.append(_finding(
            id="http.weak-hsts", title="HSTS max-age is too short",
            severity="medium", category="http", target=host,
            detail=f"max-age={hsts.max_age}; at least 31536000 (one year) is expected.",
            impact="A short window leaves users unprotected once it lapses, and the preload list will not accept the domain.",
            remediation="Raise max-age to 31536000 and add includeSubDomains.",
            references=[REF_HSTS],
        ))
    elif not hsts.include_subdomains:
        findings.append(_finding(
            id="http.hsts-no-subdomains", title="HSTS does not cover subdomains",
            severity="low", category="http", target=host,
            detail="includeSubDomains is absent.",
            impact="A subdomain served over plain HTTP can be used to set cookies for the parent domain.",
            remediation="Add includeSubDomains once every subdomain serves HTTPS.",
        ))

    if result.plaintext_port_open and result.http_to_https_redirect is False:
        findings.append(_finding(
            id="http.no-https-redirect", title="Port 80 serves content without redirecting to HTTPS",
            severity="high", category="http", target=host,
            detail="An HTTP request on port 80 returned content rather than a redirect.",
            impact="Traffic to this host can travel entirely in clear text, exposing credentials and session cookies to anyone on the path.",
            remediation="Return a 301 to the HTTPS URL for every request on port 80.",
        ))

    if not result.header("content-security-policy"):
        findings.append(_finding(
            id="http.no-csp", title="No Content-Security-Policy",
            severity="medium", category="http", target=host,
            detail="Content-Security-Policy header is absent.",
            impact="CSP is the main structural defence against cross-site scripting. Without it, any injection flaw anywhere in the application escalates to full script execution in your users' sessions.",
            remediation="Introduce a policy in report-only mode, tighten it against real traffic, then enforce.",
            compliance=["OWASP ASVS 14.4"],
        ))

    minor = {
        "x-content-type-options": ("MIME type sniffing is not disabled",
                                   "Browsers may reinterpret a response as script.",
                                   "Send `X-Content-Type-Options: nosniff`."),
        "x-frame-options": ("Framing is not restricted",
                            "The site can be embedded and clickjacked.",
                            "Send `X-Frame-Options: DENY` or a CSP frame-ancestors directive."),
        "referrer-policy": ("Referrer policy is not set",
                            "Full URLs, including any tokens in them, leak to third-party sites.",
                            "Send `Referrer-Policy: strict-origin-when-cross-origin`."),
        "permissions-policy": ("Permissions policy is not set",
                               "Embedded content may request camera, microphone or geolocation access.",
                               "Send a Permissions-Policy header disabling features you do not use."),
    }
    missing = [h for h in minor if not result.header(h)]
    if missing:
        findings.append(_finding(
            id="http.missing-headers", title=f"{len(missing)} security header(s) missing",
            severity="low", category="http", target=host,
            detail="; ".join(minor[h][0] for h in missing),
            impact=" ".join(minor[h][1] for h in missing),
            remediation=" ".join(minor[h][2] for h in missing),
            evidence={"missing": missing},
        ))

    disclosure = result.disclosure
    if disclosure:
        findings.append(_finding(
            id="http.version-disclosure", title="Response headers disclose software versions",
            severity="low", category="http", target=host,
            detail="; ".join(f"{k}: {v}" for k, v in list(disclosure.items())[:4]),
            impact="Precise version numbers let an attacker skip reconnaissance and go straight to matching public exploits.",
            remediation="Suppress or genericise these headers at the web server or load balancer.",
        ))

    weak_cookies = []
    for cookie in result.cookies:
        flags = parse_cookie_flags(cookie)
        problems = []
        if not flags["secure"]:
            problems.append("no Secure")
        if not flags["httponly"]:
            problems.append("no HttpOnly")
        if not flags["samesite"]:
            problems.append("no SameSite")
        if problems:
            weak_cookies.append(f"{flags['name']} ({', '.join(problems)})")
    if weak_cookies:
        findings.append(_finding(
            id="http.insecure-cookies", title="Cookies set without full protection flags",
            severity="medium", category="http", target=host,
            detail="; ".join(weak_cookies[:5]),
            impact="Without Secure a cookie can be sent over plain HTTP; without HttpOnly it is readable by injected script; without SameSite it rides along with cross-site requests, enabling CSRF.",
            remediation="Set Secure, HttpOnly and SameSite=Lax (or Strict) on all session cookies.",
            compliance=["OWASP ASVS 3.4"],
        ))

    return findings


# --- DNS -------------------------------------------------------------------


def dns_findings(posture: DNSPosture) -> List[Finding]:
    findings: List[Finding] = []
    if not posture.available:
        findings.append(_finding(
            id="dns.unavailable", title="DNS checks could not run",
            severity="info", category="dns", target=posture.domain,
            detail="No DNS resolver was reachable from the scanning host.",
            impact="CAA, DNSSEC, SPF and DMARC posture is unknown, not absent.",
            remediation="Re-run from a network that permits outbound DNS.",
        ))
        return findings

    if not posture.caa_records:
        findings.append(_finding(
            id="dns.no-caa", title="No CAA records published",
            severity="medium", category="dns", target=posture.domain,
            detail="No Certification Authority Authorization records found.",
            impact="Any public CA may issue a certificate for this domain. CAA is the control that stops an attacker who compromises a domain validation step at some CA you have never used from getting a valid certificate for your name.",
            remediation="Publish CAA records naming only the CAs you use, and add an iodef address so unauthorised attempts are reported to you.",
            compliance=["CA/Browser Forum BR 3.2.2.8"],
        ))

    if not posture.dnssec:
        findings.append(_finding(
            id="dns.no-dnssec", title="DNSSEC is not enabled",
            severity="low", category="dns", target=posture.domain,
            detail="No DS or DNSKEY records found.",
            impact="DNS answers for this domain cannot be authenticated, so cache poisoning and spoofing remain possible. This also blocks DANE, which is one route to authenticating mail transport.",
            remediation="Enable DNSSEC signing at your DNS provider and publish the DS record at the registrar.",
        ))

    if posture.mx_records and "dmarc" not in posture.undetermined:
        policy = posture.dmarc_policy
        if not posture.dmarc:
            findings.append(_finding(
                id="dns.no-dmarc", title="No DMARC record",
                severity="high", category="dns", target=posture.domain,
                detail="No _dmarc TXT record found, but the domain accepts mail.",
                impact="Anyone can send email that appears to come from this domain. This is the mechanism behind most invoice fraud and business email compromise, and it damages a brand faster than almost any technical flaw.",
                remediation="Publish DMARC at p=none with reporting, review the reports, then move to p=quarantine and p=reject.",
                compliance=["NCSC Mail Check", "Cyber Essentials"],
            ))
        elif policy == "none":
            findings.append(_finding(
                id="dns.dmarc-monitoring-only", title="DMARC is set to monitoring only",
                severity="medium", category="dns", target=posture.domain,
                detail=f"Policy p=none. Record: {posture.dmarc[:120]}",
                impact="Spoofed mail is reported but still delivered, so the protection is observational.",
                remediation="Once reports look clean, move to p=quarantine and then p=reject.",
            ))

    if posture.mx_records and not posture.spf and "spf" not in posture.undetermined:
        findings.append(_finding(
            id="dns.no-spf", title="No SPF record",
            severity="medium", category="dns", target=posture.domain,
            detail="No v=spf1 TXT record found.",
            impact="Receiving servers have no list of hosts authorised to send for this domain, weakening DMARC alignment.",
            remediation="Publish an SPF record ending in -all once every legitimate sender is listed.",
        ))

    return findings


# --- licences --------------------------------------------------------------


def licence_findings(scan: LicenceScan, records: List[LicenceRecord]) -> List[Finding]:
    findings: List[Finding] = []
    host = scan.host

    for record in records:
        if record.category == "strong-copyleft":
            severity = "critical" if record.licence in ("AGPL-3.0", "SSPL-1.0") else "high"
            findings.append(_finding(
                id="licence.copyleft-obligation",
                title=f"{record.component} is {record.licence}",
                severity=severity, category="licence", target=host,
                detail=f"{record.component} {record.version or ''} detected via {record.evidence}.".strip(),
                impact=f"{record.obligation} For a commercial product this can mean publishing source you intended to keep proprietary.",
                remediation=f"Confirm how {record.component} is used. If it is modified or linked into your product, either isolate it behind a service boundary, obtain a commercial licence, or replace it with a permissively licensed equivalent. Record the decision.",
                evidence={"licence": record.licence, "component": record.component},
                compliance=["ISO 5230 (OpenChain)"],
            ))
        elif record.category == "proprietary" and record.risk in ("high", "critical"):
            findings.append(_finding(
                id="licence.commercial-restriction",
                title=f"{record.component} carries commercial-use restrictions",
                severity="high", category="licence", target=host,
                detail=f"{record.component} is licensed {record.licence}.",
                impact=record.obligation,
                remediation=f"Verify a paid licence is held for {record.component}, or replace it.",
            ))

    eol = [c for c in scan.components if c.end_of_life]
    if eol:
        findings.append(_finding(
            id="licence.end-of-life-component",
            title=f"{len(eol)} end-of-life component(s) in use",
            severity="high", category="licence", target=host,
            detail="; ".join(
                f"{c.name} {c.version or ''}".strip() + (f" -- {c.note}" if c.note else "")
                for c in eol[:4]
            ),
            impact="Unsupported components receive no security patches, so any vulnerability found from now on stays open permanently.",
            remediation="Plan migration to a supported version or replacement. Treat this as scheduled work, not a backlog item.",
            evidence={"components": [f"{c.name} {c.version or ''}".strip() for c in eol]},
            compliance=["Cyber Essentials (patching)", "NIS2 Art.21"],
        ))

    unknown = [r for r in records if r.category == "unknown"]
    if len(unknown) >= 3:
        findings.append(_finding(
            id="licence.undetermined",
            title=f"{len(unknown)} component(s) with an undetermined licence",
            severity="medium", category="licence", target=host,
            detail=", ".join(r.component for r in unknown[:8]),
            impact="A dependency with no established licence grant is a legal liability by default: absent an explicit licence, you have no right to use it at all. It also blocks any customer or acquirer due-diligence process.",
            remediation="Resolve each licence from its package registry and record the result in a software bill of materials.",
        ))

    if scan.exposed_manifests:
        findings.append(_finding(
            id="licence.exposed-manifest",
            title="Dependency manifest is publicly readable",
            severity="medium", category="licence", target=host,
            detail=f"Readable: {', '.join(scan.exposed_manifests)}.",
            impact="The manifest lists your exact dependency versions, letting an attacker match them against public vulnerability databases without touching your systems.",
            remediation="Block these paths at the web server; they should never be served from the document root.",
        ))

    return findings


# --- governance ------------------------------------------------------------


def governance_findings(target: ScanTarget, assets: List[CryptoAsset]) -> List[Finding]:
    """Findings about the migration programme rather than a specific host."""
    findings: List[Finding] = []

    vulnerable = [a for a in assets if not a.quantum_safe and a.broken_by == "Shor"]
    if vulnerable:
        distinct = sorted({a.name for a in vulnerable})
        findings.append(_finding(
            id="governance.cryptographic-inventory",
            title="Quantum-vulnerable cryptography is in use across the estate",
            severity="medium", category="governance", target=target.domain,
            detail=f"{len(vulnerable)} uses of {len(distinct)} quantum-vulnerable algorithm(s): {', '.join(distinct[:6])}.",
            impact="Both NCSC and NIST make a cryptographic inventory the first step of migration, for the practical reason that you cannot replace what you cannot enumerate. This scan covers the externally visible estate only; internal systems, VPNs, code signing, backups and hardware security modules are not visible from outside and are usually where the difficult cases live.",
            remediation="Extend this inventory inward: catalogue certificates, key stores, VPN and SSH configuration, signing keys and supplier dependencies. NCSC expects discovery to be complete by 2028.",
            quantum_relevant=True,
            references=[REF_NCSC],
            compliance=["NCSC 2028 discovery", "NIST SP 1800-38"],
        ))

    return findings
