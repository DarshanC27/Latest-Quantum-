"""The remediation plan, and the tooling that implements it.

Ordering is by benefit per unit of effort rather than by severity alone.
A configuration change that removes a critical exposure this afternoon
outranks a certificate authority migration that removes a different one in
two years, and a plan that does not say so is not a plan.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, NamedTuple, Sequence

from ..model import Finding


class Tool(NamedTuple):
    name: str
    category: str
    supports: str
    availability: str
    note: str
    url: str


# Software that can implement post-quantum cryptography today. Restricted
# to things that are shipping and usable, not research code.
PQC_TOOLING: Dict[str, List[Tool]] = {
    "TLS libraries": [
        Tool("OpenSSL 3.5 LTS", "library", "ML-KEM, ML-DSA, SLH-DSA, hybrid TLS groups",
             "stable, long-term support",
             "The default path for most Linux estates. Native support means no "
             "third-party provider to maintain. Enable groups with "
             "`-groups X25519MLKEM768:X25519:P-256`.",
             "https://openssl-library.org/"),
        Tool("AWS-LC", "library", "X25519MLKEM768, ML-KEM",
             "stable",
             "FIPS-validated branch available; used across AWS services.",
             "https://github.com/aws/aws-lc"),
        Tool("BoringSSL", "library", "X25519MLKEM768",
             "stable",
             "What Chrome ships. Useful as the compatibility reference.",
             "https://boringssl.googlesource.com/boringssl"),
        Tool("liboqs / oqs-provider", "library", "Full NIST PQC suite plus alternates",
             "reference implementation",
             "Open Quantum Safe. The right choice for experimentation and for "
             "algorithms not yet in mainstream libraries; treat as pre-production "
             "for anything protecting real data.",
             "https://openquantumsafe.org/"),
        Tool("wolfSSL", "library", "ML-KEM, ML-DSA, LMS, XMSS",
             "stable, commercial",
             "Designed for embedded and constrained devices, which is where "
             "PQC's larger keys hurt most.",
             "https://www.wolfssl.com/"),
        Tool("Bouncy Castle", "library", "ML-KEM, ML-DSA, SLH-DSA, LMS",
             "stable",
             "The practical route for Java and .NET estates.",
             "https://www.bouncycastle.org/"),
    ],
    "Runtimes and platforms": [
        Tool("Go 1.24+", "runtime", "crypto/mlkem, X25519MLKEM768 by default in crypto/tls",
             "stable",
             "Go enables hybrid key exchange automatically. Upgrading the "
             "toolchain and rebuilding is often the entire migration for a Go service.",
             "https://go.dev/doc/"),
        Tool("Java 24+", "runtime", "ML-KEM (JEP 496), ML-DSA (JEP 497)",
             "stable",
             "Standard-library support removes the need for a third-party provider.",
             "https://openjdk.org/"),
        Tool("OpenSSH 9.x / 10", "protocol", "sntrup761x25519, mlkem768x25519",
             "stable",
             "OpenSSH has defaulted to post-quantum hybrid key exchange since 9.0 "
             "and warns on classical-only connections in 10. Often an estate's "
             "first quantum-safe protocol, already deployed without anyone noticing.",
             "https://www.openssh.com/"),
        Tool("strongSwan 6", "protocol", "ML-KEM in IKEv2",
             "stable",
             "For site-to-site VPNs. RFC 8784 post-quantum pre-shared keys are a "
             "useful interim measure where endpoints cannot be upgraded together.",
             "https://strongswan.org/"),
    ],
    "Edge and infrastructure": [
        Tool("Cloudflare", "CDN", "X25519MLKEM768 at the edge",
             "generally available",
             "Enabled by default for inbound connections. The fastest way to "
             "protect a public web estate: no application change at all.",
             "https://blog.cloudflare.com/pq-2024/"),
        Tool("AWS (CloudFront, ELB, KMS, ACM)", "cloud",
             "Hybrid TLS termination; ML-DSA in KMS",
             "generally available",
             "Hybrid key exchange on supported security policies. Check the "
             "policy attached to each listener; it is not always the default.",
             "https://aws.amazon.com/security/post-quantum-cryptography/"),
        Tool("nginx with OpenSSL 3.5", "web server", "Hybrid groups via ssl_ecdh_curve",
             "stable",
             "Set `ssl_ecdh_curve X25519MLKEM768:X25519:secp256r1;` and confirm "
             "nginx is linked against 3.5 rather than the system 3.0.",
             "https://nginx.org/"),
        Tool("HashiCorp Vault", "key management", "Managed keys, rotation, short-lived certificates",
             "stable",
             "Crypto-agility is mostly a key management problem. Automated issuance "
             "is what makes an algorithm change a configuration change.",
             "https://developer.hashicorp.com/vault"),
    ],
    "Discovery and inventory": [
        Tool("CycloneDX 1.6 CBOM", "standard", "Cryptographic bill of materials",
             "published standard",
             "The interchange format for cryptographic inventory. This scanner "
             "exports it directly, so results can feed an existing SBOM pipeline.",
             "https://cyclonedx.org/capabilities/cbom/"),
        Tool("IBM CBOMkit", "scanner", "Source and runtime cryptography discovery",
             "open source",
             "Static analysis across a codebase, which complements the external "
             "view this scanner provides.",
             "https://github.com/PQCA/cbomkit"),
        Tool("sslyze / testssl.sh", "scanner", "Deep TLS configuration audit",
             "open source",
             "Well-established second opinion on TLS configuration specifically.",
             "https://github.com/nabla-c0d3/sslyze"),
    ],
}


@dataclass
class Action:
    """One remediation step."""

    priority: int
    title: str
    why: str
    how: str
    effort: str  # hours | days | weeks | months
    phase: str  # immediate | 2028 | 2031 | 2035
    addresses: List[str] = field(default_factory=list)
    tools: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "priority": self.priority, "title": self.title, "why": self.why,
            "how": self.how, "effort": self.effort, "phase": self.phase,
            "addresses": self.addresses, "tools": self.tools,
        }


# Templates keyed by finding id. Effort is the realistic engineering cost
# for a typical estate, not a best case.
_TEMPLATES = {
    "pqc.no-forward-secrecy": dict(
        title="Disable static RSA key exchange and require forward secrecy",
        why="Without forward secrecy, one future key compromise decrypts every session "
            "ever recorded. This is the largest harvest-now-decrypt-later exposure and "
            "the cheapest to remove.",
        how="Remove all TLS_RSA_* suites from the server cipher list, leaving ECDHE "
            "suites only. No client in current use requires static RSA.",
        effort="hours", phase="immediate",
        tools=["nginx with OpenSSL 3.5", "AWS (CloudFront, ELB, KMS, ACM)"],
    ),
    "tls.broken-ciphers": dict(
        title="Remove broken cipher suites",
        why="These are exploitable with conventional hardware today, independently of "
            "any quantum consideration.",
        how="Restrict to AEAD suites: TLS 1.3 defaults, plus ECDHE with AES-GCM or "
            "ChaCha20-Poly1305 for TLS 1.2.",
        effort="hours", phase="immediate",
    ),
    "tls.deprecated-version": dict(
        title="Disable TLS 1.0, TLS 1.1 and SSLv3",
        why="Deprecated by RFC 8996 and disallowed under PCI DSS. Offering them lets an "
            "attacker downgrade clients to the weakest option available.",
        how="Set the minimum protocol version to TLS 1.2. Check analytics for genuinely "
            "legacy clients first, but the population is now negligible.",
        effort="hours", phase="immediate",
    ),
    "certificate.expired": dict(
        title="Renew the expired certificate and automate renewal",
        why="This is a live outage for any client that validates certificates.",
        how="Reissue now, then adopt ACME automation so renewal is not a manual task.",
        effort="hours", phase="immediate",
    ),
    "certificate.weak-key": dict(
        title="Reissue certificates with adequate key strength",
        why="Keys below 2048 bits are breakable with conventional resources.",
        how="Reissue at RSA-3072 or ECDSA P-256, and shorten the certificate lifetime.",
        effort="days", phase="immediate",
    ),
    "certificate.broken-signature-hash": dict(
        title="Reissue certificates signed with SHA-1 or MD5",
        why="Collision attacks against these hashes are practical today, so certificate "
            "forgery does not require a quantum computer.",
        how="Reissue with SHA-256 or SHA-384 from a current CA.",
        effort="days", phase="immediate",
    ),
    "pqc.no-hybrid-key-exchange": dict(
        title="Enable hybrid post-quantum key exchange (X25519MLKEM768)",
        why="Protects session keys against retrospective decryption. The hybrid design "
            "keeps a classical component, so it is safe to deploy now.",
        how="Upgrade to OpenSSL 3.5+, Go 1.24+, or enable the option at your CDN, then "
            "add X25519MLKEM768 to the offered groups ahead of the classical ones. "
            "Clients that do not recognise it negotiate classically, so rollout is "
            "non-breaking.",
        effort="days", phase="2031",
        tools=["OpenSSL 3.5 LTS", "Cloudflare", "Go 1.24+", "nginx with OpenSSL 3.5"],
    ),
    "tls.no-tls13": dict(
        title="Enable TLS 1.3",
        why="Hybrid post-quantum key exchange is defined only for TLS 1.3, so this "
            "blocks the entire migration on this endpoint.",
        how="Upgrade the TLS terminator and enable TLS 1.3 alongside 1.2.",
        effort="days", phase="immediate",
        tools=["OpenSSL 3.5 LTS", "nginx with OpenSSL 3.5"],
    ),
    "pqc.classical-certificate-key": dict(
        title="Plan certificate migration to ML-DSA",
        why="Server authentication keys become forgeable once a quantum computer exists. "
            "This depends on CA support, so it needs lead time rather than urgency.",
        how="Track your CA's post-quantum roadmap, shorten certificate lifetimes now to "
            "gain agility, and pilot ML-DSA certificates in a non-production estate.",
        effort="months", phase="2035",
        tools=["Bouncy Castle", "OpenSSL 3.5 LTS", "HashiCorp Vault"],
    ),
    "pqc.symmetric-128-only": dict(
        title="Offer AES-256 alongside AES-128",
        why="Grover's algorithm halves symmetric strength, taking AES-128 to roughly 64 "
            "effective bits.",
        how="Add AES-256-GCM suites and prefer TLS_AES_256_GCM_SHA384 on TLS 1.3.",
        effort="hours", phase="2031",
    ),
    "governance.cryptographic-inventory": dict(
        title="Build a cryptographic inventory covering internal systems",
        why="NCSC requires discovery to be complete by 2028, and no migration can be "
            "planned without it. The externally visible estate is the easy part.",
        how="Catalogue certificates, key stores, VPN and SSH configuration, code signing, "
            "database and backup encryption, and supplier dependencies. Export to CBOM "
            "and keep it current.",
        effort="months", phase="2028",
        tools=["CycloneDX 1.6 CBOM", "IBM CBOMkit"],
    ),
    "http.no-hsts": dict(
        title="Enable HTTP Strict Transport Security",
        why="Closes the plaintext window on a user's first request, which is where TLS "
            "stripping attacks operate.",
        how="Send `Strict-Transport-Security: max-age=31536000; includeSubDomains`, then "
            "consider preload.",
        effort="hours", phase="immediate",
    ),
    "http.no-https-redirect": dict(
        title="Redirect all plaintext HTTP to HTTPS",
        why="Credentials and session cookies can otherwise travel in clear text.",
        how="Return 301 to the HTTPS URL for every request on port 80.",
        effort="hours", phase="immediate",
    ),
    "http.no-csp": dict(
        title="Introduce a Content-Security-Policy",
        why="The main structural mitigation for cross-site scripting.",
        how="Deploy in report-only mode, tune against real traffic, then enforce.",
        effort="weeks", phase="immediate",
    ),
    "http.insecure-cookies": dict(
        title="Set Secure, HttpOnly and SameSite on session cookies",
        why="Protects session tokens from plaintext transmission, script access and "
            "cross-site request forgery.",
        how="Update the session cookie configuration in the application framework.",
        effort="hours", phase="immediate",
    ),
    "dns.no-caa": dict(
        title="Publish CAA records",
        why="Restricts which certificate authorities may issue for your domain, "
            "limiting the impact of a validation failure at any CA.",
        how="Publish CAA records for your CAs plus an iodef reporting address.",
        effort="hours", phase="immediate",
    ),
    "dns.no-dmarc": dict(
        title="Publish a DMARC policy",
        why="Without it, anyone can send mail appearing to come from your domain.",
        how="Start at p=none with aggregate reporting, then progress to quarantine "
            "and reject.",
        effort="days", phase="immediate",
    ),
    "licence.copyleft-obligation": dict(
        title="Resolve copyleft licence obligations",
        why="Strong copyleft, and AGPL in particular, can require publishing source you "
            "intended to keep proprietary. The AGPL network clause triggers on running "
            "the software as a service, with no distribution needed.",
        how="Establish how each component is used, then isolate, replace, or obtain a "
            "commercial licence. Record the decision for due diligence.",
        effort="weeks", phase="immediate",
    ),
    "licence.end-of-life-component": dict(
        title="Replace end-of-life components",
        why="Unsupported software receives no security patches, so every future "
            "vulnerability stays open.",
        how="Plan migration to supported versions as scheduled work.",
        effort="weeks", phase="immediate",
    ),
    "licence.undetermined": dict(
        title="Establish licences for undetermined dependencies",
        why="Without an explicit grant the default position is that you have no right to "
            "use the component at all, and it blocks customer due diligence.",
        how="Resolve each licence from its registry and record it in an SBOM.",
        effort="days", phase="immediate",
    ),
    "licence.exposed-manifest": dict(
        title="Stop serving dependency manifests publicly",
        why="They enumerate exact versions for an attacker to match against known "
            "vulnerabilities.",
        how="Block these paths at the web server.",
        effort="hours", phase="immediate",
    ),
}

# Effort ordering, used to break ties in favour of quick wins.
_EFFORT_RANK = {"hours": 0, "days": 1, "weeks": 2, "months": 3}


def build_plan(findings: Sequence[Finding]) -> List[Action]:
    """Produce a deduplicated, prioritised remediation plan."""
    by_id: Dict[str, List[Finding]] = {}
    for finding in findings:
        by_id.setdefault(finding.id, []).append(finding)

    actions: List[Action] = []
    for finding_id, group in by_id.items():
        template = _TEMPLATES.get(finding_id)
        if template is None:
            continue
        worst = min(f.rank for f in group)
        targets = sorted({f.target for f in group})
        actions.append(
            Action(
                priority=0,
                title=template["title"],
                why=template["why"],
                how=template["how"],
                effort=template["effort"],
                phase=template["phase"],
                addresses=[
                    f"{group[0].title} on {len(targets)} host(s): "
                    + ", ".join(targets[:4])
                    + (" ..." if len(targets) > 4 else "")
                ],
                tools=list(template.get("tools", [])),
            )
        )
        actions[-1].__dict__["_rank"] = worst

    # Severity first, then cheapest. A critical fixed in an afternoon should
    # never sit below a critical that takes a quarter.
    actions.sort(key=lambda a: (a.__dict__.get("_rank", 4), _EFFORT_RANK.get(a.effort, 9)))
    for index, action in enumerate(actions, start=1):
        action.priority = index
        action.__dict__.pop("_rank", None)
    return actions


def tools_for(actions: Sequence[Action]) -> List[Tool]:
    """The subset of the catalogue this plan actually calls for."""
    wanted = {name for action in actions for name in action.tools}
    return [
        tool
        for tools in PQC_TOOLING.values()
        for tool in tools
        if tool.name in wanted
    ]
