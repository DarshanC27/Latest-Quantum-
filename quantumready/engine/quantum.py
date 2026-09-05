"""Quantum classification of cryptographic algorithms, and Mosca's theorem.

Two quantum algorithms matter, and they matter very differently.

Shor's algorithm solves integer factorisation and discrete logarithms in
polynomial time. Every public-key algorithm in mainstream use -- RSA, DSA,
Diffie-Hellman, ECDSA, ECDH, EdDSA -- rests on exactly those problems, so
against a cryptographically relevant quantum computer their security is
not reduced, it is eliminated. Using a larger key does not help: RSA-4096
falls to the same algorithm as RSA-2048, just slightly later.

Grover's algorithm gives a quadratic speed-up on unstructured search,
which halves the effective strength of a symmetric cipher. That is a
manageable problem: AES-128 drops to 64 bits and must be replaced, while
AES-256 drops to 128 bits and remains sound. This is why the migration is
about public-key cryptography and not about ciphers.

The practical consequence is harvest-now-decrypt-later. An adversary
recording traffic today can decrypt it whenever a CRQC arrives, so any
data whose confidentiality must outlast that date is already exposed --
which is the question Mosca's inequality formalises.
"""

from __future__ import annotations

import datetime as _dt
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

# NIST SP 800-57 Part 1 Rev. 5, Table 2: comparable classical strengths.
_RSA_STRENGTH = (
    (1024, 80),
    (2048, 112),
    (3072, 128),
    (7680, 192),
    (15360, 256),
)

# Algorithm families whose hard problem Shor's algorithm solves outright.
SHOR_VULNERABLE = frozenset(
    {"RSA", "RSASSA-PSS", "DSA", "DH", "EC", "ECDSA", "ECDH", "ECDHE",
     "Ed25519", "Ed448", "X25519", "X448"}
)

# NIST post-quantum standards, by the FIPS that specifies each.
PQC_STANDARDS = {
    "ML-KEM-512": ("FIPS 203", 1),
    "ML-KEM-768": ("FIPS 203", 3),
    "ML-KEM-1024": ("FIPS 203", 5),
    "ML-DSA-44": ("FIPS 204", 2),
    "ML-DSA-65": ("FIPS 204", 3),
    "ML-DSA-87": ("FIPS 204", 5),
    "SLH-DSA-SHA2-128s": ("FIPS 205", 1),
    "SLH-DSA-SHA2-128f": ("FIPS 205", 1),
    "SLH-DSA-SHA2-192s": ("FIPS 205", 3),
    "SLH-DSA-SHA2-192f": ("FIPS 205", 3),
    "SLH-DSA-SHA2-256s": ("FIPS 205", 5),
    "SLH-DSA-SHA2-256f": ("FIPS 205", 5),
}

# What each vulnerable algorithm should become. Signature algorithms move to
# ML-DSA, key establishment to a hybrid ML-KEM group.
REPLACEMENTS = {
    "RSA": "ML-DSA-65 for signing, ML-KEM-768 for key establishment",
    "RSASSA-PSS": "ML-DSA-65",
    "DSA": "ML-DSA-65",
    "EC": "ML-DSA-65 (signing) or hybrid X25519MLKEM768 (key exchange)",
    "ECDSA": "ML-DSA-65",
    "ECDH": "X25519MLKEM768 hybrid key exchange",
    "ECDHE": "X25519MLKEM768 hybrid key exchange",
    "Ed25519": "ML-DSA-65",
    "Ed448": "ML-DSA-87",
    "X25519": "X25519MLKEM768 hybrid key exchange",
    "X448": "SecP384r1MLKEM1024 hybrid key exchange",
    "DH": "ML-KEM-768",
    "AES-128": "AES-256",
    "3DES": "AES-256-GCM",
    "SHA-1": "SHA-384",
    "MD5": "SHA-384",
}


def rsa_classical_bits(modulus_bits: int) -> int:
    """Comparable symmetric strength of an RSA modulus, interpolated."""
    if modulus_bits <= 0:
        return 0
    if modulus_bits <= _RSA_STRENGTH[0][0]:
        # Below 1024 bits, scale down rather than claiming a floor of 80.
        return max(1, int(80 * modulus_bits / 1024))
    for (low_bits, low_strength), (high_bits, high_strength) in zip(
        _RSA_STRENGTH, _RSA_STRENGTH[1:]
    ):
        if modulus_bits <= high_bits:
            span = high_bits - low_bits
            position = (modulus_bits - low_bits) / span
            return int(low_strength + position * (high_strength - low_strength))
    return 256


@dataclass
class QuantumAssessment:
    """What a quantum adversary does to one algorithm."""

    algorithm: str
    classical_bits: int
    quantum_bits: int
    quantum_safe: bool
    broken_by: Optional[str]  # "Shor" | "Grover" | None
    rationale: str
    replacement: Optional[str] = None


def assess_public_key(algorithm: str, size_bits: int, curve: Optional[str] = None) -> QuantumAssessment:
    """Classify a public key. Shor's algorithm reduces these to zero."""
    if algorithm in PQC_STANDARDS:
        standard, level = PQC_STANDARDS[algorithm]
        return QuantumAssessment(
            algorithm=algorithm,
            classical_bits=size_bits or 128,
            quantum_bits=128 if level >= 3 else 128,
            quantum_safe=True,
            broken_by=None,
            rationale=f"standardised in {standard} at NIST security category {level}",
        )

    if algorithm in ("RSA", "RSASSA-PSS"):
        classical = rsa_classical_bits(size_bits)
        return QuantumAssessment(
            algorithm=f"RSA-{size_bits}",
            classical_bits=classical,
            quantum_bits=0,
            quantum_safe=False,
            broken_by="Shor",
            rationale=(
                f"RSA-{size_bits} offers about {classical} bits classically, but "
                "Shor's algorithm factors the modulus in polynomial time, "
                "leaving no residual security against a CRQC"
            ),
            replacement=REPLACEMENTS["RSA"],
        )

    if algorithm in ("EC", "ECDSA", "ECDH", "ECDHE"):
        classical = size_bits // 2 if size_bits else 0
        label = f"{algorithm} {curve}" if curve else algorithm
        return QuantumAssessment(
            algorithm=label,
            classical_bits=classical,
            quantum_bits=0,
            quantum_safe=False,
            broken_by="Shor",
            rationale=(
                f"{label} offers about {classical} bits classically, but Shor's "
                "algorithm solves the elliptic-curve discrete logarithm, and "
                "elliptic curves fall to a CRQC sooner than equivalent RSA "
                "because they need far fewer logical qubits"
            ),
            replacement=REPLACEMENTS.get("ECDSA"),
        )

    if algorithm in ("Ed25519", "Ed448", "X25519", "X448"):
        classical = 128 if algorithm in ("Ed25519", "X25519") else 224
        return QuantumAssessment(
            algorithm=algorithm,
            classical_bits=classical,
            quantum_bits=0,
            quantum_safe=False,
            broken_by="Shor",
            rationale=(
                f"{algorithm} is a strong classical choice at about {classical} "
                "bits, but it is still elliptic-curve based and Shor's "
                "algorithm applies unchanged"
            ),
            replacement=REPLACEMENTS.get(algorithm),
        )

    if algorithm == "DSA":
        classical = rsa_classical_bits(size_bits)
        return QuantumAssessment(
            algorithm=f"DSA-{size_bits}",
            classical_bits=classical,
            quantum_bits=0,
            quantum_safe=False,
            broken_by="Shor",
            rationale="finite-field discrete logarithm, solved by Shor's algorithm",
            replacement=REPLACEMENTS["DSA"],
        )

    return QuantumAssessment(
        algorithm=algorithm,
        classical_bits=size_bits,
        quantum_bits=0,
        quantum_safe=False,
        broken_by=None,
        rationale="algorithm not recognised; classify it manually",
    )


def assess_symmetric(cipher: str, bits: int) -> QuantumAssessment:
    """Classify a symmetric cipher. Grover halves the effective key size."""
    quantum_bits = bits // 2
    safe = quantum_bits >= 128
    if bits == 0:
        return QuantumAssessment(
            algorithm=cipher, classical_bits=0, quantum_bits=0, quantum_safe=False,
            broken_by=None, rationale="no encryption at all",
        )
    return QuantumAssessment(
        algorithm=cipher,
        classical_bits=bits,
        quantum_bits=quantum_bits,
        quantum_safe=safe,
        broken_by=None if safe else "Grover",
        rationale=(
            f"Grover's algorithm reduces a {bits}-bit key to about "
            f"{quantum_bits} bits of effective strength"
            + ("; this remains sound" if safe else ", which is below the 128-bit floor")
        ),
        replacement=None if safe else "AES-256-GCM",
    )


def assess_hash(name: str) -> QuantumAssessment:
    """Classify a hash function used for signing."""
    sizes = {"MD2": 128, "MD4": 128, "MD5": 128, "SHA-1": 160, "SHA-224": 224,
             "SHA-256": 256, "SHA-384": 384, "SHA-512": 512}
    bits = sizes.get(name, 0)
    classically_broken = name in ("MD2", "MD4", "MD5", "SHA-1")
    quantum_bits = bits // 2
    return QuantumAssessment(
        algorithm=name,
        classical_bits=0 if classically_broken else bits // 2,
        quantum_bits=0 if classically_broken else quantum_bits,
        quantum_safe=not classically_broken and quantum_bits >= 128,
        broken_by=None if classically_broken else ("Grover" if quantum_bits < 128 else None),
        rationale=(
            f"{name} is already broken against collision attacks classically; "
            "a quantum adversary is not required"
            if classically_broken
            else f"Grover's algorithm reduces preimage resistance to about "
                 f"{quantum_bits} bits"
        ),
        replacement="SHA-384" if classically_broken else None,
    )


# --- Mosca's theorem -------------------------------------------------------


@dataclass
class MoscaResult:
    """The X + Y > Z assessment for an organisation."""

    shelf_life_years: int  # X: how long the data must stay confidential
    migration_years: int  # Y: how long a full migration takes
    years_to_quantum: float  # Z: time until a CRQC is assumed to exist
    quantum_year: int
    at_risk: bool
    exposure_years: float  # by how much X + Y overruns Z
    deadline_year: int  # the year migration must have started by
    verdict: str
    explanation: str
    assumptions: List[str] = field(default_factory=list)

    @property
    def formula(self) -> str:
        total = self.shelf_life_years + self.migration_years
        relation = ">" if self.at_risk else "<="
        return (
            f"X({self.shelf_life_years}) + Y({self.migration_years}) = {total} "
            f"{relation} Z({self.years_to_quantum:g})"
        )


# Expert-survey positions on when a cryptographically relevant quantum
# computer arrives. These are judgement calls, not measurements, so the
# scenario is always stated alongside any conclusion drawn from it.
QUANTUM_SCENARIOS = {
    "conservative": (2030, "an early breakthrough; the planning assumption for "
                           "national security and long-lived secrets"),
    "central": (2035, "the mainstream planning date, and the year by which the "
                      "UK NCSC requires migration to be complete"),
    "optimistic": (2040, "slower progress on error correction than currently "
                         "projected"),
}


def assess_mosca(
    shelf_life_years: int,
    migration_years: int,
    *,
    scenario: str = "central",
    quantum_year: Optional[int] = None,
    now: Optional[_dt.datetime] = None,
) -> MoscaResult:
    """Apply Mosca's inequality.

    If the time your data must stay secret (X) plus the time it takes to
    migrate (Y) exceeds the time until a quantum computer can break your
    cryptography (Z), then data you are protecting today will still be
    sensitive when it becomes readable. The migration should already be
    under way.
    """
    now = now or _dt.datetime.now(_dt.timezone.utc)
    current_year = now.year

    if quantum_year is None:
        quantum_year, scenario_note = QUANTUM_SCENARIOS.get(
            scenario, QUANTUM_SCENARIOS["central"]
        )
    else:
        scenario_note = "operator-supplied estimate"

    years_to_quantum = quantum_year - (
        current_year + (now.timetuple().tm_yday - 1) / 365.0
    )
    total = shelf_life_years + migration_years
    at_risk = total > years_to_quantum
    exposure = total - years_to_quantum
    deadline_year = int(quantum_year - shelf_life_years - migration_years)

    if at_risk:
        verdict = "EXPOSED"
        if deadline_year < current_year:
            timing = (
                f"The latest safe start date was {deadline_year}, which has "
                "passed: on these assumptions the migration is already overdue "
                "rather than upcoming, and the practical goal is to shorten the "
                "exposure window rather than eliminate it."
            )
        else:
            timing = f"Migration must begin by {deadline_year} at the latest."
        explanation = (
            f"Data created today must stay confidential for {shelf_life_years} "
            f"years, and a full migration is expected to take {migration_years} "
            f"years. Together that is {total} years of required protection, but "
            f"only {years_to_quantum:.1f} years remain before the {quantum_year} "
            f"threat date. The shortfall is {exposure:.1f} years: traffic "
            "captured today would still be sensitive when it becomes "
            f"decryptable. {timing}"
        )
    else:
        margin = -exposure
        verdict = "WITHIN TOLERANCE"
        explanation = (
            f"Required protection of {total} years fits inside the "
            f"{years_to_quantum:.1f} years remaining before the {quantum_year} "
            f"threat date, with {margin:.1f} years to spare. Migration must "
            f"still begin by {deadline_year} for that to hold, and the margin "
            "disappears if the threat date moves earlier."
        )

    return MoscaResult(
        shelf_life_years=shelf_life_years,
        migration_years=migration_years,
        years_to_quantum=round(years_to_quantum, 1),
        quantum_year=quantum_year,
        at_risk=at_risk,
        exposure_years=round(exposure, 1),
        deadline_year=deadline_year,
        verdict=verdict,
        explanation=explanation,
        assumptions=[
            f"Threat date {quantum_year}: {scenario_note}.",
            f"Data shelf life X = {shelf_life_years} years. Set this from your "
            "longest retention obligation, not the average.",
            f"Migration time Y = {migration_years} years, covering discovery, "
            "supplier readiness, testing and rollout.",
            "The inequality assumes an adversary is already recording traffic. "
            "For anything that crosses a public network, assume they are.",
        ],
    )


# Typical confidentiality lifetimes, offered as defaults in the interface
# because most organisations underestimate X on first attempt.
SECTOR_SHELF_LIFE = {
    "healthcare": (25, "patient records carry lifetime confidentiality duties"),
    "government": (30, "national security and census material is routinely "
                       "classified for decades"),
    "legal": (20, "matter files and privileged material outlive the engagement"),
    "finance": (15, "mortgage, pension and insurance records run for decades"),
    "insurance": (20, "policy and claims history persists for the life of cover"),
    "defence": (30, "classified material has multi-decade review periods"),
    "pharmaceutical": (25, "trial data and formulations retain value for the "
                           "life of the patent and beyond"),
    "education": (15, "student records are retained long after graduation"),
    "retail": (7, "payment and customer data under PCI and tax retention"),
    "technology": (10, "source code and customer data"),
    "general": (10, "a common default; replace it with your real retention "
                    "obligation"),
}


def suggested_shelf_life(sector: str) -> Tuple[int, str]:
    return SECTOR_SHELF_LIFE.get(sector.lower(), SECTOR_SHELF_LIFE["general"])
