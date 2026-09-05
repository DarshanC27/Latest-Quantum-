"""Shared test setup.

The local TLS server needs a private key. Rather than commit one -- which
is a poor signal from a security tool and trips secret scanners, even for
a throwaway loopback key -- the keypairs are generated on demand into an
ignored directory the first time the tests run.
"""

from __future__ import annotations

import pathlib
import sys

import pytest

HERE = pathlib.Path(__file__).parent
FIXTURES = HERE / "fixtures"
sys.path.insert(0, str(HERE.parents[0]))
sys.path.insert(0, str(HERE))

# Keypairs the local TLS server serves. Regenerated whenever missing.
SERVER_KEYPAIRS = ("server-rsa2048", "server-ecdsa-p256", "server-rsa1024")


def _keypairs_present() -> bool:
    return all(
        (FIXTURES / f"{name}{suffix}").exists()
        for name in SERVER_KEYPAIRS
        for suffix in (".crt.pem", ".key.pem")
    )


@pytest.fixture(scope="session", autouse=True)
def ensure_server_keypairs():
    """Generate the loopback server keypairs if they are not already there."""
    if _keypairs_present():
        return
    try:
        import cryptography  # noqa: F401
    except ImportError:
        pytest.skip(
            "server keypairs are missing and 'cryptography' is not installed; "
            "install the dev extra (pip install -e '.[dev]') to generate them",
            allow_module_level=True,
        )
        return

    import make_fixtures

    make_fixtures.main()
    if not _keypairs_present():  # pragma: no cover - generation failed
        pytest.fail("keypair generation did not produce the expected files")
