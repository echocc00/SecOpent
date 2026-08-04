"""AuditKeyManager private material export/import (W3-C T4)."""
from __future__ import annotations

from secopent.infrastructure.audit.key_manager import AuditKeyManager


def test_export_import_round_trips_the_key() -> None:
    keys = AuditKeyManager()
    material = keys.export_private_material()
    assert isinstance(material, str)
    assert material  # non-empty

    rebuilt = AuditKeyManager.from_private_material(material)
    # Same key: a signature by one verifies under the other's public key.
    msg = b"hello audit"
    sig = keys.sign(msg)
    assert rebuilt.verify(msg, sig) is True
    # Public key bytes match.
    assert rebuilt.public_key_bytes() == keys.public_key_bytes()


def test_from_private_material_reconstructs_signing_key() -> None:
    keys = AuditKeyManager()
    material = keys.export_private_material()
    rebuilt = AuditKeyManager.from_private_material(material)
    msg = b"chain event"
    sig = rebuilt.sign(msg)
    assert keys.verify(msg, sig) is True


def test_export_then_sign_is_stable_across_rebuild() -> None:
    """A signature made before rebuild verifies after rebuild (restart survival)."""
    keys = AuditKeyManager()
    msg = b"persistent event"
    sig = keys.sign(msg)

    rebuilt = AuditKeyManager.from_private_material(keys.export_private_material())
    assert rebuilt.verify(msg, sig) is True
