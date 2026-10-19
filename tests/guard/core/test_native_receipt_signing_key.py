"""Native Hermes profile receipt keys remain stable and produce verifiable signatures."""

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from plugins.violin_guard.core.evidence import receipt_integrity


def test_native_profile_signing_key_is_persisted_and_authenticates_receipts(tmp_path):
    key_path = tmp_path / "state" / "receipt-signing-key"
    first_key = receipt_integrity._load_or_create_profile_signing_key(key_path)
    second_key = receipt_integrity._load_or_create_profile_signing_key(key_path)
    assert first_key == second_key
    assert len(first_key) == 32

    record = receipt_integrity.seal_execution_receipt(
        {"execution_id": "native-test", "evidence_paths": {}, "declared_evidence_outputs": []},
        tmp_path,
        signing_key=first_key,
    )
    public_key = Ed25519PrivateKey.from_private_bytes(first_key).public_key().public_bytes_raw()
    assert record[receipt_integrity.PUBLIC_SIGNATURE_FIELD].startswith("ed25519:")
    assert receipt_integrity._signed_digests(record, public_key=public_key) == {}


def test_native_signer_is_enabled_only_for_hermes_profile_layout(tmp_path):
    profile_root = tmp_path / ".hermes" / "profiles" / "violin"
    (profile_root / "plugins" / "violin_guard").mkdir(parents=True)
    (profile_root / "plugins" / "violin_guard" / "plugin.yaml").write_text(
        "name: violin_guard\n", encoding="utf-8"
    )
    (profile_root / "config.yaml").write_text("{}\n", encoding="utf-8")

    key = receipt_integrity._native_profile_signing_key(profile_root)

    assert key is not None
    assert key == receipt_integrity._native_profile_signing_key(profile_root)
    assert (profile_root / "state" / "receipt-signing-key").is_file()
    assert receipt_integrity._native_profile_signing_key(tmp_path) is None


def test_native_profile_signing_key_rejects_corrupt_existing_file(tmp_path):
    key_path = tmp_path / "state" / "receipt-signing-key"
    key_path.parent.mkdir()
    key_path.write_bytes(b"short")
    key_path.chmod(0o600)

    try:
        receipt_integrity._load_or_create_profile_signing_key(key_path)
    except ValueError as exc:
        assert "must contain 32 bytes" in str(exc)
    else:
        raise AssertionError("corrupt receipt signing key was silently replaced")


def test_native_profile_signing_key_rejects_symlink(tmp_path):
    target = tmp_path / "outside-key"
    target.write_bytes(b"k" * 32)
    key_path = tmp_path / "state" / "receipt-signing-key"
    key_path.parent.mkdir()
    try:
        key_path.symlink_to(target)
    except OSError as exc:
        pytest.skip(f"symlink creation unavailable: {exc}")

    try:
        receipt_integrity._load_or_create_profile_signing_key(key_path)
    except ValueError as exc:
        assert "must not be a symlink" in str(exc)
    else:
        raise AssertionError("symlinked receipt signing key was accepted")
