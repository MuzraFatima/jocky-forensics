"""AES-256-GCM evidence encryption at rest."""

import base64
import json
import secrets

import pytest

from backend.app.evidence.storage import (
    EvidenceCipher,
    EvidenceDecryptionError,
    cipher_from_environment,
    read_record,
    write_record,
)
from backend.app.evidence.store import EvidenceStore
from backend.app.evidence.vault import EvidenceVault

SECRET_MARKER = "very-secret-hostname-4711"


@pytest.fixture
def cipher():
    return EvidenceCipher(secrets.token_bytes(32))


def _files(base):
    return [p for p in base.rglob("*.json")]


def test_sealed_vault_artifact_is_ciphertext_on_disk(tmp_path, cipher):
    vault = EvidenceVault(base_dir=str(tmp_path), cipher=cipher)
    sealed = vault.seal_artifact("CASE-ENC", "system", {"hostname": SECRET_MARKER})
    raw = _files(tmp_path)[0].read_text(encoding="utf-8")
    assert SECRET_MARKER not in raw
    assert json.loads(raw)["jocky_envelope"] == "AES-256-GCM"
    assert vault.get_artifact(sealed["evidence_id"])["data"]["hostname"] == SECRET_MARKER
    assert vault.verify_artifact(sealed["evidence_id"])["valid"] is True


def test_editing_ciphertext_is_detected_as_tampering(tmp_path, cipher):
    vault = EvidenceVault(base_dir=str(tmp_path), cipher=cipher)
    sealed = vault.seal_artifact("CASE-ENC", "network", {"connections": [1, 2, 3]})
    path = _files(tmp_path)[0]
    envelope = json.loads(path.read_text(encoding="utf-8"))
    blob = bytearray(base64.b64decode(envelope["ciphertext"]))
    blob[5] ^= 0x01
    envelope["ciphertext"] = base64.b64encode(bytes(blob)).decode()
    path.write_text(json.dumps(envelope), encoding="utf-8")

    result = vault.verify_artifact(sealed["evidence_id"])
    assert result["valid"] is False
    assert result["tampered"] is True
    audit = vault.verify_vault_integrity(case_id="CASE-ENC")
    assert audit["vault_status"] == "COMPROMISED"


def test_ciphertext_moved_to_another_evidence_id_fails(tmp_path, cipher):
    record = {"evidence_id": "EVID-A", "data": {"x": 1}}
    path_a = tmp_path / "EVID-A.json"
    write_record(path_a, record, cipher)
    path_b = tmp_path / "EVID-B.json"
    path_b.write_text(path_a.read_text(encoding="utf-8"), encoding="utf-8")
    assert read_record(path_a, cipher)["data"] == {"x": 1}
    with pytest.raises(EvidenceDecryptionError):
        read_record(path_b, cipher)


def test_wrong_key_or_missing_key_cannot_open(tmp_path, cipher):
    path = tmp_path / "EVID-K.json"
    write_record(path, {"evidence_id": "EVID-K"}, cipher)
    with pytest.raises(EvidenceDecryptionError, match="encrypted with key"):
        read_record(path, EvidenceCipher(secrets.token_bytes(32)))
    with pytest.raises(EvidenceDecryptionError, match="no evidence key"):
        read_record(path, None)


def test_plaintext_records_from_before_encryption_still_read(tmp_path, cipher):
    plain = EvidenceStore(base_dir=str(tmp_path), cipher=None)
    saved = plain.save_evidence(case_id="OLD", source="system", data={"a": 1})
    encrypted_store = EvidenceStore(base_dir=str(tmp_path), cipher=cipher)
    assert encrypted_store.get_evidence(saved["evidence_id"])["data"] == {"a": 1}
    assert encrypted_store.verify_evidence(saved["evidence_id"])["valid"] is True


def test_store_round_trip_and_listing_when_encrypted(tmp_path, cipher):
    store = EvidenceStore(base_dir=str(tmp_path), cipher=cipher)
    saved = store.save_evidence(case_id="C1", source="processes", data={"count": 2})
    assert SECRET_MARKER not in _files(tmp_path)[0].read_text(encoding="utf-8")
    listing = store.list_evidence(case_id="C1")
    assert listing[0]["evidence_id"] == saved["evidence_id"]
    assert store.verify_evidence(saved["evidence_id"])["valid"] is True


def test_cipher_from_environment(tmp_path, monkeypatch):
    monkeypatch.delenv("JOCKY_EVIDENCE_KEY", raising=False)
    monkeypatch.delenv("JOCKY_ENCRYPT_EVIDENCE", raising=False)
    assert cipher_from_environment() is None

    key = secrets.token_bytes(32)
    monkeypatch.setenv("JOCKY_EVIDENCE_KEY", base64.b64encode(key).decode())
    assert cipher_from_environment().key_id == EvidenceCipher(key).key_id

    monkeypatch.setenv("JOCKY_EVIDENCE_KEY", "not-base64!!")
    with pytest.raises(ValueError):
        cipher_from_environment()

    monkeypatch.delenv("JOCKY_EVIDENCE_KEY")
    monkeypatch.setenv("JOCKY_ENCRYPT_EVIDENCE", "1")
    monkeypatch.setenv("JOCKY_STORAGE_DIR", str(tmp_path))
    first = cipher_from_environment()
    assert (tmp_path / "evidence.key").is_file()
    assert cipher_from_environment().key_id == first.key_id


def test_cipher_rejects_short_keys():
    with pytest.raises(ValueError):
        EvidenceCipher(b"short")
