# tests/test_all.py
import pytest
import base64
import json
import tempfile
from unittest.mock import patch, MagicMock
import requests

from cryptography.hazmat.primitives.asymmetric import padding
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
import datetime

from merkle_proof import (
    DefaultHasher,
    compute_leaf_hash,
    verify_match,
    RootMismatchError,
    verify_inclusion,
    verify_consistency
)
from util import extract_public_key, verify_artifact_signature
from main import main, get_log_entry, get_latest_checkpoint, inclusion, consistency
#from merkle_proof import DefaultHasher, verify_consistency, verify_inclusion, compute_leaf_hash, RootMismatchError

def test_compute_leaf_hash():
    data = base64.b64encode(b"hello world").decode()
    leaf_hash = compute_leaf_hash(data)
    assert isinstance(leaf_hash, str)
    assert len(leaf_hash) == 64  # sha256 hex length


def test_verify_match_success():
    digest = b"12345"
    assert verify_match(digest, digest) is None


def test_verify_match_failure():
    with pytest.raises(RootMismatchError):
        verify_match(b"abc", b"def")


def test_get_log_entry_success(monkeypatch):
    fake_response = MagicMock()
    fake_response.json.return_value = {"uuid": {"body": "abc"}}
    fake_response.raise_for_status.return_value = None
    monkeypatch.setattr("requests.get", lambda *a, **kw: fake_response)

    result = get_log_entry(10)
    assert isinstance(result, dict)
    assert "uuid" in result


def test_get_latest_checkpoint(monkeypatch):
    fake_response = MagicMock()
    fake_response.json.return_value = {"treeID": "1", "treeSize": 100, "rootHash": "abcd"}
    fake_response.raise_for_status.return_value = None
    monkeypatch.setattr("requests.get", lambda *a, **kw: fake_response)

    result = get_latest_checkpoint()
    assert "treeSize" in result
    assert "rootHash" in result


def test_inclusion_file_not_found(tmp_path):
    # nonexistent artifact should return False
    result = inclusion(1, tmp_path / "nonexistent.txt")
    assert result is False


def test_extract_public_key_invalid():
    with pytest.raises(Exception):
        extract_public_key(b"not a real cert")


def test_verify_artifact_signature_invalid(tmp_path):
    # write dummy artifact
    file_path = tmp_path / "artifact.txt"
    file_path.write_text("dummy content")
    # invalid key and sig
    verify_artifact_signature(b"fake_signature", b"fake_key", file_path)
    # No exception should be raised


def test_consistency_no_checkpoint(monkeypatch):
    # make get_latest_checkpoint return None
    monkeypatch.setattr("main.get_latest_checkpoint", lambda *a, **kw: None)
    result = consistency({"treeID": "x", "treeSize": 1, "rootHash": "abc"})
    assert result is False

def test_inclusion_get_log_entry_failure(monkeypatch, tmp_path):
    monkeypatch.setattr("main.get_log_entry", lambda *a, **kw: None)
    file_path = tmp_path / "artifact.txt"
    file_path.write_text("fake")
    result = inclusion(10, file_path)
    assert result is False

def test_extract_public_key_invalid(monkeypatch):
    from util import extract_public_key
    with pytest.raises(Exception):
        extract_public_key(b"invalid cert data")

def test_verify_artifact_signature_invalid_pem(tmp_path):
    path = tmp_path / "artifact.txt"
    path.write_text("hello")
    # intentionally bad key
    verify_artifact_signature(b"fake_sig", b"not_a_pem", path)

# CLI Test
def test_main_checkpoint(monkeypatch):
    monkeypatch.setattr("sys.argv", ["main.py", "-c"])
    main()

def test_main_inclusion_missing(monkeypatch):
    monkeypatch.setattr("sys.argv", ["main.py", "--inclusion", "1", "--artifact", "no_file.txt"])
    main()

def test_main_consistency_missing_args(monkeypatch):
    monkeypatch.setattr("sys.argv", ["main.py", "--consistency"])
    main()

def test_verify_consistency_equal_sizes():
    h = DefaultHasher
    leaf = h.hash_leaf(b"x")
    root = leaf.hex()
    verify_consistency(h, 1, 1, [], root, root)

def test_verify_inclusion_success():
    h = DefaultHasher
    leaf = h.hash_leaf(b"x").hex()
    proof = []
    root = leaf
    verify_inclusion(h, 0, 1, leaf, proof, root)

def test_consistency_value_error(monkeypatch):

    monkeypatch.setattr("main.get_latest_checkpoint", lambda *a, **kw: {"treeID": "x", "treeSize": 2, "rootHash": "abc"})
    monkeypatch.setattr("requests.get", lambda *a, **kw: type("Fake", (), {"raise_for_status": lambda *a, **kw: None, "json": lambda *a, **kw: {"hashes": []}})())
    result = consistency({"treeID": "x", "treeSize": 1, "rootHash": "abc"})
    assert result is False


def test_get_latest_checkpoint_exception(monkeypatch):

    monkeypatch.setattr(requests, "get", lambda *a, **kw: (_ for _ in ()).throw(requests.exceptions.RequestException("fail")))
    result = get_latest_checkpoint()
    assert result is None

def test_consistency_value_error(monkeypatch):
    monkeypatch.setattr("main.get_latest_checkpoint", lambda *a, **kw: {"treeID": "x", "treeSize": 2, "rootHash": "abc"})
    monkeypatch.setattr("requests.get", lambda *a, **kw: type("Fake", (), {"raise_for_status": lambda *a, **kw: None, "json": lambda *a, **kw: {"hashes": []}})())
    result = consistency({"treeID": "x", "treeSize": 1, "rootHash": "abc"})
    assert result is False

def test_inclusion_invalid_body(monkeypatch, tmp_path):
    # simulate invalid base64 in log body
    monkeypatch.setattr("main.get_log_entry", lambda *a, **kw: {"uuid": {"body": "!!!"}})
    f = tmp_path / "a.txt"
    f.write_text("fake")
    result = inclusion(1, f, debug=True)
    assert result is False

def test_get_log_entry_request_exception(monkeypatch):
    monkeypatch.setattr(requests, "get", lambda *a, **kw: (_ for _ in ()).throw(requests.exceptions.RequestException("boom")))
    result = get_log_entry(10)
    assert result is None

def test_extract_public_key_success(tmp_path):
    # generate a temporary self-signed certificate
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                                  x509.NameAttribute(NameOID.COMMON_NAME, "Test Cert")])
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=10))
        .sign(key, hashes.SHA256())
    )
    cert_bytes = cert.public_bytes(serialization.Encoding.PEM)
    public_key = extract_public_key(cert_bytes)
    assert b"BEGIN PUBLIC KEY" in public_key

def test_verify_artifact_signature_valid(tmp_path):
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    path = tmp_path / "artifact.txt"
    path.write_text("dummy data")
    signature = key.sign(b"dummy data", 
                         padding.PKCS1v15(),
                         hashes.SHA256())
    verify_artifact_signature(signature, public_key, path)

def test_verify_consistency_valid():
    h = DefaultHasher
    leaf = h.hash_leaf(b"a").hex()
    left = h.hash_leaf(b"a")
    right = h.hash_leaf(b"b")
    proof = [right.hex()]
    root1 = left.hex()
    combined = h.hash_children(left, right).hex()
    verify_consistency(h, 1, 2, proof, root1, combined)

def test_inclusion_success(monkeypatch, tmp_path):
    fake_body_dict = {
        "spec": {
            "signature": {
                "content": base64.b64encode(b"sig").decode(),
                "publicKey": {"content": base64.b64encode(b"fake_cert").decode()}
            }
        }
    }

    fake_body = base64.b64encode(json.dumps(fake_body_dict).encode()).decode()

    log_entry = {"uuid": {"body": fake_body}}
    proof = {"uuid": {"verification": {"inclusionProof": {
        "logIndex": 1, "rootHash": "a"*64, "treeSize": 1, "hashes": []
    }}}}

    monkeypatch.setattr("main.get_log_entry", lambda *a, **kw: log_entry)
    monkeypatch.setattr("main.get_verification_proof", lambda *a, **kw: proof)
    monkeypatch.setattr("main.extract_public_key", lambda cert: b"fake_pubkey")
    monkeypatch.setattr("util.verify_artifact_signature", lambda sig, key, path: None)
    monkeypatch.setattr("main.verify_inclusion", lambda *a, **kw: True)

    f = tmp_path / "f.txt"
    f.write_text("ok")
    assert inclusion(1, f, debug=True) is True

def test_consistency_success(monkeypatch):
    monkeypatch.setattr("main.get_latest_checkpoint", lambda *a, **kw: {
        "treeID": "x", "treeSize": 2, "rootHash": "b"*64
    })
    fake = type("Fake", (), {
        "raise_for_status": lambda *a, **kw: None,
        "json": lambda *a, **kw: {"hashes": ["a"*64]}
    })()
    monkeypatch.setattr("requests.get", lambda *a, **kw: fake)
    # patch verify_consistency inside main (not merkle_proof)
    monkeypatch.setattr("main.verify_consistency", lambda *a, **kw: None)
    assert consistency({"treeID": "x", "treeSize": 1, "rootHash": "a"*64}) is True
