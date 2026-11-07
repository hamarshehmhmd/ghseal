import os
import subprocess
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization as ser
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa


def _write_key(dirpath: Path, name: str, kind="ed25519", password=None):
    k = ed25519.Ed25519PrivateKey.generate() if kind == "ed25519" else rsa.generate_private_key(65537, 2048)
    enc = ser.BestAvailableEncryption(password.encode()) if password else ser.NoEncryption()
    priv = dirpath / name
    priv.write_bytes(k.private_bytes(ser.Encoding.PEM, ser.PrivateFormat.OpenSSH, enc))
    pub = k.public_key().public_bytes(ser.Encoding.OpenSSH, ser.PublicFormat.OpenSSH).decode()
    (dirpath / (name + ".pub")).write_text(pub + f" {name}@laptop\n")
    return priv, pub


@pytest.fixture(scope="session")
def keyring(tmp_path_factory):
    d = tmp_path_factory.mktemp("keys")
    ring = {}
    for name, kind, pw in [("alice", "ed25519", None), ("bob", "rsa", None), ("carol", "ed25519", None),
                           ("mallory", "ed25519", None), ("locked", "ed25519", "hunter2")]:
        priv, pub = _write_key(d, name, kind, pw)
        ring[name] = {"priv": str(priv), "pub": pub}
    # a fake forge: file:// URLs serving <user>.keys
    forge = d / "forge"
    forge.mkdir()
    (forge / "alice.keys").write_text(ring["alice"]["pub"] + "\n")
    (forge / "bob.keys").write_text(ring["bob"]["pub"] + "\n"
                                    "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBEm "
                                    "\nsk-ssh-ed25519@openssh.com AAAAGnNrLXNzaC1lZDI1NTE5QG9wZW5zc2guY29tAAAAI\n")
    (forge / "carol.keys").write_text(ring["carol"]["pub"] + "\n")
    ring["_forge"] = forge
    return ring


@pytest.fixture
def proj(tmp_path, monkeypatch, keyring):
    """An empty git repo, a fake HOME without keys, the fake forge, and alice's identity."""
    home = tmp_path / "home"
    home.mkdir()
    repo = tmp_path / "repo"
    repo.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.setenv("GHSEAL_GITHUB_KEYS_URL", keyring["_forge"].as_uri() + "/{user}.keys")
    monkeypatch.setenv("GHSEAL_IDENTITY", keyring["alice"]["priv"])
    for v in ("GHSEAL_AGE_KEY", "GHSEAL_PASSPHRASE", "FORCE_COLOR"):
        monkeypatch.delenv(v, raising=False)
    monkeypatch.chdir(repo)
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.email", "t@example.com"], cwd=repo, check=True)
    subprocess.run(["git", "config", "user.name", "t"], cwd=repo, check=True)
    return repo


ENV_TEXT = """# app config
DATABASE_URL=postgres://app:s3cret@db.internal:5432/app
STRIPE_SECRET_KEY="sk_live_51abc"
export OPENAI_API_KEY='sk-proj-xyz'
DEBUG=false  # not a secret
"""
