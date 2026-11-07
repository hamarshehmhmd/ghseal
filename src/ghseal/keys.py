"""Recipients (GitHub/GitLab/Codeberg SSH keys, age keys) and local identities."""
from __future__ import annotations

import base64
import getpass
import hashlib
import os
import re
import sys
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path

from pyrage import ssh, x25519

SUPPORTED = ("ssh-ed25519", "ssh-rsa")
UNSUPPORTED_HINT = {
    "ecdsa-sha2-nistp256": "ECDSA keys are not supported by age",
    "ecdsa-sha2-nistp384": "ECDSA keys are not supported by age",
    "ecdsa-sha2-nistp521": "ECDSA keys are not supported by age",
    "sk-ssh-ed25519@openssh.com": "hardware (FIDO) SSH keys are not supported by age",
    "sk-ecdsa-sha2-nistp256@openssh.com": "hardware (FIDO) SSH keys are not supported by age",
}
FORGES = {
    "github": "https://github.com/{user}.keys",
    "gitlab": "https://gitlab.com/{user}.keys",
    "codeberg": "https://codeberg.org/{user}.keys",
}
_USER = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]{0,38})$")


class KeyError_(Exception):
    pass


def normalize(line: str) -> str:
    """'ssh-ed25519 AAAA... comment' -> 'ssh-ed25519 AAAA...' (comment dropped)."""
    parts = line.strip().split()
    if len(parts) < 2:
        raise KeyError_(f"not a public key: {line.strip()[:40]!r}")
    return f"{parts[0]} {parts[1]}"


def ssh_tag(key: str) -> str:
    """The 4-byte recipient tag age writes into ssh-ed25519 / ssh-rsa stanzas."""
    blob = base64.b64decode(key.split()[1])
    return base64.b64encode(hashlib.sha256(blob).digest()[:4]).decode().rstrip("=")


def fingerprint(key: str) -> str:
    if key.startswith("age1"):
        return key[:12] + "…" + key[-6:]
    blob = base64.b64decode(key.split()[1])
    return "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode().rstrip("=")


def to_recipient(key: str):
    if key.startswith("age1"):
        return x25519.Recipient.from_str(key)
    return ssh.Recipient.from_str(key)


def split_supported(lines: list[str]) -> tuple[list[str], list[tuple[str, str]]]:
    ok, skipped = [], []
    for raw in lines:
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        k = normalize(raw)
        kind = k.split()[0]
        if kind in SUPPORTED:
            try:
                to_recipient(k)
            except Exception as e:  # malformed key material
                skipped.append((k, f"invalid key ({e})"))
                continue
            ok.append(k)
        else:
            skipped.append((k, UNSUPPORTED_HINT.get(kind, f"unsupported key type {kind}")))
    return ok, skipped


def fetch_forge_keys(forge: str, user: str, timeout: float = 15.0) -> list[str]:
    """Fetch the public SSH keys a forge publishes for a user (raw lines)."""
    if forge not in FORGES:
        raise KeyError_(f"unknown forge {forge!r} (use github, gitlab or codeberg)")
    if not _USER.match(user):
        raise KeyError_(f"invalid username {user!r}")
    base = os.environ.get(f"GHSEAL_{forge.upper()}_KEYS_URL", FORGES[forge])
    url = base.format(user=user)
    req = urllib.request.Request(url, headers={"User-Agent": "ghseal"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            text = r.read().decode("utf-8", "replace")
    except urllib.error.HTTPError as e:
        if e.code == 404:
            raise KeyError_(f"{forge} user {user!r} not found") from None
        raise KeyError_(f"fetching {url}: HTTP {e.code}") from None
    except (urllib.error.URLError, OSError) as e:
        raise KeyError_(f"fetching {url}: {e}") from None
    return [l for l in text.splitlines() if l.strip()]


@dataclass
class Spec:
    name: str
    source: str  # "github:alice", "age", "ssh", "file:path"
    keys: list[str]
    skipped: list[tuple[str, str]]


def resolve(spec: str, name: str | None = None, fetch=fetch_forge_keys) -> Spec:
    """Turn a CLI argument into a recipient: @user, github:user, gitlab:user, age1..., ssh-..., or a .pub path."""
    s = spec.strip()
    m = re.match(r"^(?:@|(github|gitlab|codeberg):)(\S+)$", s)
    if m:
        forge = m.group(1) or "github"
        user = m.group(2)
        ok, skipped = split_supported(fetch(forge, user))
        return Spec(name or user, f"{forge}:{user}", ok, skipped)
    if s.startswith("age1"):
        to_recipient(s)
        return Spec(name or "age-" + s[4:12], "age", [s], [])
    if s.split()[0] in SUPPORTED or s.split()[0] in UNSUPPORTED_HINT:
        ok, skipped = split_supported([s])
        comment = s.split()[2] if len(s.split()) > 2 else None
        return Spec(name or comment or ("key-" + ssh_tag(ok[0]) if ok else "key"), "ssh", ok, skipped)
    p = Path(os.path.expanduser(s))
    if p.is_file():
        lines = p.read_text().splitlines()
        ages = [l.strip() for l in lines if l.strip().startswith("age1")]
        ok, skipped = split_supported([l for l in lines if not l.strip().startswith("age1")])
        for a in ages:
            to_recipient(a)
        return Spec(name or p.stem.split(".")[0], f"file:{p.name}", ages + ok, skipped)
    raise KeyError_(f"don't know how to add {spec!r}: use @user, gitlab:user, age1..., an ssh public key or a .pub file")


# ---------------------------------------------------------------- identities

DEFAULT_IDENTITIES = ["~/.ssh/id_ed25519", "~/.ssh/id_rsa", "~/.config/ghseal/keys.txt"]


def _load_ssh(data: bytes, path: str):
    try:
        return ssh.Identity.from_buffer(data)
    except Exception as e:
        if "decrypted" not in str(e) and "passphrase" not in str(e).lower():
            raise KeyError_(f"{path}: {e}") from None
    # passphrase-protected key: decrypt it in memory with `cryptography`
    from cryptography.hazmat.primitives import serialization as ser

    pw = os.environ.get("GHSEAL_PASSPHRASE")
    if pw is None:
        if not sys.stdin.isatty():
            raise KeyError_(f"{path} is passphrase-protected: set GHSEAL_PASSPHRASE or run in a terminal")
        pw = getpass.getpass(f"passphrase for {path}: ")
    try:
        key = ser.load_ssh_private_key(data, password=pw.encode())
    except ValueError:
        raise KeyError_(f"{path}: wrong passphrase") from None
    plain = key.private_bytes(ser.Encoding.PEM, ser.PrivateFormat.OpenSSH, ser.NoEncryption())
    return ssh.Identity.from_buffer(plain)


def load_identities(paths: list[str] | None = None) -> tuple[list, list[str]]:
    """Return (identities, descriptions). Explicit paths must exist; defaults are optional."""
    ids, desc = [], []
    env_key = os.environ.get("GHSEAL_AGE_KEY")
    if env_key:
        for line in env_key.splitlines():
            if line.strip().startswith("AGE-SECRET-KEY-"):
                ids.append(x25519.Identity.from_str(line.strip()))
                desc.append("$GHSEAL_AGE_KEY")
    explicit = list(paths or [])
    if os.environ.get("GHSEAL_IDENTITY"):
        explicit += os.environ["GHSEAL_IDENTITY"].split(os.pathsep)
    candidates = explicit or ([] if ids else DEFAULT_IDENTITIES)
    for raw in candidates:
        p = Path(os.path.expanduser(raw))
        if not p.is_file():
            if raw in explicit:
                raise KeyError_(f"identity file not found: {raw}")
            continue
        data = p.read_bytes()
        text = data.decode("utf-8", "replace")
        if "AGE-SECRET-KEY-" in text:
            for line in text.splitlines():
                if line.strip().startswith("AGE-SECRET-KEY-"):
                    ids.append(x25519.Identity.from_str(line.strip()))
                    desc.append(str(raw))
        elif "PRIVATE KEY" in text:
            ids.append(_load_ssh(data, str(raw)))
            desc.append(str(raw))
    return ids, desc


def keygen() -> tuple[str, str]:
    ident = x25519.Identity.generate()
    return str(ident), str(ident.to_public())
