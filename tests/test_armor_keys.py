import os

import pyrage
import pytest

from ghseal import armor, keys


def test_armor_roundtrip_and_line_length():
    data = os.urandom(1000)
    t = armor.armor(data)
    lines = t.strip().splitlines()
    assert lines[0] == armor.BEGIN and lines[-1] == armor.END
    assert all(len(l) == 64 for l in lines[1:-2]) and len(lines[-2]) <= 64
    assert armor.dearmor(t) == data
    assert armor.dearmor(t.encode()) == data
    assert armor.dearmor(b"age-encryption.org/v1\nbinary") == b"age-encryption.org/v1\nbinary"


def test_dearmor_rejects_garbage():
    with pytest.raises(ValueError):
        armor.dearmor("hello")


def test_header_stanzas_carry_ssh_tags(keyring):
    a, b = keyring["alice"]["pub"], keyring["bob"]["pub"]
    ct = pyrage.encrypt(b"x", [keys.to_recipient(keys.normalize(a)), keys.to_recipient(keys.normalize(b))])
    st = armor.header_stanzas(ct)
    tags = {s[1] for s in st if s[0] in keys.SUPPORTED}
    assert tags == {keys.ssh_tag(a), keys.ssh_tag(b)}
    with pytest.raises(ValueError):
        armor.header_stanzas(b"nope")


def test_split_supported_skips_ecdsa_and_fido(keyring):
    ok, skipped = keys.split_supported([
        keyring["alice"]["pub"] + " comment",
        "ecdsa-sha2-nistp256 AAAAE2Vj",
        "sk-ssh-ed25519@openssh.com AAAAGnNr",
        "# comment", "",
    ])
    assert len(ok) == 1 and ok[0].count(" ") == 1
    assert keys.split_supported(["ssh-ed25519 AAAAbroken"])[1][0][1].startswith("invalid key")
    assert [s[1] for s in skipped] == ["ECDSA keys are not supported by age",
                                       "hardware (FIDO) SSH keys are not supported by age"]


def test_resolve_github_user_via_forge(proj, keyring):
    s = keys.resolve("@bob")
    assert s.name == "bob" and s.source == "github:bob"
    assert s.keys == [keys.normalize(keyring["bob"]["pub"])]
    assert len(s.skipped) == 2
    assert keys.resolve("github:alice").keys == [keys.normalize(keyring["alice"]["pub"])]


def test_resolve_errors(proj):
    with pytest.raises(keys.KeyError_, match="invalid username"):
        keys.resolve("@bad/name")
    with pytest.raises(keys.KeyError_):
        keys.resolve("@nobody-here")
    with pytest.raises(keys.KeyError_, match="don't know"):
        keys.resolve("definitely not a key")


def test_resolve_age_pubfile_and_raw_ssh(tmp_path, keyring):
    secret, public = keys.keygen()
    assert keys.resolve(public).keys == [public]
    s = keys.resolve(keyring["carol"]["priv"] + ".pub")
    assert s.name == "carol" and s.source.startswith("file:")
    raw = keys.resolve(keyring["alice"]["pub"] + " alice@laptop")
    assert raw.name == "alice@laptop"


def test_fetch_uses_forge_url_and_404(monkeypatch):
    calls = []

    class R:
        def __init__(self, body):
            self.body = body

        def read(self):
            return self.body

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

    def fake(req, timeout):
        calls.append(req.full_url)
        if "ghost" in req.full_url:
            import urllib.error
            raise urllib.error.HTTPError(req.full_url, 404, "nf", {}, None)
        return R(b"ssh-ed25519 AAAA x\n")

    monkeypatch.delenv("GHSEAL_GITLAB_KEYS_URL", raising=False)
    monkeypatch.setattr(keys.urllib.request, "urlopen", fake)
    assert keys.fetch_forge_keys("gitlab", "jane") == ["ssh-ed25519 AAAA x"]
    assert calls == ["https://gitlab.com/jane.keys"]
    with pytest.raises(keys.KeyError_, match="not found"):
        keys.fetch_forge_keys("gitlab", "ghost")
    with pytest.raises(keys.KeyError_, match="unknown forge"):
        keys.fetch_forge_keys("sourcehut", "x")


def test_identities_ssh_rsa_age_env(monkeypatch, keyring):
    monkeypatch.delenv("GHSEAL_IDENTITY", raising=False)
    monkeypatch.delenv("GHSEAL_AGE_KEY", raising=False)
    ids, desc = keys.load_identities([keyring["alice"]["priv"], keyring["bob"]["priv"]])
    assert len(ids) == 2
    secret, public = keys.keygen()
    monkeypatch.setenv("GHSEAL_AGE_KEY", secret)
    ids, desc = keys.load_identities()
    assert desc == ["$GHSEAL_AGE_KEY"]
    ct = pyrage.encrypt(b"hi", [keys.to_recipient(public)])
    assert pyrage.decrypt(ct, ids) == b"hi"


def test_identity_missing_explicit_raises(monkeypatch):
    monkeypatch.delenv("GHSEAL_IDENTITY", raising=False)
    with pytest.raises(keys.KeyError_, match="not found"):
        keys.load_identities(["/nonexistent/key"])


def test_passphrase_protected_ssh_key(monkeypatch, keyring):
    monkeypatch.delenv("GHSEAL_IDENTITY", raising=False)
    monkeypatch.setenv("GHSEAL_PASSPHRASE", "hunter2")
    ids, _ = keys.load_identities([keyring["locked"]["priv"]])
    ct = pyrage.encrypt(b"ok", [keys.to_recipient(keys.normalize(keyring["locked"]["pub"]))])
    assert pyrage.decrypt(ct, ids) == b"ok"
    monkeypatch.setenv("GHSEAL_PASSPHRASE", "wrong")
    with pytest.raises(keys.KeyError_, match="wrong passphrase"):
        keys.load_identities([keyring["locked"]["priv"]])
    monkeypatch.delenv("GHSEAL_PASSPHRASE")
    monkeypatch.setattr("sys.stdin", open(os.devnull))
    with pytest.raises(keys.KeyError_, match="GHSEAL_PASSPHRASE"):
        keys.load_identities([keyring["locked"]["priv"]])


def test_fingerprint_formats(keyring):
    assert keys.fingerprint(keys.normalize(keyring["alice"]["pub"])).startswith("SHA256:")
    _, pub = keys.keygen()
    assert keys.fingerprint(pub).startswith("age1")


@pytest.mark.skipif(not os.environ.get("GHSEAL_LIVE"), reason="set GHSEAL_LIVE=1 to hit github.com")
def test_live_github_keys(monkeypatch):
    monkeypatch.delenv("GHSEAL_GITHUB_KEYS_URL", raising=False)
    ok, skipped = keys.split_supported(keys.fetch_forge_keys("github", "hamarshehmhmd"))
    assert ok and ok[0].startswith(("ssh-ed25519", "ssh-rsa"))
