import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from ghseal import armor, cli, core, keys
from conftest import ENV_TEXT


def run(*args, code=0, capsys=None):
    rc = cli.main(["--color", "never", *args])
    out = capsys.readouterr() if capsys else None
    assert rc == code, (rc, out)
    return (out.out + out.err) if out else ""


def setup_team(capsys, members=("@alice", "@bob")):
    run("init", capsys=capsys)
    Path(".env").write_text(ENV_TEXT)
    run("add", *members, capsys=capsys)
    return run("seal", capsys=capsys)


def as_user(monkeypatch, keyring, name):
    monkeypatch.setenv("GHSEAL_IDENTITY", keyring[name]["priv"])


def test_init_writes_config_gitignore_and_guard(proj, capsys):
    out = run("init", capsys=capsys)
    cfg = json.loads(Path(".ghseal.json").read_text())
    assert cfg["files"] == [{"plain": ".env", "sealed": ".env.sealed"}]
    assert "/.env" in Path(".gitignore").read_text()
    assert ".env" in Path(".cursorignore").read_text().splitlines()
    deny = json.loads(Path(".claude/settings.json").read_text())["permissions"]["deny"]
    assert "Read(./.env)" in deny
    assert "AI agent ignore rules" in out
    run("init", code=1, capsys=capsys)


def test_seal_open_roundtrip_for_each_teammate(proj, capsys, monkeypatch, keyring):
    out = setup_team(capsys)
    assert "sealed .env (4 vars)" in out and "alice, bob" in out
    text = Path(".env.sealed").read_text()
    assert text.startswith(armor.BEGIN) and "sk_live" not in text
    os.remove(".env")
    as_user(monkeypatch, keyring, "bob")  # RSA key
    run("open", capsys=capsys)
    assert Path(".env").read_text() == ENV_TEXT
    if os.name == "posix":
        assert (Path(".env").stat().st_mode & 0o777) == 0o600
    as_user(monkeypatch, keyring, "mallory")
    out = run("open", "--stdout", code=1, capsys=capsys)
    assert "none of your keys" in out


def test_add_reports_skipped_unsupported_keys(proj, capsys):
    run("init", capsys=capsys)
    out = run("add", "@bob", capsys=capsys)
    assert "skipping ecdsa-sha2-nistp256" in out and "skipping sk-ssh-ed25519@openssh.com" in out
    assert "with 1 key(s)" in out
    run("add", "@bob", code=1, capsys=capsys)


def test_seal_is_stable_when_nothing_changed(proj, capsys):
    setup_team(capsys)
    before = Path(".env.sealed").read_text()
    out = run("seal", capsys=capsys)
    assert "already up to date" in out
    assert Path(".env.sealed").read_text() == before
    run("seal", "--force", capsys=capsys)
    assert Path(".env.sealed").read_text() != before


def test_seal_rejects_unparseable_env(proj, capsys):
    run("init", capsys=capsys)
    run("add", "@alice", capsys=capsys)
    Path(".env").write_text('A="unterminated\n')
    assert "unterminated" in run("seal", code=1, capsys=capsys)


def test_seal_without_recipients_is_an_error(proj, capsys):
    run("init", capsys=capsys)
    Path(".env").write_text("A=1\n")
    assert "no recipients" in run("seal", code=1, capsys=capsys)


def test_open_refuses_to_clobber_local_changes(proj, capsys):
    setup_team(capsys)
    Path(".env").write_text(ENV_TEXT + "NEW=1\n")
    out = run("open", code=1, capsys=capsys)
    assert "local changes (1 added" in out
    run("open", "--force", capsys=capsys)
    assert "NEW" not in Path(".env").read_text()


def _ghseal(*args, env=None, **kw):
    return subprocess.run([sys.executable, "-m", "ghseal", *args], capture_output=True, text=True,
                          env=env or os.environ.copy(), **kw)


def test_run_injects_without_plaintext(proj, capsys):
    setup_team(capsys)
    os.remove(".env")
    code = "import os;print(os.environ['STRIPE_SECRET_KEY'], os.environ['DEBUG'])"
    p = _ghseal("run", "--", sys.executable, "-c", code)
    assert p.returncode == 0, p.stderr
    assert p.stdout.strip() == "sk_live_51abc false"
    assert not Path(".env").exists()


def test_run_respects_existing_env_unless_override(proj, capsys):
    setup_team(capsys)
    env = dict(os.environ, DEBUG="true")
    code = "import os;print(os.environ['DEBUG'])"
    assert _ghseal("run", "--", sys.executable, "-c", code, env=env).stdout.strip() == "true"
    assert _ghseal("run", "--override", "--", sys.executable, "-c", code, env=env).stdout.strip() == "false"


def test_run_propagates_exit_code_and_errors(proj, capsys):
    setup_team(capsys)
    assert _ghseal("run", "--", sys.executable, "-c", "raise SystemExit(7)").returncode == 7
    p = _ghseal("run")
    assert p.returncode == 1 and "usage" in p.stderr
    assert "command not found" in _ghseal("run", "--", "no-such-cmd-xyz").stderr


def test_set_get_unset_names_without_plaintext(proj, capsys):
    setup_team(capsys)
    os.remove(".env")
    run("set", "NEW_TOKEN=abc 123", capsys=capsys)
    assert run("get", "NEW_TOKEN", capsys=capsys).strip() == "abc 123"
    assert not Path(".env").exists()
    names = run("names", capsys=capsys)
    assert "NEW_TOKEN" in names and "abc" not in names
    run("unset", "DEBUG", capsys=capsys)
    assert "DEBUG" not in run("names", capsys=capsys)
    run("get", "DEBUG", code=1, capsys=capsys)


def test_set_updates_local_plaintext_too(proj, capsys):
    setup_team(capsys)
    run("set", "DEBUG=true", capsys=capsys)
    assert "DEBUG=true" in Path(".env").read_text()
    assert "matches" in run("diff", capsys=capsys)


def test_set_reads_value_from_stdin(proj, capsys, monkeypatch):
    import io
    setup_team(capsys)
    monkeypatch.setattr("sys.stdin", io.StringIO("from-stdin\n"))
    run("set", "PIPED", capsys=capsys)
    assert run("get", "PIPED", capsys=capsys).strip() == "from-stdin"


def test_diff_shows_names_not_values(proj, capsys):
    setup_team(capsys)
    Path(".env").write_text(ENV_TEXT.replace("sk_live_51abc", "sk_live_rotated").replace("DEBUG=false", "")
                            + "SENTRY_DSN=https://x\n")
    out = run("diff", code=1, capsys=capsys)
    assert "+ SENTRY_DSN" in out and "- DEBUG" in out and "~ STRIPE_SECRET_KEY" in out
    assert "rotated" not in out and "sk_live" not in out


def test_check_passes_on_clean_setup(proj, capsys):
    setup_team(capsys)
    out = run("check", capsys=capsys)
    assert "sealed to all 2 recipient(s)" in out and "passed" in out
    run("check", "--strict", capsys=capsys)


def test_check_flags_new_member_not_sealed_yet(proj, capsys):
    setup_team(capsys)
    run("add", "@carol", "--no-seal", capsys=capsys)
    out = run("check", code=1, capsys=capsys)
    assert "not sealed to carol yet" in out


def test_check_flags_key_no_longer_in_config(proj, capsys):
    setup_team(capsys)
    cfg = json.loads(Path(".ghseal.json").read_text())
    cfg["recipients"] = [r for r in cfg["recipients"] if r["name"] != "bob"]
    Path(".ghseal.json").write_text(json.dumps(cfg))
    out = run("check", code=1, capsys=capsys)
    assert "still readable by 1 SSH key(s)" in out


def test_check_flags_plaintext_committed_and_unsealed_changes(proj, capsys):
    setup_team(capsys)
    subprocess.run(["git", "add", "-f", ".env"], check=True)
    Path(".env").write_text(ENV_TEXT + "EXTRA=1\n")
    out = run("check", code=1, capsys=capsys)
    assert ".env (plaintext) is committed to git" in out
    assert "unsealed changes: +EXTRA" in out


def test_check_warns_when_not_gitignored_and_guard_missing(proj, capsys):
    run("init", "--no-guard", capsys=capsys)
    Path(".gitignore").write_text("")
    Path(".env").write_text("A=1\n")
    run("add", "@alice", capsys=capsys)
    run("seal", capsys=capsys)
    out = run("check", capsys=capsys)
    assert "not in .gitignore" in out and "AI agent ignore rules missing" in out
    run("check", "--strict", code=1, capsys=capsys)


def test_check_flags_missing_sealed_file(proj, capsys):
    run("init", capsys=capsys)
    run("add", "@alice", capsys=capsys)
    assert ".env.sealed missing" in run("check", code=1, capsys=capsys)


def test_remove_reseals_and_lists_secrets_to_rotate(proj, capsys, monkeypatch, keyring):
    setup_team(capsys)
    out = run("remove", "bob", capsys=capsys)
    assert "re-sealed to 1 recipient(s)" in out
    assert "Rotate them" in out and "STRIPE_SECRET_KEY" in out
    as_user(monkeypatch, keyring, "bob")
    run("open", "--stdout", code=1, capsys=capsys)
    as_user(monkeypatch, keyring, "alice")
    assert "passed" in run("check", capsys=capsys)
    run("remove", "nobody", code=1, capsys=capsys)


def test_add_teammate_reseals_existing_file_without_plaintext(proj, capsys, monkeypatch, keyring):
    setup_team(capsys)
    os.remove(".env")
    out = run("add", "@carol", capsys=capsys)
    assert "re-sealed to 3 recipient(s)" in out
    as_user(monkeypatch, keyring, "carol")
    assert "sk_live_51abc" in run("open", "--stdout", capsys=capsys)


def test_refresh_detects_key_change_and_accept(proj, capsys, monkeypatch, keyring, tmp_path):
    forge = tmp_path / "forge2"
    shutil.copytree(keyring["_forge"], forge)
    monkeypatch.setenv("GHSEAL_GITHUB_KEYS_URL", forge.as_uri() + "/{user}.keys")
    setup_team(capsys)
    assert "keys unchanged" in run("refresh", capsys=capsys)
    (forge / "bob.keys").write_text(keyring["mallory"]["pub"] + "\n")  # bob's account now serves another key
    out = run("refresh", code=2, capsys=capsys)
    assert "bob (github:bob) changed keys: +1 -1" in out and "hijacked" in out
    run("refresh", "--accept", capsys=capsys)
    as_user(monkeypatch, keyring, "mallory")
    run("open", "--stdout", capsys=capsys)
    as_user(monkeypatch, keyring, "bob")
    run("open", "--stdout", code=1, capsys=capsys)


def test_ls_shows_fingerprints(proj, capsys):
    setup_team(capsys)
    out = run("ls", capsys=capsys)
    assert "alice" in out and "github:bob" in out and "SHA256:" in out
    assert "file: .env -> .env.sealed" in out


def test_track_second_file(proj, capsys):
    setup_team(capsys)
    run("track", ".env.production", capsys=capsys)
    Path(".env.production").write_text("PROD=1\n")
    run("seal", capsys=capsys)
    assert Path(".env.production.sealed").exists()
    assert ".env.production" in Path(".cursorignore").read_text()
    p = _ghseal("run", "-f", ".env.production", "--", sys.executable, "-c",
                "import os;print(os.environ.get('PROD'), os.environ.get('DEBUG'))")
    assert p.stdout.strip() == "1 None"


def test_keygen_and_ci_flow(proj, capsys, tmp_path, monkeypatch):
    out = run("keygen", "-o", str(tmp_path / "ci.key"), capsys=capsys)
    public = out.splitlines()[0].strip()
    assert public.startswith("age1")
    run("keygen", "-o", str(tmp_path / "ci.key"), code=1, capsys=capsys)
    setup_team(capsys, members=("@alice", public))
    assert "sealed to all 2" in run("check", capsys=capsys)
    secret = [l for l in (tmp_path / "ci.key").read_text().splitlines() if l.startswith("AGE-SECRET")][0]
    env = dict(os.environ, GHSEAL_AGE_KEY=secret)
    env.pop("GHSEAL_IDENTITY")
    p = _ghseal("run", "--", sys.executable, "-c", "import os;print(os.environ['OPENAI_API_KEY'])", env=env)
    assert p.stdout.strip() == "sk-proj-xyz", p.stderr


def test_global_identity_flag(proj, capsys, monkeypatch, keyring):
    setup_team(capsys)
    monkeypatch.delenv("GHSEAL_IDENTITY")
    assert "no identity found" in run("open", "--stdout", code=1, capsys=capsys)
    assert "sk_live" in run("-i", keyring["bob"]["priv"], "open", "--stdout", capsys=capsys)


def test_default_identity_from_home_ssh(proj, capsys, monkeypatch, keyring):
    setup_team(capsys)
    monkeypatch.delenv("GHSEAL_IDENTITY")
    ssh = Path(os.environ["HOME"]) / ".ssh"
    ssh.mkdir()
    shutil.copy(keyring["alice"]["priv"], ssh / "id_ed25519")
    assert "sk_live" in run("open", "--stdout", capsys=capsys)


def test_guard_is_idempotent_and_merges_claude_settings(proj, capsys):
    Path(".claude").mkdir()
    Path(".claude/settings.json").write_text(json.dumps({"permissions": {"allow": ["Bash(ls)"], "deny": ["Read(./secrets/**)"]}}))
    Path(".cursorignore").write_text("node_modules\n")
    run("init", capsys=capsys)
    first = {n: Path(n).read_text() for n in [".cursorignore", ".aiexclude", ".claude/settings.json"]}
    assert "already in place" in run("guard", capsys=capsys)
    assert {n: Path(n).read_text() for n in first} == first
    s = json.loads(first[".claude/settings.json"])
    assert s["permissions"]["allow"] == ["Bash(ls)"]
    assert s["permissions"]["deny"][0] == "Read(./secrets/**)" and "Read(./.env)" in s["permissions"]["deny"]
    assert first[".cursorignore"].startswith("node_modules\n")


def test_no_config_error(proj, capsys):
    assert "no .ghseal.json" in run("ls", code=1, capsys=capsys)


def test_config_found_from_subdirectory(proj, capsys):
    setup_team(capsys)
    os.makedirs("app/src")
    os.chdir("app/src")
    assert "alice" in run("ls", capsys=capsys)


def test_version_and_help(capsys):
    with pytest.raises(SystemExit):
        cli.main(["--version"])
    assert "ghseal 0.1.0" in capsys.readouterr().out
    assert cli.main([]) == 0


AGE = shutil.which("age")


@pytest.mark.skipif(not AGE, reason="age CLI not installed")
def test_interop_age_cli_decrypts_ghseal_output(proj, capsys, keyring):
    setup_team(capsys)
    p = subprocess.run([AGE, "-d", "-i", keyring["bob"]["priv"], ".env.sealed"], capture_output=True, text=True)
    assert p.returncode == 0, p.stderr
    assert p.stdout == ENV_TEXT


@pytest.mark.skipif(not AGE, reason="age CLI not installed")
def test_interop_ghseal_opens_age_cli_output(proj, capsys, keyring):
    run("init", capsys=capsys)
    run("add", "@alice", capsys=capsys)
    pub = Path(keyring["alice"]["priv"] + ".pub")
    subprocess.run([AGE, "-a", "-R", str(pub), "-o", ".env.sealed"], input="FROM_AGE=1\n", text=True, check=True)
    assert run("get", "FROM_AGE", capsys=capsys).strip() == "1"
    assert "passed" in run("check", capsys=capsys)
