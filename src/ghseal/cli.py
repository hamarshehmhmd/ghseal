"""ghseal command line interface."""
from __future__ import annotations

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path

from . import __version__, core, dotenv, guard, keys
from .core import GhsealError, Project

USE_COLOR = False


def c(code: str, s: str) -> str:
    return f"\x1b[{code}m{s}\x1b[0m" if USE_COLOR else s


def ok(s):
    print(c("32", "✓ ") + s)


def warn(s):
    print(c("33", "! ") + s)


def err(s):
    print(c("31", "✗ ") + s)


def info(s):
    print(c("2", "  " + s))


def _ids(a):
    return keys.load_identities(a.identity)[0] if a.identity else None


# ------------------------------------------------------------------ commands

def cmd_init(a):
    p = Project.init(os.getcwd(), a.file)
    ok(f"created {core.CONFIG} tracking {a.file} -> {a.file}.sealed")
    if core.ensure_gitignored(p.root, a.file):
        ok(f"added /{a.file} to .gitignore")
    if not a.no_guard:
        changed = guard.apply(p)
        if changed:
            ok("AI agent ignore rules: " + ", ".join(changed))
    info("next: ghseal add @your-github-username  (then teammates), ghseal seal")
    return 0


def cmd_track(a):
    p = Project.find()
    f = p.add_file(a.file, a.sealed)
    p.save()
    ok(f"tracking {f['plain']} -> {f['sealed']}")
    if core.ensure_gitignored(p.root, f["plain"]):
        ok(f"added /{f['plain']} to .gitignore")
    guard.apply(p)
    return 0


def cmd_add(a):
    p = Project.find()
    for spec in a.who:
        s = keys.resolve(spec, a.name if len(a.who) == 1 else None)
        for k, why in s.skipped:
            warn(f"{s.name}: skipping {k.split()[0]} key ({why})")
        r = p.add_recipient(s)
        ok(f"added {r['name']} ({r['source']}) with {len(r['keys'])} key(s)")
        for k in r["keys"]:
            info(f"{k.split()[0] if not k.startswith('age1') else 'age'}  {keys.fingerprint(k)}")
    p.save()
    if not a.no_seal:
        _reseal_all(p, a)
    return 0


def _reseal_all(p, a, force=True):
    sealed_any = False
    for f in p.files:
        if not p.path(f["sealed"]).is_file():
            continue  # first seal is explicit: `ghseal seal`
        try:
            if p.path(f["plain"]).is_file():
                st = p.seal(f["plain"], _ids(a), force=force)
            else:
                _, data = p.open_env(f["plain"], _ids(a))
                st = p.seal(f["plain"], _ids(a), force=True, text=data)
            ok(f"{f['sealed']}: re-sealed to {len(p.recipients)} recipient(s)" if st == "sealed"
               else f"{f['sealed']}: unchanged")
            sealed_any = True
        except GhsealError as e:
            warn(f"{f['sealed']}: not re-sealed ({e})")
    return sealed_any


def cmd_remove(a):
    p = Project.find()
    names = []
    for who in a.who:
        r = p.recipient(who)
        if not r:
            raise GhsealError(f"no recipient named {who!r}")
        p.recipients.remove(r)
        names.append(r["name"])
        ok(f"removed {r['name']} ({r['source']})")
    # list what the removed people could read, before re-sealing
    to_rotate = []
    for f in p.files:
        try:
            _, data = p.open_env(f["plain"], _ids(a))
            to_rotate += [k for k in dotenv.parse(data.decode()) if k not in to_rotate]
        except GhsealError:
            pass
    p.save()
    _reseal_all(p, a)
    if to_rotate:
        warn(f"{', '.join(names)} could read these values (and still can, from git history). Rotate them:")
        for k in to_rotate:
            info(k)
    return 0


def cmd_ls(a):
    p = Project.find()
    if not p.recipients:
        warn("no recipients yet")
    for r in p.recipients:
        print(f"{c('1', r['name'])}  {c('2', r['source'])}  added {r.get('added', '?')}")
        for k in r["keys"]:
            info(f"{'age' if k.startswith('age1') else k.split()[0]}  {keys.fingerprint(k)}")
    for f in p.files:
        print(c("2", f"file: {f['plain']} -> {f['sealed']}"))
    return 0


def cmd_refresh(a):
    p = Project.find()
    changed = False
    for r in p.recipients:
        forge, _, user = r["source"].partition(":")
        if forge not in keys.FORGES:
            continue
        try:
            new, skipped = keys.split_supported(keys.fetch_forge_keys(forge, user))
        except keys.KeyError_ as e:
            warn(f"{r['name']}: {e}")
            continue
        added = [k for k in new if k not in r["keys"]]
        gone = [k for k in r["keys"] if k not in new]
        if not added and not gone:
            ok(f"{r['name']}: keys unchanged")
            continue
        changed = True
        warn(f"{r['name']} ({r['source']}) changed keys: +{len(added)} -{len(gone)}")
        for k in added:
            info(f"+ {keys.fingerprint(k)}")
        for k in gone:
            info(f"- {keys.fingerprint(k)}")
        if a.accept:
            r["keys"] = new
    if changed and a.accept:
        p.save()
        ok(f"updated {core.CONFIG}")
        _reseal_all(p, a)
        return 0
    if changed:
        warn("new keys can mean a new laptop, or a hijacked account. Confirm with the person, "
             "then run `ghseal refresh --accept`")
        return 2
    return 0


def cmd_seal(a):
    p = Project.find()
    targets = [p.file(f) for f in a.files] if a.files else p.files
    for f in targets:
        st = p.seal(f["plain"], _ids(a), force=a.force)
        if st == "unchanged":
            ok(f"{f['sealed']} already up to date")
        else:
            n = len(dotenv.parse(p.path(f["plain"]).read_text()))
            ok(f"sealed {f['plain']} ({n} vars) -> {f['sealed']} for {len(p.recipients)} recipient(s): "
               + ", ".join(r["name"] for r in p.recipients))
    return 0


def cmd_open(a):
    p = Project.find()
    f, data = p.open_env(a.file, _ids(a))
    if a.stdout:
        sys.stdout.write(data.decode())
        return 0
    dst = p.path(f["plain"])
    if dst.is_file():
        cur = dst.read_bytes()
        if cur == data:
            ok(f"{f['plain']} already matches {f['sealed']}")
            return 0
        if not a.force:
            ad, rm, ch = core.env_diff(dotenv.parse(data.decode()), dotenv.parse(cur.decode()))
            raise GhsealError(f"{f['plain']} has local changes ({len(ad)} added, {len(rm)} removed, "
                              f"{len(ch)} changed); seal them first or use --force to overwrite")
    fd = os.open(dst, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)
    ok(f"wrote {f['plain']} ({len(dotenv.parse(data.decode()))} vars, mode 600)")
    info("tip: `ghseal run -- <cmd>` injects them without a plaintext file on disk")
    return 0


def cmd_run(a):
    cmd = a.cmd
    if cmd and cmd[0] == "--":
        cmd = cmd[1:]
    if not cmd:
        raise GhsealError("usage: ghseal run [-f FILE] -- command [args...]")
    p = Project.find()
    env = dict(os.environ)
    targets = [p.file(x) for x in a.files] if a.files else p.files
    for f in targets:
        _, data = p.open_env(f["plain"], _ids(a))
        for k, v in dotenv.parse(data.decode()).items():
            if a.override or k not in os.environ:
                env[k] = v
    exe = shutil.which(cmd[0], path=env.get("PATH"))
    if not exe:
        raise GhsealError(f"command not found: {cmd[0]}")
    sys.stdout.flush()
    if os.name == "posix":
        os.execve(exe, cmd, env)
    return subprocess.call([exe, *cmd[1:]], env=env)


def cmd_names(a):
    p = Project.find()
    _, data = p.open_env(a.file, _ids(a))
    for k, v in dotenv.parse(data.decode()).items():
        print(f"{k}  {c('2', f'({len(v)} chars)')}")
    return 0


def cmd_get(a):
    p = Project.find()
    _, data = p.open_env(a.file, _ids(a))
    env = dotenv.parse(data.decode())
    if a.key not in env:
        raise GhsealError(f"{a.key} is not set")
    print(env[a.key])
    return 0


def _edit(a, fn, verb):
    p = Project.find()
    f = p.file(a.file)
    sealed = p.path(f["sealed"])
    text = p.open_env(f["plain"], _ids(a))[1].decode() if sealed.is_file() else ""
    new = fn(text)
    p.seal(f["plain"], _ids(a), force=True, text=new.encode())
    plain = p.path(f["plain"])
    if plain.is_file():
        plain.write_text(fn(plain.read_text()))
    ok(f"{verb} in {f['sealed']}" + (f" (and {f['plain']})" if plain.is_file() else ""))
    return 0


def cmd_set(a):
    if "=" in a.assignment:
        key, val = a.assignment.split("=", 1)
    else:
        key = a.assignment
        val = sys.stdin.read().rstrip("\n") if not sys.stdin.isatty() else __import__("getpass").getpass(f"{key}: ")
    return _edit(a, lambda t: dotenv.set_key(t, key, val), f"set {key}")


def cmd_unset(a):
    return _edit(a, lambda t: dotenv.unset_key(t, a.key), f"removed {a.key}")


def cmd_diff(a):
    p = Project.find()
    f, data = p.open_env(a.file, _ids(a))
    plain = p.path(f["plain"])
    if not plain.is_file():
        raise GhsealError(f"{f['plain']} does not exist locally (nothing to compare)")
    ad, rm, ch = core.env_diff(dotenv.parse(data.decode()), dotenv.parse(plain.read_text()))
    if not (ad or rm or ch):
        ok(f"{f['plain']} matches {f['sealed']}")
        return 0
    print(c("1", f"{f['plain']} vs {f['sealed']} (values hidden)"))
    for k in ad:
        print(c("32", f"+ {k}"))
    for k in rm:
        print(c("31", f"- {k}"))
    for k in ch:
        print(c("33", f"~ {k}"))
    return 1


def cmd_check(a):
    p = Project.find()
    findings = core.check(p, _ids(a))
    errors = warns = 0
    for fd in findings:
        if fd.level == "error":
            errors += 1
            err(fd.msg)
        elif fd.level == "warn":
            warns += 1
            warn(fd.msg)
        else:
            ok(fd.msg)
    if errors or (a.strict and warns):
        print(c("31", f"ghseal check: {errors} error(s), {warns} warning(s)"))
        return 1
    print(c("32", f"ghseal check: passed ({warns} warning(s))"))
    return 0


def cmd_guard(a):
    p = Project.find()
    changed = guard.apply(p)
    if changed:
        for name in changed:
            ok(f"wrote rules to {name}")
    else:
        ok("AI agent ignore rules already in place")
    info("best effort only: agents with a shell can still read files; prefer `ghseal run`")
    return 0


def cmd_keygen(a):
    secret, public = keys.keygen()
    if a.output:
        out = Path(os.path.expanduser(a.output))
        if out.exists():
            raise GhsealError(f"{out} exists")
        out.parent.mkdir(parents=True, exist_ok=True)
        fd = os.open(out, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as fh:
            fh.write(f"# public key: {public}\n{secret}\n")
        print(public)
        info(f"secret key written to {out}")
    else:
        print(f"# public key: {public}")
        print(secret)
    return 0


# ------------------------------------------------------------------ parser

def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        prog="ghseal",
        description="Share .env files by sealing them to your teammates' GitHub SSH keys (age format).",
    )
    ap.add_argument("--version", action="version", version=f"ghseal {__version__}")
    ap.add_argument("--color", choices=["auto", "always", "never"], default="auto")
    ap.add_argument("-i", "--identity", action="append", metavar="FILE",
                    help="private key to decrypt with (ssh or age); repeatable")
    sub = ap.add_subparsers(dest="command", metavar="command")

    def sp(name, fn, help_):
        s = sub.add_parser(name, help=help_, description=help_)
        s.set_defaults(fn=fn)
        return s

    s = sp("init", cmd_init, "create .ghseal.json, gitignore the plaintext and add AI agent ignore rules")
    s.add_argument("file", nargs="?", default=".env")
    s.add_argument("--no-guard", action="store_true", help="don't write AI agent ignore files")
    s = sp("track", cmd_track, "track another env file (e.g. .env.production)")
    s.add_argument("file")
    s.add_argument("--sealed", help="sealed file name (default FILE.sealed)")
    s = sp("add", cmd_add, "add recipients: @user (GitHub), gitlab:user, codeberg:user, age1..., ssh key or .pub file")
    s.add_argument("who", nargs="+")
    s.add_argument("--name", help="display name (single recipient only)")
    s.add_argument("--no-seal", action="store_true", help="don't re-seal existing files")
    s = sp("remove", cmd_remove, "remove recipients, re-seal and list the secrets to rotate")
    s.add_argument("who", nargs="+")
    sp("ls", cmd_ls, "list recipients and their pinned key fingerprints")
    s = sp("refresh", cmd_refresh, "re-fetch forge keys and flag any change (possible hijack or new laptop)")
    s.add_argument("--accept", action="store_true", help="accept the new keys and re-seal")
    s = sp("seal", cmd_seal, "encrypt env files to every recipient")
    s.add_argument("files", nargs="*")
    s.add_argument("--force", action="store_true", help="re-encrypt even if nothing changed")
    s = sp("open", cmd_open, "decrypt the sealed file back to plaintext (mode 600)")
    s.add_argument("file", nargs="?")
    s.add_argument("--stdout", action="store_true")
    s.add_argument("--force", action="store_true", help="overwrite local changes")
    s = sp("run", cmd_run, "run a command with the sealed vars injected; no plaintext on disk")
    s.add_argument("-f", "--file", dest="files", action="append")
    s.add_argument("--override", action="store_true", help="sealed values win over the current environment")
    s.add_argument("cmd", nargs=argparse.REMAINDER)
    s = sp("names", cmd_names, "list variable names in the sealed file (values hidden)")
    s.add_argument("file", nargs="?")
    s = sp("get", cmd_get, "print one value")
    s.add_argument("key")
    s.add_argument("-f", "--file")
    s = sp("set", cmd_set, "set KEY=VALUE (or KEY, value from stdin) directly in the sealed file")
    s.add_argument("assignment")
    s.add_argument("-f", "--file")
    s = sp("unset", cmd_unset, "remove KEY from the sealed file")
    s.add_argument("key")
    s.add_argument("-f", "--file")
    s = sp("diff", cmd_diff, "compare local plaintext with the sealed file (names only)")
    s.add_argument("file", nargs="?")
    s = sp("check", cmd_check, "CI / pre-commit check: sealed to everyone, nobody extra, no plaintext in git")
    s.add_argument("--strict", action="store_true", help="fail on warnings too")
    sp("guard", cmd_guard, "write .cursorignore/.aiexclude/.codeiumignore/.aiderignore and Claude Code deny rules")
    s = sp("keygen", cmd_keygen, "generate an age key (for CI: store the secret as GHSEAL_AGE_KEY)")
    s.add_argument("-o", "--output", help="write the secret key to this file (mode 600)")
    return ap


def main(argv=None) -> int:
    global USE_COLOR
    ap = build_parser()
    a = ap.parse_args(argv)
    if a.color == "always" or (a.color == "auto" and os.environ.get("FORCE_COLOR")):
        USE_COLOR = True
    elif a.color == "auto":
        USE_COLOR = sys.stdout.isatty() and not os.environ.get("NO_COLOR")
    if not getattr(a, "fn", None):
        ap.print_help()
        return 0
    try:
        return a.fn(a) or 0
    except (GhsealError, keys.KeyError_, dotenv.DotenvError, ValueError) as e:
        print(c("31", f"ghseal: {e}"), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
