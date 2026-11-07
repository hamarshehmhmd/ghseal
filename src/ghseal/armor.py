"""age ASCII armor (PEM-like), compatible with `age -a` / `age -d`."""
from __future__ import annotations

import base64

BEGIN = "-----BEGIN AGE ENCRYPTED FILE-----"
END = "-----END AGE ENCRYPTED FILE-----"


def armor(data: bytes) -> str:
    b64 = base64.b64encode(data).decode()
    lines = [b64[i:i + 64] for i in range(0, len(b64), 64)]
    return "\n".join([BEGIN, *lines, END]) + "\n"


def dearmor(text: str | bytes) -> bytes:
    if isinstance(text, bytes):
        if not text.lstrip().startswith(BEGIN.encode()):
            return text  # binary age file
        text = text.decode("ascii")
    body = text.strip().splitlines()
    if not body or body[0].strip() != BEGIN or body[-1].strip() != END:
        raise ValueError("not an armored age file")
    return base64.b64decode("".join(l.strip() for l in body[1:-1]), validate=True)


def header_stanzas(data: bytes) -> list[list[str]]:
    """Return the stanza argument lists of an age v1 header, e.g. [['ssh-ed25519', tag, share], ...]."""
    if not data.startswith(b"age-encryption.org/v1\n"):
        raise ValueError("not an age v1 file")
    end = data.find(b"\n--- ")
    if end < 0:
        raise ValueError("truncated age header")
    stanzas = []
    for line in data[:end].decode("ascii", "replace").split("\n")[1:]:
        if line.startswith("-> "):
            stanzas.append(line[3:].split(" "))
    return stanzas
