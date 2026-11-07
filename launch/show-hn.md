Title: Show HN: ghseal – share .env files encrypted to your teammates' GitHub SSH keys

URL: https://github.com/hamarshehmhmd/ghseal

Text:
Every small team I've been on shared .env files over Slack. Then someone leaves and nobody knows which keys they had.

GitHub already publishes everyone's public SSH keys at github.com/<user>.keys, and age can encrypt to those. ghseal is a thin workflow around that:

- `ghseal add @alice` fetches and pins her keys
- `ghseal seal` writes .env.sealed (a plain age file) that you commit
- `ghseal run -- npm start` decrypts in memory, so there's no .env on disk for an agent to read
- `ghseal remove bob` re-seals and prints the secrets bob could read, so you know what to rotate
- `ghseal check` in CI fails if someone's missing or a removed key can still decrypt

No server, no account. If the tool dies, `age -d -i ~/.ssh/id_ed25519` still opens your file.

Limits: whole-file encryption, so git shows *that* it changed, not which key. ECDSA/FIDO SSH keys aren't supported by age. Key pinning is trust-on-first-use.

AGPL-3.0. Curious how others handle this without going full Vault.
