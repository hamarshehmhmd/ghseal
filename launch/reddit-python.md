Subreddit: r/Python (Showcase flair)
Title: ghseal: share .env files by encrypting them to your teammates' GitHub SSH keys

Body:
**What My Project Does**
A CLI that encrypts your .env to the SSH keys your teammates already have on GitHub (github.com/<user>.keys), so you can commit `.env.sealed` instead of pasting secrets into Slack. `ghseal run -- cmd` injects the vars without writing plaintext. `remove` re-seals and lists what to rotate, and `check` runs in CI. Output is a standard age file.

**Target Audience**
Small teams and side projects that don't want to run Vault/Doppler. It's v0.1, tested on Linux/macOS/Windows in CI, with interop tests against the real `age` CLI.

**Comparison**
sops/dotenvx/git-crypt all work, but you have to hand out keys yourself. Here the keys are just people's GitHub accounts. It's built on pyrage (Rust age bindings) and handles passphrase-protected SSH keys via `cryptography`.

https://github.com/hamarshehmhmd/ghseal (AGPL-3.0)
