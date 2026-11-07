Subreddit: r/commandline
Title: ghseal: encrypt .env to people's GitHub SSH keys, run commands with it decrypted in memory

Body:
`ghseal add @alice && ghseal seal` gives you an age-encrypted .env.sealed you can commit. Then `ghseal run -- npm start` injects the vars, and `ghseal set KEY=...` edits it without a plaintext copy. It also writes .cursorignore / Claude Code deny rules so agents leave plaintext alone.

Python, one-line install: curl -fsSL https://raw.githubusercontent.com/hamarshehmhmd/ghseal/main/install.sh | sh

https://github.com/hamarshehmhmd/ghseal (AGPL-3.0)
