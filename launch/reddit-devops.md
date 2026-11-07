Subreddit: r/devops
Title: Made a tiny tool to stop passing .env files around in Slack

Body:
It encrypts .env to teammates' GitHub SSH keys (the ones at github.com/<user>.keys). You commit the encrypted file, and people run `ghseal run -- <cmd>` to get the vars injected without a plaintext file.

Bits I actually wanted:
- offboarding prints the exact secrets the person could read, so you know what to rotate
- `ghseal refresh` fails if someone's GitHub keys changed (new laptop or hijacked account)
- `ghseal check` for CI: catches a committed .env, or a removed key that can still decrypt
- CI gets its own age key via a GHSEAL_AGE_KEY secret

Plain age format underneath, no server. https://github.com/hamarshehmhmd/ghseal

Feedback welcome, especially if you think this is a bad idea vs sops.
