# pipet

Signed remote command execution over a [cocoon](https://github.com/serephus/cocoon)
pastebin.

An **agent** signs a command request and publishes it as a paste. A **remote**
polls the pastebin, verifies the SSH signature, runs the command, and publishes
the result. Pastes are used as the transport, so no inbound ports, VPN, or
shared filesystem are needed.

- Requests: `pipet:<remote>:req:<request_id>`
- Results: `pipet:<remote>:res:<request_id>`
- Presence: `pipet:presence:<remote>`

## Requirements

- Python 3 and the [`requests`](https://pypi.org/project/requests/) package
- OpenSSH (`ssh-keygen`)
- `curl` (optional; use `--http-client curl` when Python's TLS/DNS path is slow)
- A cocoon instance (defaults to `https://cocoon.sereph.us`)

With Nix, `nix develop` (or `direnv allow`) installs everything. Otherwise:

```sh
pip install requests
chmod +x pipet.py
```

The default HTTP transport is the Python `requests` library. If Python's
TLS/DNS path is slow on a host, select curl explicitly:

```sh
./pipet.py serve --remote host1 --http-client curl ...
```

`--http-client auto` is also available and prefers curl when installed. The
`requests` transport uses a persistent session with connection pooling.

## Quick start

Generate an agent key and print its `allowed_signers` line:

```sh
ssh-keygen -t ed25519 -f ~/.ssh/pipet_agent
./pipet.py pubkey --key ~/.ssh/pipet_agent --signer agent1
```

Append that line to `~/.config/pipet/allowed_signers` **on the remote**.

Generate a remote identity key for signed results and discovery:

```sh
ssh-keygen -t ed25519 -f ~/.ssh/pipet_remote
./pipet.py pubkey --key ~/.ssh/pipet_remote --signer host1
```

Append that line to `~/.config/pipet/remotes_allowed_signers` **on the agent**.

Run the remote (inside tmux, a service, etc.):

```sh
./pipet.py serve --remote host1 \
  --announce-key ~/.ssh/pipet_remote --announce-signer host1
```

Discover remotes and run a command:

```sh
./pipet.py remotes
./pipet.py submit --remote host1 --key ~/.ssh/pipet_agent --signer agent1 \
  -c 'uname -a'
./pipet.py result <request_id> --remote host1 --wait
```

`result` writes the remote's stdout/stderr and exits with the remote exit code
(timeouts are `124`).

## Commands

| Command | Side | Purpose |
| --- | --- | --- |
| `pubkey` | either | Print an `allowed_signers` line for a key |
| `remotes` | agent | Discover announced remotes (`discover` is an alias) |
| `submit` | agent | Sign and publish a command request |
| `result` | agent | Fetch and verify a result, optionally wait |
| `serve` | remote | Poll and execute requests continuously |
| `once` | remote | Run one poll cycle (cron/systemd timer) |

Run `./pipet.py <command> --help` for every option.

## Common options

HTTP (all commands):

- `--http-client {auto,requests,curl}` — HTTP transport (default: `requests`).
- `PIPET_HTTP_CLIENT` — same, via environment.

Agent:

- `submit --timeout N` — requested execution timeout; the remote clamps it to
  its `--max-timeout`.
- `submit --expires N` — how long the request is valid (default 300s).
- `submit --request-id ID` — reuse an id for idempotent retries.
- `result --wait` / `--wait-timeout N` — wait for a result.
- `remotes --json` — machine-readable discovery output.

Remote:

- `serve --max-timeout N` — hard cap on execution time (default 300s).
- `serve --max-output-bytes N` — cap per output stream (default 1,000,000).
- `serve --cwd DIR` — default working directory.
- `serve --announce-key KEY` — enable discovery and sign results.
- `serve --announce-interval N` / `--announce-ttl N` — presence cadence.
- `serve --retry-interrupted` — re-run commands left running by a crash
  (the default is at-most-once).

## Discovery

A remote started with `--announce-key` publishes a signed presence paste every
`--announce-interval` seconds. `pipet remotes` verifies those announcements
against `~/.config/pipet/remotes_allowed_signers` and shows the remote's
`max_timeout`, `max_output_bytes`, `cwd`, hostname, and signer.

`--ttl N` controls how far back the agent looks (default 900s).

## Configuration file

Instead of repeating flags, pass `--config path` or set `PIPET_CONFIG`:

```json
{
  "paste_url": "https://cocoon.sereph.us",
  "http_client": "requests",
  "agent": {
    "key": "~/.ssh/pipet_agent",
    "signer": "agent1",
    "remote": "host1",
    "timeout": 60
  },
  "remote": {
    "remote": "host1",
    "allowed_signers": "~/.config/pipet/allowed_signers",
    "announce_key": "~/.ssh/pipet_remote",
    "announce_signer": "host1",
    "max_timeout": 300,
    "max_output_bytes": 1000000
  }
}
```

CLI flags override the config file. Useful environment variables:
`PIPET_PASTE_URL`, `PIPET_HTTP_CLIENT`, `PIPET_SSH_KEY`, `PIPET_SIGNER`,
`PIPET_ANNOUNCE_KEY`, `PIPET_ANNOUNCE_SIGNER`, `PIPET_NAMESPACE`,
`PIPET_CONFIG`.

## Security

- **Request authentication:** the agent signs the canonical request payload;
  the remote verifies it with `ssh-keygen -Y verify` against `allowed_signers`.
  The signed payload names the target remote, and requests expire.
- **Result authentication:** when `--announce-key` is set, the remote signs each
  result; the agent verifies it against `remotes_allowed_signers`. The agent
  scans all result pastes with the expected title and accepts only the first
  validly signed one, ignoring injected fakes.
- **Replay protection:** requests carry an expiry, and each remote records
  processed request ids in its state file. Commands are not re-run after a crash
  unless `--retry-interrupted` is set.
- **Paste contents are public.** Commands and results are visible to anyone who
  can read the pastebin, though they cannot be forged. Do not put secrets in
  commands.
- `--no-verify` disables result/discovery signature checks. Use it only with a
  trusted pastebin.
- The remote executes commands as its own user via `/bin/sh -c`. Run it under a
  dedicated, least-privilege account.
