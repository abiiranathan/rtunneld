# Operations Guide

## Installation

Both daemons install themselves. The systemd unit is embedded in the binary, so the target does not need a source checkout or a copy of `deploy/`.

```bash
# Relay (root)
sudo rtunneld install --listen 0.0.0.0:4433

# Agent (root, with a one-time enrollment URI)
sudo rtunnel-agent install "rtunnel://relay.example.com:4433/?fp=<relay_fp>&token=<token>" \
  --allowed-target 127.0.0.1:22

# Client (no root required)
rtunnel install "rtunnel://relay.example.com:4433/?fp=<relay_fp>&token=<token>"
```

Useful options:

- `--bin-dir <dir>` installs the executable somewhere other than `/usr/local/bin` (relay/agent), `~/.local/bin` (Unix client), or `%LOCALAPPDATA%\Programs\rtunnel` (Windows client).
- `--no-start` writes the unit without enabling or starting the service.
- `--no-ssh-config` (client only) skips the `~/.ssh/config` include.
- `--no-ssh-hosts` (client only) skips automatic host discovery after enrollment.
- `--no-path` (Windows client only) skips adding the install directory to the user `PATH`.

After enrolling, the client queries the relay and writes an OpenSSH entry for
every granted agent. The agent block routes to the agent's default target (the
first `allowed_targets` entry); extra targets get short aliases such as
`Host winbox` or `Host nas-445`. Regenerate the entries at any time:

```bash
rtunnel ssh-config --all --write
```

Devices also carry a relay-side canonical name. Set one during setup with
`rtunnel setup --name office-pc`, or change it later:

```bash
rtunnel name                 # show this device's Device ID and canonical name
rtunnel name office-pc       # update the relay and local config
sudo rtunneld name 482913077 office-pc   # operator-side rename on the relay
```

Names match `[a-z0-9-]{1,63}` and are unique case-insensitively. They are
resolved to the stable Device ID before grants are checked, so a rename never
changes authorization. A host that has a local `display_name` republishes it
when it reconnects, replacing an operator-only rename. Inspect names with:

```bash
rtunnel agents
sudo rtunneld peers-list
```

`rtunnel tui` provides the same device list interactively and launches the local
`ssh` binary with `ProxyCommand=rtunnel connect <device-id>`. Pass `--user` when
the remote username differs from the local one.

Change an agent's allowlist without re-enrolling it:

```bash
sudo rtunnel-agent targets list
sudo rtunnel-agent targets add winbox:22
sudo rtunnel-agent targets set winbox:22 nas:445
sudo systemctl restart rtunnel-agent
```

The scripts in `scripts/` are standalone bootstrappers around these commands. They download a prebuilt release, verify its checksum when `SHA256SUMS` is available, and then invoke the matching `install` subcommand. `scripts/install.conf` provides repo, version, state directory, listen address, and binary directory defaults; every value can be overridden by environment variables.

| Component | Binary path                    | State directory          | Unit                                    |
| --------- | ------------------------------ | ------------------------ | --------------------------------------- |
| Relay     | `/usr/local/bin/rtunneld`      | `/var/lib/rtunnel`       | `/etc/systemd/system/rtunneld.service`  |
| Agent     | `/usr/local/bin/rtunnel-agent` | `/var/lib/rtunnel-agent` | `/etc/systemd/system/rtunnel-agent.service` |
| Client (Unix) | `~/.local/bin/rtunnel`     | `~/.config/rtunnel`      | n/a                                     |
| Client (Windows) | `%LOCALAPPDATA%\Programs\rtunnel\rtunnel.exe` | `%APPDATA%\rtunnel` | n/a |

### Windows Client

The relay and agent are Linux-only. On a Windows workstation, run the PowerShell
bootstrapper instead of `install.sh`:

```powershell
$installer = Join-Path $env:TEMP "install-rtunnel.ps1"
Invoke-WebRequest -UseBasicParsing `
  https://raw.githubusercontent.com/abiiranathan/rtunneld/main/scripts/install.ps1 `
  -OutFile $installer
powershell -ExecutionPolicy Bypass -File $installer `
  "rtunnel://relay.example.com:4433/?fp=<relay_fp>&token=<token>"
```

`scripts/install.ps1` and `scripts/install-client.ps1` install `rtunnel.exe`,
append the install directory to the **user** `PATH` (`HKCU\Environment`), and
broadcast `WM_SETTINGCHANGE` so new terminals see it. It also writes an absolute
`Include` line for `%USERPROFILE%\.ssh\rtunnel.d\*`; Windows OpenSSH does not
reliably expand `~`. Open a new terminal after the installer finishes.

The Windows client requires the optional OpenSSH Client feature (Settings > Apps
> Optional Features). Verify with:

```powershell
ssh -V
rtunnel.exe agents
rtunnel.exe ssh-config --all --write
ssh user@<agent>
```

## File Paths
- Relay State: `/var/lib/rtunnel` (`identity.key`, `identity.crt`, `rtunnel.db`, `audit.log`)
- Agent State: `/var/lib/rtunnel-agent` (`identity.key`, `identity.crt`, `config.toml`)
- Client State (Unix): `~/.config/rtunnel` (`identity.key`, `identity.crt`, `config.toml`)
- Client State (Windows): `%APPDATA%\rtunnel` (`identity.key`, `identity.crt`, `config.toml`)
- Client SSH snippets: `~/.ssh/rtunnel.d/*.conf`, loaded from `~/.ssh/config` by `rtunnel install`, `rtunnel ssh-config --write`, or `rtunnel ssh-config --all --write`; on Windows the same files live under `%USERPROFILE%\.ssh\rtunnel.d\`
- Relay agent targets: `agent_targets` table in `rtunnel.db` stores the last targets advertised by each agent, so `rtunnel agents` can describe an agent while it is offline.
- Relay canonical names: the `peers.display_name` column in `rtunnel.db` stores each device's relay-side name. It is nullable, unique case-insensitively, and preserved across restarts and in-place upgrades.

## Audit Logging
The relay produces an append-only JSONL log at `<state_dir>/audit.log` recording:
- `session_open`, `session_close` (byte counts and duration)
- `auth_failure`
- `enroll`
- `name_change`
- `grant_change`
- `revoke`
