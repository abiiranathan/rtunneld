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
- `--no-path` (Windows client only) skips adding the install directory to the user `PATH`.

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
rtunnel.exe ssh-config <agent> --write
ssh user@<agent>
```

## File Paths
- Relay State: `/var/lib/rtunnel` (`identity.key`, `identity.crt`, `rtunnel.db`, `audit.log`)
- Agent State: `/var/lib/rtunnel-agent` (`identity.key`, `identity.crt`, `config.toml`)
- Client State (Unix): `~/.config/rtunnel` (`identity.key`, `identity.crt`, `config.toml`)
- Client State (Windows): `%APPDATA%\rtunnel` (`identity.key`, `identity.crt`, `config.toml`)
- Client SSH snippets: `~/.ssh/rtunnel.d/*.conf`, loaded from `~/.ssh/config` by `rtunnel install` or `rtunnel ssh-config --write`; on Windows the same files live under `%USERPROFILE%\.ssh\rtunnel.d\`

## Audit Logging
The relay produces an append-only JSONL log at `<state_dir>/audit.log` recording:
- `session_open`, `session_close` (byte counts and duration)
- `auth_failure`
- `enroll`
- `grant_change`
- `revoke`
