**English** | [Русский](README.md)

# gostpx

System proxy tray switcher for macOS and Windows. One proxy from config, one click — and supported system traffic is routed through it. Transparent tool supporting SOCKS5, HTTP(S), and SSH upstreams.

> 📖 *Note: Detailed documentation is available in Russian in [`docs/`](docs/).*

## Philosophy

**Catch what we can, honestly show what we cannot.**

gostpx never forces stubborn traffic: it does not block QUIC, intercept third-party DoH, inject into processes, or disable IPv6. Traffic bypassing the proxy is clearly flagged.

> [!WARNING]
> **This is not an anonymity tool.** No kill-switch: if the upstream drops, traffic routes directly with your real IP. The tray alerts immediately, but does not block packets.

## Key Features

- **macOS & Windows System Tray:** clear statuses (🟢 on, 🔴 OFF, 🔴 dropped / error, 🟡 no network), RTT latency, on-demand external IP check.
- **Settings UI:** native graphical window (Wails v3) with live connection testing and comment-preserving TOML editing.
- **Reliability:** handshake health probes, auto-reconnect with backoff, local network loss detection, OS notifications on drop and recovery (macOS and Windows), autostart support.
- **CLI & Terminal:** full CLI (`on`, `off`, `toggle`, `status`, `set`, `test`, `config`, `doctor --connections` — a one-off check of which apps currently bypass the proxy), plus `eval "$(gostpx env)"` for shell tools (`curl`, `git`, `npm`).
- **Security:** passwords stored separately in `credentials.toml` (`0600` permissions, [ADR-011](docs/DECISIONS.md#adr-011)); `config.toml` contains no secrets. Hot reload on config changes.

## Traffic Coverage

- **Routed:** apps that honour the system proxy: on macOS Safari and CFNetwork apps (verified), Chromium browsers and Firefox (expected); on Windows Edge, Chrome and WinINET clients (verified).
- **Bypassed:** console tools without environment variables, apps with custom network stacks, UDP/QUIC, DNS of apps that bypass the proxy (names in proxied connections are resolved by the upstream). Local loopback (`127.0.0.1`, `localhost`) connects directly ([ADR-019](docs/DECISIONS.md#adr-019)).
- Full normative matrix: [docs/LIMITATIONS.md](docs/LIMITATIONS.md).

## Installation

Download pre-built binaries from [GitHub Releases](https://github.com/losoph/gostpx/releases):
- **macOS (Universal):** `gostpx-macos-universal.zip` (`gostpx.app`, ad-hoc signed; on first run right-click → Open or `xattr -dr com.apple.quarantine /Applications/gostpx.app`).
- **Windows (x64 / arm64):** `gostpxw-windows-amd64.exe` (tray GUI) and `gostpx-windows-amd64.exe` (CLI).

## Quick Start

```bash
gostpx set socks5://user:pass@proxy.example.net:1080  # configure proxy
gostpx test                                           # test connectivity
gostpx on                                             # enable system proxy
gostpx status --check-ip                              # check status & external IP
eval "$(gostpx env)"                                  # configure current terminal
```

Config files: `~/Library/Application Support/gostpx/config.toml` (macOS), `%APPDATA%\gostpx\config.toml` (Windows).

## Building from Source

Requires **Go 1.27**.
```bash
go build -o work/gostpx ./cmd/gostpx      # macOS: tray + CLI in one binary (CGO)
./build/darwin/package.sh work/gostpx dev work/gostpx.app 0 work/gostpx.zip
GOOS=windows go build ./cmd/gostpx        # Windows CLI
GOOS=windows go build -ldflags "-H windowsgui" ./cmd/gostpxw  # Windows tray
go test -race -tags gostpxtest ./internal/...   # tests
```

## Project Status

**v0.2.0 — Phase 2 complete:** `sysproxy` mode for macOS and Windows with tray and CLI. Next: Phase 5 (network changes, coverage verification). System-wide `tun` mode is postponed ([ADR-017](docs/DECISIONS.md#adr-017)).
Deliberately omitted: kill-switch, bypass lists, IPv6 routing ([ADR-008](docs/DECISIONS.md#adr-008)), multiple profiles ([ADR-012](docs/DECISIONS.md#adr-012)), Shadowsocks/WireGuard ([ADR-010](docs/DECISIONS.md#adr-010)).

Documentation (Russian): [LIMITATIONS.md](docs/LIMITATIONS.md) · [ARCHITECTURE.md](docs/ARCHITECTURE.md) · [DECISIONS.md](docs/DECISIONS.md) · [CONFIG.md](docs/CONFIG.md) · [CLI.md](docs/CLI.md) · [ROADMAP.md](docs/ROADMAP.md) · [COVERAGE-TESTS.md](docs/COVERAGE-TESTS.md) · [PLATFORM-NOTES.md](docs/PLATFORM-NOTES.md).

## License

[MIT](LICENSE)
