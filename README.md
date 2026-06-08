# weft-loom-app-windows

Windows notification-area client for the
[Weft](https://github.com/openweft) dashboard.

A tray icon; **Open Dashboard** shows
[`weft-webui`](https://github.com/openweft/weft-webui) in a WebView2
window. The connection logic — datacenter discovery, secure transport,
and failover — lives in
[`weft-app-core`](https://github.com/openweft/weft-app-core); this repo
is the Windows tray + WebView glue. It is the same Go shell as
[`weft-app-osx`](https://github.com/openweft/weft-app-osx) and
[`weft-app-gtk`](https://github.com/openweft/weft-app-gtk), with
`webview_go` resolving to WebView2 here, the macOS Keychain swapped for
Windows Credential Manager, and Touch ID swapped for Windows Hello.

## How it works

Three modes of one binary (one main loop each): the **tray** owns the
failover supervisor + loopback gateway + control server; **Open
Dashboard** spawns the binary in `--dashboard` mode, which loads the
gateway's single stable loopback origin in a WebView2 window and never
re-points it — so a datacenter failover preserves cookies, session and
SPA state, and only the dashboard's "connection switched" banner blips.
The **`--sign-in`** mode opens the auth WebView2 window when the operator
clicks "Sign in" in the tray menu. See the
[`weft-app-core` README](https://github.com/openweft/weft-app-core) for
the full picture.

```
weft-loom-app-windows (tray)                     weft-loom-app-windows --dashboard
─────────────────────                       ────────────────────────────
shell.Shell                                 WebView2
  ├─ failover.Supervisor  (probes each DC)    loads gateway origin
  ├─ failover.Gateway     (loopback origin) ◀── stable http://127.0.0.1:PORT
  └─ control.Server       (/active) ──poll──▶ control.Client
        ▲                                       └─ on DC change:
        └ OnSwitch publishes active DC             __weftFailoverNotice → banner
```

## No public web service

Each DC's `weft-webui` is reached over an SSH local-forward (default) or
the WireGuard mesh — the platform exposes no worldwide web listener. The
transport key gates the network, dex OIDC gates the session. See
`config.example.json`.

For the WireGuard transport (pure-Go userspace `wireguard-go`, no `tun`
privilege), pass a mesh config:

```powershell
weft-loom-app-windows.exe --config app.json --wg-config wireguard.json
```

See `wireguard.example.json` for the schema (`wg genkey`-style base64
keys).

## Tray menu

- **Active DC label** (top of the menu, disabled) — the operator-facing
  "Cluster · DC" name of the datacenter the dashboard is currently
  reading from. The tray tooltip carries the same string so it's
  visible without opening the menu.
- **Open Dashboard** — spawns the dashboard WebView2 window. Disabled
  until a non-expired session token is cached when `auth` is configured
  in `app.json` (so clicking it can never land on the dex sign-in page
  instead of the SPA).
- **Datacenters** — submenu showing each cluster header + indented per-
  DC rows, glyphed `●` for healthy / `○` for down, with ` — active`
  on the currently-selected DC.
- **Switch cluster** — submenu listing every cluster declared in
  `app.json`. Only present when more than one cluster is configured.
  Clicking a cluster quarantines every endpoint outside it so failover
  stays scoped ; the SPA's Topbar chip + the tray tooltip update via
  the usual `OnSwitch` path.
- **Sign in** / **Sign out** — only present when an `auth` block is
  declared. "Sign in" spawns the `--sign-in` subprocess (WebView2 with
  `login.html`) ; on success the new token is in Credential Manager and
  the tray reads it back. "Sign out" deletes the cached token.
- **Quit** — terminates the supervisor, gateway, and control server.

## Build

Requires a gcc toolchain (mingw-w64 / TDM-GCC) on `PATH` and the
Evergreen **WebView2 runtime** (preinstalled on Windows 11).

```powershell
copy config.example.json %AppData%\weft\app.json   # then edit for your cluster
task deps
task build
```

Packaging as an MSIX: `task msix`.

## Encrypted SSH key + Windows Hello passphrase

The SSH transport accepts a passphrase-protected key — the recommended
posture — without prompting on every launch. The flow :

```
   ┌─────────────────┐    ┌──────────────────────┐   ┌────────────────────┐
   │ %USERPROFILE%\  │    │ Windows Credential   │   │ weft-loom-app-windows   │
   │  .ssh\id_ed25519│    │  Manager             │   │                    │
   │ (PEM, encrypted)│    │ target=              │   │ SSHForward         │
   │                 │    │  weft-ssh-passphrase │   │ (bastion hosts)    │
   │                 │    │  \<key path>         │   │                    │
   └────────┬────────┘    └─────────┬────────────┘   └────────┬───────────┘
            │                       │                         │
            │ read PEM              │ release passphrase      │ ssh dial
            └──────┬────────────────┘ (Windows Hello gate)    │
                   │                       │                  │
                   ▼                       │                  │
   ssh.ParsePrivateKeyWithPassphrase(pem, passphrase) ────────┘
```

**One-shot setup**

```powershell
# 1. Make sure the key is actually passphrase-protected. If you generated
#    it without one and want to add one :
ssh-keygen -p -f %USERPROFILE%\.ssh\id_ed25519
# Old passphrase: (empty)
# New passphrase: ●●●●●●●●

# 2. Stage the passphrase in Windows Credential Manager. Prompts on the
#    controlling console with echo off, so it never lands in shell
#    history or env vars.
weft-loom-app-windows.exe --store-ssh-passphrase %USERPROFILE%\.ssh\id_ed25519
# Enter passphrase for C:\Users\<you>\.ssh\id_ed25519 (empty if none):
# ●●●●●●●●
# weft-app: passphrase cached in Credential Manager
#           (target=weft-ssh-passphrase\C:\Users\<you>\.ssh\id_ed25519)
```

**Subsequent launches** — the tray's shell calls `sshPassphraseGet` when
`ssh.ParsePrivateKey` returns `*ssh.PassphraseMissingError`; the
Credential Manager release is gated by the current Windows account's
DPAPI master key, with an opportunistic Windows Hello prompt on top.

**Windows Hello** — when the box is enrolled (PIN + camera / fingerprint
reader configured under **Settings → Accounts → Sign-in options →
Windows Hello**), the SSH passphrase release surfaces the standard
Windows Hello prompt the same way the lock screen does. When the box is
NOT enrolled (no biometric hardware, Windows Hello not configured for
the current user), the biometric step is silently skipped — the
Credential Manager release falls back to the per-session DPAPI gate,
which is what Windows does for every Generic credential anyway. So the
app keeps working on boxes without a camera or fingerprint reader, and
the biometric protection layers on transparently when the hardware is
present.

**Rotation** — re-running `--store-ssh-passphrase` overwrites the entry.
To wipe :

```powershell
cmdkey /delete:weft-ssh-passphrase\%USERPROFILE%\.ssh\id_ed25519
```

The Credential Manager entry is per-key-file-path, so multiple keys
(e.g. one per production cluster) coexist without colliding.

## Sign-in & authentication

When the `auth` block is present in `app.json`, the tray's "Sign in"
menu item opens the WebView2 login window (`login.html`) with two
buttons :

- **Sign in with OIDC** — runs the Authorization Code + PKCE flow
  against the configured `issuer` (dex by default). The same WebView2
  navigates to the IdP login page ; the loopback HTTP listener captures
  the redirect. The resulting id_token is cached in Credential Manager.
- **Sign in with OpenPubkey** — bound to dex's `/openpubkey/cert`
  endpoint. Surfaced as a stub until the cluster's dex ships the
  extension ; clicking it falls back to OIDC.

A third **Sign in with local key (dev)** button appears when
`keypair_fallback = true` is set in `app.json` and `gateway` points to
the cluster origin. The app loads (or generates + persists) an ed25519
private key in Credential Manager (target prefix `weft-app-keypair`),
signs a 60-second assertion bound to `gateway/api/auth/keypair`, and
POSTs it ; the server returns a session id_token if the matching public
key is in its `--keypair-allowlist` file. Register your pubkey by running
`weft-loom-app-windows --print-pubkey` and pasting the output into the
server's allowlist.

## Tested logic

The non-UI logic is covered by tests in this repo
(`auth_test.go`, `auth_keypair_test.go`, `auth_oidc_test.go`,
`wgmesh_test.go`) and in `weft-app-core` (`failover`, `shell`,
`control`, `discovery`). This repo's `main` package is the thin
Win32 + WebView2 shell.
