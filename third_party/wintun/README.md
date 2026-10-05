# Wintun provenance

Windows amd64 uses the official Go binding, pinned to
`golang.zx2c4.com/wintun v0.0.0-20230126152724-0fa3db229ce2`
(`0fa3db229ce2036ae779de8ba03d336b7aa826bd`), under MIT.
Copyright (C) 2017–2021 WireGuard LLC. See `LICENSE-go.txt`.
Source: <https://git.zx2c4.com/wintun-go/>.

The binary is the unmodified, signed **Wintun 0.14.1** AMD64 DLL:

- Official archive: <https://www.wintun.net/builds/wintun-0.14.1.zip>
- Archive SHA-256: `07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51`
- `wintun/bin/amd64/wintun.dll` SHA-256: `e5da8447dc2c320edc0fc52fa01885c103de8c118481f683643cacc3220dafce`
- Redistribution terms: `LICENSE-binary.txt`, copied verbatim from the archive.

The DLL is downloaded and checked by the explicit smoke bundle builder. It is
not committed or silently downloaded by the daemon. Runtime requires the pinned
DLL next to the executable and checks its digest before creating an adapter.
The official binding searches only the application directory and System32.
The installation directory must be writable only by its administrator/owner.
Do not substitute a self-built driver or ship a modified DLL.

The B4 adapter uses a 1 MiB ring and one reader, copying and releasing each
borrowed receive buffer before enqueueing into a bounded 64-packet Go channel.
Queue pressure drops packets. Writes allocate, copy and send under a teardown
lock; ring-full errors are returned. Context cancellation wakes the Windows
event wait, joins the reader, ends the session and closes the owned adapter.
No global driver uninstall is performed. Windows retains the signed driver in
its driver store; that is separate from the per-run adapter/session resources.

The native lifecycle test deliberately installs no address or route. This is
not yet the complete Wintun–SADR–ESP product pipeline.
