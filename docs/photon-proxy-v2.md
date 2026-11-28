# Photon Proxy v2

`photon-proxy run -config proxy.yaml` starts any combination of SOCKS5 Client,
one Relay, and named Exits under one managed Zone. Each path is selected by
the originating Client. For example, `less@h26,child/truenas@h2p` reaches Less
over public IPv6, then Child's `truenas` Exit over Photon Mesh. The first release
supports TrustTunnel HTTP/2 for TCP streams and UDP datagrams.

## Photon Windows

Set `proxy_v2_config: proxy-v2.yaml` in the Photon Windows YAML and start
the backend as usual. The path is relative to the Photon Windows YAML. The
proxy YAML uses the same `client`, `relay`, `exits`, `port_groups`, `tls`, and
`directory_refresh` settings as Linux. Windows supplies the directory, signed
publication and direct IPsec transport from its daemon, so omit
`directory_socket`, `publish_socket`, and `link_namespace`.

For example, a Windows client can use the following `proxy-v2.yaml`:

```yaml
state_dir: proxy-state
directory_refresh: 2s
client:
  admin:
    listen: 127.0.0.1:19573
    socket: '\\.\pipe\photon-proxy-v2'
    token: replace-with-a-private-token
    web: true
  routes:
    via-less:
      listen: 127.0.0.1:1080
      hops: [less@h2l4, child/internet@h2l6]
```

Open `http://127.0.0.1:19573/ui` to manage and probe routes. The named pipe
provides private access to the same HTTP API for local pipe clients. To use
the route in Mihomo or FlClash, add `127.0.0.1:1080` as a SOCKS5 outbound
with UDP enabled. Replacing its hops preserves the port. A Windows node can
also configure Relay and Exit bindings, including the `link_local` port groups
shown below. A direct hop needs an authenticated Photon link to the adjacent
node in the requested outer address family. The Windows daemon carries direct
TCP over that link independently of Wintun business routes and Babel selection.

The proxy creates a private Windows ACL on a new `state_dir`. Use a dedicated
directory on NTFS and keep the state and configuration available to the
account that runs the daemon. Installations using SCM and the desktop backend
should give each running Zone a unique state directory, ports and pipe name.
Copying a Photon Windows profile keeps its reference to the existing Proxy v2
YAML and state. To move them, copy the proxy configuration and its private
state directory while the backend is stopped and update the reference.
Manual port and TLS rotations address the running Windows configuration:

```powershell
photon-windows.exe proxy rotate --config photon.yaml --port-group wan
photon-windows.exe proxy rotate --config photon.yaml --tls
```

## Daemon and local state

On Linux, configure two local Photon daemon sockets:

```yaml
proxy_directory_socket: /run/photon-proxy/directory.sock
proxy_publish_socket: /run/photon-proxy/publish.sock
```

The read socket serves the committed records and public authorization state.
The proxy validates authorization and keeps the resulting directory in memory.
It checks the daemon's revision every 60 seconds by default
(`directory_refresh: 60s`) and fetches records when the revision changes.
Known authorization and lease deadlines are applied locally, including during
a refresh interval. A newly learned update can take up to one refresh period
to reach the proxy. Upgrade the daemon and proxy together because the read
socket uses a versioned request and response.

The write socket can
replace this Zone's v2 proxy records and has no general Photon management
methods. Both sockets use mode `0660`. Put them in a directory with a dedicated
proxy group and restrict write-socket access to the local proxy publisher.
When the daemon and proxy run as different users, a root-owned setgid directory
gives the sockets the intended group. Enable only the proxy publisher that owns
the Zone's local proxy records.

Use a persistent private `state_dir` (mode `0700`). Its `state.db` stores the
SOCKS5 routing state, signing key, TLS certificate and private key, and port and
key rotation state. Relay and Exit nodes also store accepted signature nonces
until their acceptance window ends. Back it up with the same controls as private keys. DNS and
live connection state are kept in memory.

## Example node

The endpoint names are local to their Zone. A Relay always has ID `relay`. Exit
`exit` is the default; other Exit IDs appear after a slash in the route. Replace
sample addresses and Zone names with local ones.

```yaml
directory_socket: /run/photon-proxy/directory.sock
publish_socket: /run/photon-proxy/publish.sock
state_dir: /var/lib/photon-proxy

client:
  allowed_sources: [192.168.10.0/24]
  default_listen: 192.168.10.2:0
  admin:
    listen: 192.168.10.2:19573
    socket: /var/lib/photon-proxy/admin.sock
    token: replace-this-token
    web: true
  routes:
    via-quark:
      listen: 192.168.10.2:1080
      hops: [quark@h26, child/internet@h2p]

port_groups:
  wan:
    bind: ["::"]
    range: [24400, 24431]
    rotate_interval: 24h
  mesh:
    bind: ["::"]
    port: 24500

relay:
  bindings:
    - transport: trusttunnel+h2
      addresses:
        - {source: ipsec, via: [public-v4, public-v6], port_set: wan}
        - {source: route-local, via: [photon], port_set: mesh}
  accept_from: ['*.catofes.']
  deny_from: [test.catofes.]
  accept_to: ['re:(jtti|table)-[a-z0-9-]+\.catofes\.']
  deny_to: [table-canary.catofes.]

exits:
  truenas:
    bindings:
      - transport: trusttunnel+h2
        addresses:
          - {source: route-local, via: [photon], port_set: mesh}
    advertise_policy: true
    accept_from: [child.catofes.]
    accept_to:
      - {cidr: "192.168.50.10/32", protocols: [tcp], ports: [443, 445]}
  internet:
    bindings:
      - transport: trusttunnel+h2
        addresses:
          - {source: route-local, via: [photon], port_set: mesh}
    advertise_policy: true
    accept_from: [child.catofes.]
    accept_to:
      - {scope: public}
    deny_to:
      - {cidr: "192.0.2.0/24"}
```

Both Exits can share the Relay's Mesh listener. `source: route-local` derives
the host address from the Zone's active, authorized non-shared routes and
assignments. The proxy advertises the Mesh binding when it can bind the derived
address locally. `source: ipsec` uses the Zone's verified IPsec address and DNS
announcements. A static address uses `host: <IPv4, IPv6 or DNS>` instead. The
dialing hop resolves DNS in the selected family, merges static candidates, and
applies the matching proxy port group.

## Direct IPsec hops

`h2l4` and `h2l6` use the direct Photon IPsec link to the next node, with IPv4
or IPv6 as the outer IPsec family. Both dial an IPv6 link-local address scoped
to the selected link interface. Each hop requires an installed direct SA of
the requested family.

Direct hops use links configured in IPsec's `family-redundant` mode. On Linux,
set `link_namespace: photon` when the XFRM interfaces are in the
`photon` network namespace. Use `link_namespace: host` for host interfaces.
The option enables outbound direct hops, including on client-only proxies.
When the process runs in a different namespace, it needs permission to enter
the link namespace (`CAP_SYS_ADMIN`) and access its handle in `/run/netns`. The proxy creates
only direct-hop TCP sockets there. It uses its normal network namespace for
SOCKS listeners, other connection methods, and exit traffic.

To receive direct hops, add a dedicated port group and binding address. Allow
the configured TCP port in the link namespace on the Photon tunnel interfaces.

```yaml
link_namespace: photon
port_groups:
  direct:
    link_local: true
    port: 24540
relay:
  bindings:
    - transport: trusttunnel+h2
      addresses:
        - {source: link-local, via: [link-local-v4, link-local-v6], port_set: direct}
  accept_from: ['*.catofes.']
  accept_to: ['*.catofes.']
```

For example, use `hops: [less@h2l4, table/exit@h2l6]` when each adjacent pair
has the corresponding direct link. The proxy checks local IPsec state every
five seconds independently of the directory. On rotation, new streams switch
once a TLS-pinned HTTP/2 probe succeeds through the staged link. Existing
streams can drain while the old tunnel remains installed.

Zone ACL expressions accept exact names, the existing leftmost subtree wildcard,
and `re:` followed by a full-name Go regular expression. An empty accept list
denies that direction. Deny wins. Relay `to` matches the next hop Zone. Exit
`to` matches a business destination. Omitting protocol or port matches all
values for that field. Public scope excludes special-use addresses, the node's
connected prefixes and current Mesh assignments. Use `deny_to` for additional
internal prefixes at the site. Exit ACL publication is opt-in with
`advertise_policy`.

## Rotation

At least three free port choices are needed per rotating group. The proxy binds
the next port, confirms a local TLS/HTTP2 exchange, then publishes it with the
current port as the previous generation. The previous generation accepts new
streams until the next successful publication. It then drains established
streams. New connections prefer the current port and can fall back to the
previous port. Public TCP mappings and firewall rules must cover the configured
range.

```sh
photon-proxy rotate -config proxy.yaml -port-group wan
photon-proxy rotate -config proxy.yaml -tls
```

The leaf certificate is self-signed. Its key is pinned by the endpoint's
Zone-signed TLS record. The default leaf lifetime is 365 days and renewal with
the same key starts 30 days before expiry. Manual key rotation publishes both
pins, switches after the configured `tls.overlap` window, and retains the old
pin for another overlap window. The default overlap is 24 hours.

## Management API and Web

Enable `client.admin.listen` for HTTP or `client.admin.socket` for a private
Unix socket. A TCP listener requires a configured `token` or explicit
`disable_auth: true`. Use a fixed management address for a remote system, or
port zero with discovery via `GET /v1/admin` on the Unix socket. Nginx can
terminate HTTPS. A configured token is passed as `Authorization: Bearer <token>`.
With `web: true`, the built-in panel is at `/ui`. Select an exit and any
optional relays from the Gossip directory. The actions on a saved route let
you switch its hops, test it, or delete its SOCKS5 listener.

New routes use `client.default_listen` if the address is left blank. The
default is `127.0.0.1:0`. A port of 0 allocates an available port.
To expose SOCKS5 to other machines, add the allowed IP prefixes to
`client.allowed_sources` and set an address such as `0.0.0.0:1080` or
`192.168.10.2:1080` when creating the route. Use `[IPv6]:port` for IPv6.
To change an existing listener address, delete and recreate the route.
For a YAML-defined route, change its YAML entry and delete its saved instance
before restarting.

The saved-route probes use the configured hops. TCP connectivity checks for
HTTP 204 at `https://www.google.com/generate_204`. UDP queries
`example.com` at `1.1.1.1:53`. The Cloudflare download counts exactly
4,194,304 bytes and reports the body transfer rate and total elapsed time.
Custom targets can check private exits with a TCP connection or a DNS query.

TCP and UDP share the same route. The exit applies its destination policy to
both. An existing explicit `udp_prefixes` list further limits UDP destinations
for that route.

| Method and path | Behavior |
| --- | --- |
| `GET /v1/admin` | Management listener, default SOCKS5 listener, and allowed SOCKS5 sources |
| `GET /v1/routes` | List current SOCKS5 routes and actual ports |
| `POST /v1/routes` | Create a named route, with optional `listen` for a fixed port |
| `PUT /v1/routes/{name}` | Change the path while retaining its SOCKS5 port |
| `DELETE /v1/routes/{name}` | Remove a SOCKS5 route; entries seeded by YAML are restored on startup |
| `GET /v1/endpoints` | List advertised relays and exits separately, with their connection methods |
| `GET /v1/candidates?protocol=tcp&target=192.168.50.10:443` | Read matching advertised endpoints and a bounded list of candidate paths |
| `POST /v1/probe` | Test explicit `hops` and a `protocol` / `target` |
| `POST /v1/routes/{name}/probe` | Test a saved route with `{"kind":"connectivity"}`, `{"kind":"dns"}`, `{"kind":"download"}`, or a custom `protocol` / `target` |

Candidates come from verified advertisements. An Exit whose policy is private
can be named in a route directly. Actual authentication and destination checks
run on every hop when the route is used.

## Wire format

All records belong to the Zone in the outer signed Photon record. The v2 key
namespace is independent of the legacy capability.

| Type | Key | Value |
| --- | --- | --- |
| `service.proxy.identity.v2` | `services/proxy/v2/identity` | Active lease and raw Ed25519 signing public key as unpadded base64url |
| `service.proxy.endpoint.v2` | `services/proxy/v2/endpoints/<id>` | Active lease, role, bindings, and role policy |
| `service.proxy.tls.v2` | `services/proxy/v2/tls/<id>` | Active lease and one or two SHA-256 SPKI pins |

A record lease has `active` and `expires_at` (Unix seconds). The endpoint's
`bindings` items have `transport` (`h2` for TrustTunnel HTTP/2), `tls_id`,
`protocols`, `addresses` and `port_sets`. Port sets contain `current`, and
optionally `previous`, with `generation` and `port` fields. TLS pins are
lowercase hexadecimal. The local proxy daemon supplies inferred Mesh and IPsec
addresses from its verified snapshot when they are referenced.

The request is an HTTP/2 `CONNECT` with authority `_photon_relay_chain_v2`.
The three proxy fields, shown before HPACK encoding, are:

```http
Photon-Proxy-Route: less@h26,child/truenas@h2p
Photon-Proxy-Target: tcp=192.168.50.10:443
Photon-Proxy-Auth: quark.catofes.~<97 bytes encoded as 130 base64url characters>
```

The route has one to eight unique Zones. An unqualified Zone is relative to the
signed origin's parent Zone; the trailing dot identifies an absolute Zone.
`h24`, `h26`, and `h2p` mean TrustTunnel HTTP/2 over public IPv4, public IPv6,
and Photon Mesh. The TCP target is `tcp=<host:port>`. A UDP target uses
`udp=<comma-separated prefixes>`, followed by the existing TrustTunnel
datagram framing. The authorization bytes are the first 8 bytes of SHA-256 of
the raw Ed25519 public key, an 8-byte big-endian Unix timestamp in milliseconds,
one byte of lifetime in seconds (up to 120), a 16-byte nonce, and a 64-byte
Ed25519 signature. Sign the NUL-separated protocol label
`photon.proxy.chain.v2`, origin, route Header value, target Header value, and
first 33 bytes of the authorization bytes. Relays carry the three values
unchanged. Request expiry limits stream establishment. A receiver allows two
minutes of clock skew in either direction and persists accepted nonces across
restarts. The signed lifetime remains at most 120 seconds. After the first
upgrade of a Relay or Exit that used an in-memory replay cache, the receiver
requires signatures issued after the upgrade cutover so old requests cannot
be replayed under the expanded window. A sender whose clock is behind may
have to wait for its clock to reach that cutover. Each receiving Relay and
Exit must be updated to apply the larger tolerance.
