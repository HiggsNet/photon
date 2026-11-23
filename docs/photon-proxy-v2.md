# Photon Proxy v2

`photon-proxy run -config proxy.yaml` starts any combination of SOCKS5 Client,
one Relay, and named Exits under one managed Zone. Each path is selected by
the originating Client. For example, `less@h26,child/truenas@h2p` reaches Less
over public IPv6, then Child's `truenas` Exit over Photon Mesh. The first release
supports TrustTunnel HTTP/2 for TCP streams and UDP datagrams.

## Daemon and local state

Configure two local Photon daemon sockets:

```yaml
proxy_directory_socket: /run/photon-proxy/directory.sock
proxy_publish_socket: /run/photon-proxy/publish.sock
```

The read socket returns the locally verified directory. The write socket can
replace this Zone's v2 proxy records and has no general Photon management
methods. Both sockets use mode `0660`. Put them in a directory with a dedicated
proxy group and restrict write-socket access to the local proxy publisher.
When the daemon and proxy run as different users, a root-owned setgid directory
gives the sockets the intended group. Enable only the proxy publisher that owns
the Zone's local proxy records.

Use a persistent private `state_dir` (mode `0700`). Its `state.db` stores the
SOCKS5 routing state, signing key, TLS certificate and private key, and port and
key rotation state. Back it up with the same controls as private keys. DNS and
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
      udp_prefixes: ["0.0.0.0/0", "::/0"]

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
With `web: true`, the built-in panel is at `/ui`.

| Method and path | Behavior |
| --- | --- |
| `GET /v1/routes` | List current SOCKS5 routes and actual ports |
| `POST /v1/routes` | Create a named route, with optional `listen` for a fixed port |
| `PUT /v1/routes/{name}` | Change the path while retaining its SOCKS5 port |
| `DELETE /v1/routes/{name}` | Remove a SOCKS5 route; entries seeded by YAML are restored on startup |
| `GET /v1/candidates?protocol=tcp&target=192.168.50.10:443` | Read matching advertised endpoints and a bounded list of candidate paths |
| `POST /v1/probe` | Test explicit `hops` and a `protocol` / `target` |
| `POST /v1/routes/{name}/probe` | Test a saved route; UDP sends a DNS query to an IP and port |

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
unchanged. Request expiry limits stream establishment.
