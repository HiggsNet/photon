# ranet-lite source notice

Source: https://github.com/NickCao/ranet-lite

Commit: `24a24a2ff380c9f8ceb0092d640daa32e86b5eb5`

The unchanged MIT license is in LICENSE (SHA-256
`a5f170541dce10ddde7a3f04d1dc18b56a220c7a323594d1e43a304e633b211e`).

Derived files in Photon:

| Photon | Upstream internal/ike source | Changes |
| --- | --- | --- |
| internal/photonclient/ike/payload.go | header.go, payload.go | Bounded framing, explicit errors, duplicate and critical checks |
| internal/photonclient/ike/proposal.go | payloads_sa.go | Fixed CBC/SHA256/P-256 proposal and strict selection |
| internal/photonclient/ike/payloads_init.go | payloads_misc.go | Bounded KE, nonce and Notify codecs |

Crypto, session, tests and fixtures are new Photon implementations. No upstream
dependencies or complete runtime have been imported. See
docs/photon-windows/ranet-port-map.md for the adoption decisions. Retain this
directory when distributing binaries containing the derived code.
