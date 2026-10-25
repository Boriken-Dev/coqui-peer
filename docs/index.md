# coqui-peer

Who a peer is and whether we trust it, independent of how the peer authenticates. The crate
has no TLS and no crypto transport. It holds what every authentication method shares: the
`<alg>:<hash>` peer id, a trust store with the pairing flow, and a sans-IO handshake trait that
runs over byte streams and message transports alike.

Methods are crates named `coqui-peer-<method>`; [`coqui-peer-tls`](https://github.com/Boriken-Dev/coqui-peer-tls)
is the first.

The crate is not published to crates.io; depend on it by git revision:

```toml
coqui-peer = { git = "https://github.com/Boriken-Dev/coqui-peer", rev = "<commit>" }
```

The API reference is under [Rust API](https://boriken-dev.github.io/coqui-peer/rust/index.html).
The source, the API header (`AGENTS.md`) and the changelog are in the
[repository](https://github.com/Boriken-Dev/coqui-peer).
