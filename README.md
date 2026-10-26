# coqui-peer

[![Version](https://img.shields.io/badge/version-0.1.0--dev-blue.svg)](https://github.com/Boriken-Dev/coqui-peer/blob/main/CHANGELOG.md#unreleased)
[![Rust version](https://img.shields.io/badge/rust-1.89%2B-blue.svg)](https://github.com/Boriken-Dev/coqui-peer/blob/main/Cargo.toml)
[![License: MPL-2.0](https://img.shields.io/badge/license-MPL--2.0-blue.svg)](https://github.com/Boriken-Dev/coqui-peer/blob/main/LICENSE)
[![Docs](https://img.shields.io/badge/docs-latest-blue.svg)](https://boriken-dev.github.io/coqui-peer/rust/coqui_peer/index.html)
[![CI](https://img.shields.io/github/actions/workflow/status/Boriken-Dev/coqui-peer/test.yml)](https://github.com/Boriken-Dev/coqui-peer/actions/workflows/test.yml)

**Who a peer is, and whether we trust it**, with no TLS and no crypto transport. This is the
core that every authentication method shares; the method itself lives in a crate named
`coqui-peer-<method>`. A project that wants peer identity and trust without rustls or X.509
takes this crate and a method crate; a project that wants TLS takes
[`coqui-peer-tls`](https://github.com/Boriken-Dev/coqui-peer-tls), which pulls in this one.
See the [documentation](https://boriken-dev.github.io/coqui-peer/).

## Features

- **`PeerId`** — a peer's id as `<alg>:<hash>` text (`sha256:3f15...`), parsed from the forms
  people paste (bare hex, colon-separated hex, grouped base32), compared in constant time.
- **`TrustStore`** — accepted and waiting peers on disk, with per-source caps (IPv6 grouped
  by /64, configurable), a rerecord interval and the pairing flow: record waiting, the
  operator accepts or removes by id.
  It keeps whatever key bytes a method gives it and records the method name beside them.
- **A key-proof contract** — a peer is recorded as waiting only after it proved it holds the
  key it presented. Every method must meet it; it is documented on `TrustStore`.
- **A sans-IO `Handshake`** — the caller feeds received bytes or messages in and gets bytes or
  messages out, so a method runs over a byte stream, WebSocket messages, datagrams or shared
  memory. Blocking helpers are included; async ones come with the `tokio` feature.
- Plain data, no process-global state, nothing reads a file or an environment variable
  unless you name a directory.

## Installation

```bash
cargo add coqui-peer --git https://github.com/Boriken-Dev/coqui-peer
```

| Feature | Adds | Needed for |
| --- | --- | --- |
| `serde` | `serde` | reading and writing `PeerId` and `Digest` as text, in the format you choose |
| `tokio` | `tokio` (`io-util`) | `asynch::drive_stream`, `asynch::drive_messages` |

## Quick start

Everything is built in code. Open a store, record a peer that has proved its key, and let the
operator accept it:

```rust,no_run
use coqui_peer::{KeyMaterial, PeerId, TrustStore};

let store = TrustStore::open(std::path::Path::new("/var/lib/app"))?;

// A method hands the store the peer's public key; the id is its SHA-256.
let key = KeyMaterial::new("example", "PUBLIC KEY", vec![0u8; 32])?;
store.record_waiting(&key, Some("192.0.2.7:4000".parse()?)); // only after the key proof
store.accept(&key.id())?;
assert!(store.is_accepted(&key.id()));

// An id from text, in any accepted spelling.
let pinned: PeerId = "sha256:630dcd2966c4336691125448bbb25b4ff412a49c732db2c8abc1b8581bd710dd".parse()?;
assert_eq!(pinned, key.id());
# Ok::<(), Box<dyn std::error::Error>>(())
```

Running a method over a stream, with a handshake from a method crate:

```rust,ignore
let established = coqui_peer::drive_stream(method.initiate()?, &mut socket)?;
let peer: PeerId = established.peer;        // verified
let channel = established.session;          // what the method produced
```

With the `serde` feature `PeerId` and `Digest` serialize as their text, so a consumer that
wants TOML or JSON reads them with its own `toml` or `serde_json`.

## API overview

| Item | Purpose |
| --- | --- |
| `PeerId`, `Digest` | Id text forms, digest allow-lists, constant-time equality. |
| `TrustStore`, `WaitingEntry { id, source }`, `WaitingLimits` | Pairing store (format version 3; 1 and 2 are read). |
| `KeyMaterial` | `method`, PEM `label` and `bytes` kept by the store. |
| `Handshake`, `Method`, `Established`, `Framing` | The sans-IO trait. |
| `drive_stream`, `drive_messages`, `MessageTransport`, `asynch::*` | Loops over a transport. |

## Development

```bash
cargo fmt --all --check
cargo test --all-features
cargo clippy --all-targets --all-features -- -D warnings
```

### Releasing

This project follows [Semantic Versioning](https://semver.org/) and keeps a
[`CHANGELOG.md`](https://github.com/Boriken-Dev/coqui-peer/blob/main/CHANGELOG.md).
Pushing a tag matching `v*` triggers the release workflow of the repository.

## License

MPL-2.0 — see [LICENSE](https://github.com/Boriken-Dev/coqui-peer/blob/main/LICENSE).
