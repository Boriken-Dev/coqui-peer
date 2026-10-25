# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- `coqui-peer`, the method-independent core, extracted from
  [Boriken-Dev/coqui-peer-tls](https://github.com/Boriken-Dev/coqui-peer-tls). The code moved
  from there; this repository starts with a fresh history.
  - `PeerId` (was `Fingerprint`): canonical text `<alg>:<hash>`, parsing of bare hex, colon
    hex and grouped base32, a digest allow-list type and constant-time equality.
  - `TrustStore`, `WaitingEntry { id, source }`, `WaitingLimits`: the accepted and waiting
    store with per-source caps and the rerecord interval. On-disk format version 3 records the
    method name beside the key bytes (`Method:` line); versions 1 and 2 still read, as `tls`.
  - `KeyMaterial`: the bytes, PEM label and method name a method gives the store.
  - The pairing flow and the contract that a peer is recorded only after it proved its key.
  - A sans-IO `Handshake` / `Method` pair that works over streams and message transports,
    with blocking helpers and, behind `tokio`, async ones.

Depend on this repository by revision:
`coqui-peer = { git = "https://github.com/Boriken-Dev/coqui-peer", rev = "<commit>" }`.
The crate is not published to crates.io.
