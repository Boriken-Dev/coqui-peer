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

- `TrustStore::with_ipv6_prefix(bits)`: the IPv6 prefix length waiting sources are grouped
  by, 64 by default.

### Changed

- The per-source waiting limits (`per_source`, `rerecord`) count an IPv6 source by its /64
  prefix, not by address, so one subnet's holder can no longer fill the queue from many
  addresses. IPv4 sources still count per address, and an IPv4-mapped IPv6 address counts as
  its IPv4 address. The full address is still stored with each entry.

Depend on this repository by revision:
`coqui-peer = { git = "https://github.com/Boriken-Dev/coqui-peer", rev = "<commit>" }`.
The crate is not published to crates.io.
