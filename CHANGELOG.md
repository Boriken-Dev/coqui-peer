# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Changed

- The `_until` drivers bound writes as well as reads: they take a transport that implements the
  new `WriteTimeout` trait beside `ReadTimeout` (`drive_stream_until`, `complete_stream_until`,
  `drive_messages_until`, `complete_messages_until`), set its write timeout to what is left
  before every write, send and flush, and clear it before returning. A peer that stops reading
  ends the loop at its deadline with `DriveError::TimedOut` instead of holding it. A transport
  of your own implements `WriteTimeout` (a no-op where it cannot time out). A `TimedOut` or
  `WouldBlock` transport error inside such a loop is reported as `DriveError::TimedOut`.

### Added

- `ReadTimeout` and `WriteTimeout` for `&TcpStream`, so a socket another thread may shut down
  is driven through a shared reference.

## [0.0.0-alpha.0] - 2026-10-27

The first pre-release, published to crates.io. The API may change in any release before 1.0.

### Added

- `PeerId` and `Digest`: canonical text `<alg>:<hash>`, parsing of bare hex, colon hex and
  grouped base32, a digest allow-list type and constant-time equality.
- `TrustStore`, `WaitingEntry { id, source }`, `WaitingLimits`: accepted and waiting peers on
  disk (format version 1), each file recording the method name beside the key bytes
  (`Method:` line), with per-source caps (IPv4 per address, an IPv4-mapped IPv6 address as its
  IPv4 address, IPv6 by a prefix of `with_ipv6_prefix` bits, /64 by default) and the rerecord
  interval. A peer is recorded only after it proved its key.
- `WaitingQueue` and `Admission`: the waiting queue's bounds without the storage, for a host
  that keeps waiting entries elsewhere (`admit`, `remember`, `forget`); the store uses it.
- `KeyMaterial`: the bytes, PEM label and method name a method gives the store.
- A sans-IO `Handshake` / `Method` pair that works over streams and message transports, with
  blocking drivers (`drive_stream`, `drive_messages`, and `complete_stream` /
  `complete_messages`, which return the completed handshake for a method-specific finish), their
  `_until` forms that end at a deadline with `DriveError::TimedOut` (reads bounded through
  `ReadTimeout`, implemented for `TcpStream`), and, behind `tokio`, the async forms of all of
  them.
- `read_frame` and `write_frame` (and their `asynch` forms): the length-prefixed frame format
  of the drivers, at most `MAX_MESSAGE`; the reader grows its buffer as bytes arrive.
- `file::{write_new, replace, Access}` and `pem::{encode, decode, Block}`: the store's atomic
  writes (no-replace and replacing, parent directories created, owner-only on request) and its
  PEM block format, for method crates. On Windows a rename, link or removal that another handle
  blocks is retried for about a second.
- Invitations in the `TrustStore`: `invite` (a 32-byte secret from a caller-supplied
  `Random`, `InvitationOptions` for validity and uses), `redeem` (atomic, one use at a time),
  `invitations` and `revoke_invitation`, which wins over redemptions in flight. The store keeps
  only the SHA-256 of the secret.
- Key rotation in the `TrustStore`: `announce_successor`, `successor_key`, `prove_successor`,
  `promote_successor`, `successors`, `retiring` and `take_rotation_events`, with
  `RotationOptions` (retire window, default 24 hours; `require_approval`; `allow_unproven`). A
  promoted key's predecessor is refused from its retirement time on; accepting a retired key
  makes it current again.
- Pairing, module `pair`: a sans-IO exchange over any channel by invitation, by PIN (SPAKE2
  with HKDF and HMAC key confirmation over both keys and an optional channel binding; feature
  `pin`) or by an RFC 8628-style device flow; `PairingDesk` for the responder's shown PIN,
  slots, user codes, approvals and throttles; `PairingOptions` and `DeskLimits` with defaults
  and `weakened()`; `CodeAlphabet`, `Pin`, `UserCode`; the `Rotation` announcement message;
  responder deadlines (`deadline`, `time_left`, `check_deadline`). Message vectors in
  `tests/vectors/pair/`.
- `Weakening { setting, value, strict }`: a setting looser than its strict default, the one type
  every crate of the family reports weakenings with.
- `Clock` (an injectable wall clock, `TrustStore::with_clock`) and `Random` (a caller-supplied
  secure random source; `Random::os` with the `pin` feature).
- Invitation secrets, PINs and the PIN exchange's keys are zeroed when dropped, and a
  `pair::Channel`'s `Debug` hides its binding. Error messages never quote input, key material
  or paths.

[Unreleased]: https://github.com/Boriken-Dev/coqui-peer/compare/v0.0.0-alpha.0...HEAD
[0.0.0-alpha.0]: https://github.com/Boriken-Dev/coqui-peer/releases/tag/v0.0.0-alpha.0
