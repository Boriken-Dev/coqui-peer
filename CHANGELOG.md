# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/).

## [Unreleased]


### Added

- `PeerId` and `Digest`: canonical text `<alg>:<hash>`, parsing of bare hex, colon hex and
  grouped base32, a digest allow-list type and constant-time equality.
- `TrustStore`, `WaitingEntry { id, source }`, `WaitingLimits`: accepted and waiting peers on
  disk (format version 1), each file recording the method name beside the key bytes
  (`Method:` line), with per-source caps (IPv4 per address, an IPv4-mapped IPv6 address as its
  IPv4 address, IPv6 by a prefix of `with_ipv6_prefix` bits, /64 by default) and the rerecord
  interval.
- `KeyMaterial`: the bytes, PEM label and method name a method gives the store.
- The pairing flow and the contract that a peer is recorded only after it proved its key.
- A sans-IO `Handshake` / `Method` pair that works over streams and message transports, with
  blocking helpers (`drive_stream`, `drive_messages`, and `complete_stream` /
  `complete_messages`, which return the completed handshake for a method-specific finish)
  and, behind `tokio`, async ones.
- Invitations in the `TrustStore`: `invite` (a 32-byte secret from a caller-supplied
  `Random`, `InvitationOptions` for validity and uses), `redeem` (atomic, one use at a time),
  `invitations` and `revoke_invitation`. The store keeps only the SHA-256 of the secret.
- Key rotation in the `TrustStore`: `announce_successor`, `successor_key`, `promote_successor`,
  `successors`, `retiring` and `take_rotation_events`, with `RotationOptions` (retire window,
  default 24 hours; `require_approval`). A promoted key's predecessor is refused from its
  retirement time on.
- Pairing, module `pair`: a sans-IO exchange over any channel by invitation, by PIN (SPAKE2
  with HKDF and HMAC key confirmation over both keys and an optional channel binding; feature
  `pin`) or by an RFC 8628-style device flow; `PairingDesk` for the responder's shown PIN,
  slots, user codes, approvals and throttles; `PairingOptions` and `DeskLimits` with defaults
  and `weakened()`; `CodeAlphabet`, `Pin`, `UserCode`; the `Rotation` announcement message.
  Message vectors in `tests/vectors/pair/`.
- Accepting a key past its retirement time (`accept`, `accept_key`, and so a new pairing)
  makes it current again.
- `revoke_invitation` wins over redemptions in flight: a `.revoked` record refuses them and
  keeps their remaining uses from being restored.
- `TrustStore::prove_successor` records that a successor's holder proved it (`Proven:`);
  `promote_successor` requires that unless `RotationOptions::allow_unproven`.
- `pair::Channel::verified`: the device flow's joiner needs a channel that verified the
  responder (a pin, or roots), not only one that proved its key.
- A responder's `deadline()` and `check_deadline()`: a stalled exchange ends after `pin_ttl`
  or `device_ttl`. `DeskLimits::pending_per_source` (default 4) bounds pending exchanges per
  source in every mode.
- A device-flow label or user code with a control or bidirectional formatting character is
  refused on receipt as well as when sent.
- Invitation secrets, PINs and the PIN exchange's keys are zeroed when dropped (`zeroize`), and
  a `pair::Channel`'s `Debug` hides its binding.
- `Error::SuccessorTaken`: an accepted key cannot announce the pending successor of another.
- `Clock` (an injectable wall clock, `TrustStore::with_clock`) and `Random` (a caller-supplied
  secure random source; `Random::os` with the `pin` feature).

Depend on this repository by revision:
`coqui-peer = { git = "https://github.com/Boriken-Dev/coqui-peer", rev = "<commit>" }`.
The crate is not published to crates.io.
