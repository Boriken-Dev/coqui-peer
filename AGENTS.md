# `coqui-peer` — API header

Header-file-style reference for the `coqui-peer` crate: every public item with its signature,
contract and gotchas, so the crate can be used without reading its source. It ships inside the
package and is self-contained. Development documentation lives with the source at
<https://github.com/Boriken-Dev/coqui-peer>.

| Feature | Adds | Default |
| --- | --- | --- |
| `serde` | `Serialize`/`Deserialize` for `PeerId` and `Digest` as text | off |
| `tokio` | `tokio` (`io-util`): module `asynch` | off |
| `pin` | `spake2`, `hkdf`, `hmac`, `rand_core` (`getrandom`): `Random::os` | off |

MSRV Rust 1.89. A default build depends on `sha1`, `sha2`, `subtle` and `data-encoding`. No
`unsafe` code. No TLS, no crypto transport, no process-global state; nothing reads a file or
an environment variable unless the caller passes a directory. Everything is built in code;
`serde` is the only way text formats come in, and the consumer picks the format.

## PeerId, Digest

```rust
#[non_exhaustive] pub enum Digest { Sha256, Sha384, Sha512, Sha1 }
impl Digest { pub const fn name(self) -> &'static str; pub const fn size(self) -> usize;
              pub fn of(self, data: &[u8]) -> PeerId; }     // FromStr: "sha256", ...; "md5" is an error
pub struct PeerId;      // Copy, Eq (constant time), Ord, Hash, Display = canonical, FromStr
impl PeerId {
    pub fn of(data: &[u8]) -> PeerId;                // SHA-256 of a public key or certificate encoding
    pub fn from_bytes(bytes: [u8; 32]) -> PeerId;    // SHA-256
    pub fn digest(&self) -> Digest;  pub fn as_bytes(&self) -> &[u8];
    pub fn hex(&self) -> String;                     // 64 lowercase hex for sha256
    pub fn canonical(&self) -> String;               // "<alg>:<hex>", also Display
    pub fn to_base32_grouped(&self) -> String;       // sha256 only: 13 groups of 4, '-' separated
}
```

Canonical text is `<alg>:<hash>`: `sha256:<64 lowercase hex>`. `FromStr` accepts `sha256:<hex>`
(also `sha384:`, `sha512:`, `sha1:`), bare hex of 64, 96, 128 or 40 characters, colon-separated
hex pairs (`AA:BB:...`, with or without the prefix), and 52 base32 characters for SHA-256
(groups optional). An MD5 digest (name `md5` or 32 hex characters) is `Error::WeakDigest`.
Which digests a method accepts is its own allow-list of `Digest` values. Compare ids through
`==`, not through strings.

## KeyMaterial

```rust
pub struct KeyMaterial { pub method: String, pub label: String, pub bytes: Vec<u8> }
impl KeyMaterial {
    pub fn new(method: impl Into<String>, label: impl Into<String>, bytes: impl Into<Vec<u8>>)
        -> Result<KeyMaterial, Error>;     // checks the fields
    pub fn id(&self) -> PeerId;            // SHA-256 of bytes
}
pub const MAX_KEY_BYTES: usize = 65536;
```

`method`: `[a-z0-9-]`, 1 to 32 characters, the `<method>` of `coqui-peer-<method>`. `label`: PEM label,
`[A-Z0-9 ]`, 1 to 64 characters (`CERTIFICATE` for `tls`). `bytes`: 1 to `MAX_KEY_BYTES`.

## TrustStore

```rust
pub struct TrustStore;                     // Clone
pub struct WaitingLimits { pub per_source: usize, pub total: usize, pub rerecord: Duration }   // Default: 16, 1000, 60 s
pub struct WaitingEntry { pub id: PeerId, pub source: Option<SocketAddr> }
pub const FORMAT_VERSION: u32 = 1;
impl TrustStore {
    pub fn open(state_dir: &Path) -> Result<TrustStore, Error>;        // creates <state_dir>/peers/{accepted,waiting}
    pub fn with_limits(self, limits: WaitingLimits) -> TrustStore;
    pub fn with_ipv6_prefix(self, bits: u8) -> TrustStore;            // default 64; above 128 is 128
    pub fn with_clock(self, clock: Clock) -> TrustStore;              // default Clock::system()
    pub fn with_rotation(self, options: RotationOptions) -> TrustStore;
    pub fn rotation(&self) -> RotationOptions;   pub fn clock(&self) -> &Clock;
    pub fn waiting(&self) -> Result<Vec<WaitingEntry>, Error>;
    pub fn accepted(&self) -> Result<Vec<PeerId>, Error>;             // retired keys not listed
    pub fn accepted_key(&self, id: &PeerId) -> Option<KeyMaterial>;   // None once retired
    pub fn waiting_key(&self, id: &PeerId) -> Option<KeyMaterial>;
    pub fn accept(&self, id: &PeerId) -> Result<(), Error>;             // waiting -> accepted
    pub fn accept_key(&self, key: &KeyMaterial) -> Result<PeerId, Error>;
    pub fn remove(&self, id: &PeerId) -> Result<bool, Error>;         // also its pending successor
    pub fn is_accepted(&self, id: &PeerId) -> bool;                   // false from Retires on
    pub fn record_waiting(&self, key: &KeyMaterial, source: Option<SocketAddr>);
    // invitations
    pub fn invite(&self, random: &Random, options: InvitationOptions, label: &str) -> Result<Invitation, Error>;
    pub fn redeem(&self, secret: &[u8; 32]) -> Result<Invitation, Error>;   // uses one; atomic
    pub fn invitations(&self) -> Result<Vec<InvitationEntry>, Error>;
    pub fn revoke_invitation(&self, id: &InvitationId) -> Result<bool, Error>;
    // rotation
    pub fn announce_successor(&self, old: &PeerId, new: &KeyMaterial) -> Result<(), Error>;
    pub fn successor_key(&self, new: &PeerId) -> Option<KeyMaterial>;
    pub fn promote_successor(&self, new: &PeerId) -> Result<PeerId, Error>; // returns old
    pub fn successors(&self) -> Result<Vec<Successor>, Error>;
    pub fn retiring(&self) -> Result<Vec<Retiring>, Error>;
    pub fn take_rotation_events(&self) -> Vec<RotationEvent>;
}
pub struct InvitationOptions { pub valid_for: Duration, pub uses: u32 }        // Default: 24 h, 1
pub struct Invitation { pub secret: [u8; 32], pub expires: SystemTime, pub uses: u32, pub label: String }
impl Invitation { pub fn id(&self) -> InvitationId; }                           // Debug hides the secret
pub struct InvitationId;   // Copy, Ord, Display/FromStr = 64 hex; InvitationId::of(&secret) = SHA-256
pub struct InvitationEntry { pub id: InvitationId, pub expires: SystemTime, pub uses: u32, pub label: String }
pub const MAX_LABEL: usize = 128;
pub struct RotationOptions { pub retire_after: Duration, pub require_approval: bool }  // Default: 24 h, false
pub struct Successor { pub old: PeerId, pub new: PeerId }
pub struct Retiring { pub id: PeerId, pub successor: Option<PeerId>, pub retires: SystemTime }
#[non_exhaustive] pub enum RotationEvent { Announced { old, new }, Promoted { old, new, retires } }
pub struct Clock;    // Clone; Clock::system(), Clock::from_fn(|| SystemTime), now()
pub struct Random;   // Clone; Random::from_fn(|&mut [u8]| -> Result<(), Error>), fill(); feature pin: Random::os()
```

**Key-proof contract (every method must meet it).** `record_waiting` is called only after the
peer proved, inside the handshake, that it holds the private key of the key it presented. A
presented key proves nothing: public keys and certificates are copied freely, and recording
them unproven lets a stranger queue somebody else's identity. A failed proof records nothing.

Pairing: a server turns away an untrusted, key-proven peer and records it; the operator lists
`waiting`, then `accept`s or `remove`s by id; the next handshake finds `is_accepted`.
`record_waiting` is bounded: invalid keys ignored, at most `per_source` entries per source
(the oldest of that source is replaced), the same peer from the same source at most every
`rerecord`, `total` in all. A source is an IPv4 address (an IPv4-mapped IPv6 address counts as
its IPv4 address) or an IPv6 prefix of `with_ipv6_prefix` bits, /64 by default, since one
holder controls every address of a /64; 128 counts each IPv6 address alone. The full address
is still stored with the entry. `None` sources share one bucket. `is_accepted` and the `*_key`
readers check that the stored bytes hash to the id.

**Invitations.** `invite` draws a 32-byte secret from `random` and writes only its SHA-256
(the `InvitationId`), its expiry, uses and label: the caller hands the secret to the joiner
with the inviter's id, and the store cannot leak it. `redeem` claims the file by renaming it,
so of concurrent redemptions of a single-use invitation exactly one wins; it returns the uses
left after it and removes the file at 0. Errors: `NotInvited` (unknown, used up, revoked),
`Expired` (the file is removed). `InvalidOptions` only for meaningless values: zero uses or
validity, a label that is not one line of at most `MAX_LABEL` bytes without surrounding
spaces. `valid_for` is counted in whole seconds; longer ones and more uses are the caller's
choice and only widen who may redeem it.

**Rotation.** `announce_successor(old, new)` is for a key the holder of `old` sent over a
session `old` authenticated; `old` must be accepted and not retiring (`NotAccepted`), `new`
not accepted (`AlreadyAccepted`) and not `old` (`Material`); a later announcement replaces the
pending one. A method calls `promote_successor(new)` once the peer proves `new` in a handshake,
unless `RotationOptions::require_approval` (then the caller calls it to approve). Promotion
accepts `new` and gives `old` `Retires: now + retire_after`; from then on `is_accepted(old)`,
`accepted_key(old)` and `accepted()` drop it. `retire_after` zero cuts the old key off at
once (connections still on it fail their next handshake); a longer one keeps a possibly stolen
old key usable that much longer. `successor_key(new)` is `Some` only while `old` is accepted, not
retiring and names `new`. `remove(old)` deletes its pending successor. Events are returned, not
reported: `take_rotation_events` drains this process's queue (at most 1024, oldest dropped);
`successors()` and `retiring()` read the state on disk.

## Handshake, Method, drivers

```rust
pub enum Framing { Stream, Message }
pub struct Established<S> { pub peer: PeerId, pub key: Option<KeyMaterial>, pub session: S }
pub trait Handshake {
    type Output; type Error: std::error::Error + Send + Sync + 'static;
    fn framing(&self) -> Framing;
    fn receive(&mut self, input: &[u8]) -> Result<(), Self::Error>;   // bytes (Stream) or one message (Message)
    fn transmit(&mut self) -> Result<Option<Vec<u8>>, Self::Error>;   // next thing to send; call until None
    fn is_complete(&self) -> bool;
    fn finish(self) -> Result<Established<Self::Output>, Self::Error>;
}
pub trait Method {
    type Handshake: Handshake;
    fn name(&self) -> &'static str;
    fn initiate(&self) -> Result<Self::Handshake, <Self::Handshake as Handshake>::Error>;
    fn respond(&self, source: Option<SocketAddr>) -> Result<Self::Handshake, <Self::Handshake as Handshake>::Error>;
}
pub trait MessageTransport { fn send(&mut self, &[u8]) -> io::Result<()>; fn recv(&mut self) -> io::Result<Vec<u8>>; }
pub fn drive_stream<H: Handshake, T: Read + Write>(H, &mut T) -> Result<Established<H::Output>, DriveError<H::Error>>;
pub fn drive_messages<H: Handshake, T: MessageTransport>(H, &mut T) -> Result<Established<H::Output>, DriveError<H::Error>>;
pub fn complete_stream<H: Handshake, T: Read + Write>(H, &mut T) -> Result<H, DriveError<H::Error>>;
pub fn complete_messages<H: Handshake, T: MessageTransport>(H, &mut T) -> Result<H, DriveError<H::Error>>;
pub enum DriveError<E> { Io(io::Error), Handshake(E), TooLong }
pub const MAX_MESSAGE: usize = 1 << 20;
// feature tokio, module asynch: MessageTransport (async fns), drive_stream, drive_messages,
// complete_stream, complete_messages
```

The handshake does no I/O; the caller owns the transport. `Stream` handshakes treat input as
bytes (chunks may split or join); `Message` handshakes get exactly one message per `receive`.
`drive_stream` length-prefixes `Message` handshakes with four big-endian bytes (at most
`MAX_MESSAGE`). `drive_messages` hands transport messages over whole for either framing, so
use it only with a reliable, ordered transport. `finish` before `is_complete` is an error;
bytes received past the end of the handshake stay in `Output`. `Output` is `()` for a method
that only authenticates, session keys, or an encrypted channel.

`complete_stream` / `complete_messages` run the same loop and return the handshake once
`is_complete`, everything it queued sent, without calling `finish`: for a method with a finish
of its own, such as a TLS server that does not authenticate its client at that layer and so
has no `PeerId` to put in `Established` (`coqui-peer-tls`'s `TlsHandshake::finish_unauthenticated`).
`drive_*` is `complete_*` followed by `finish`. `is_complete` says the exchange is over;
`finish` succeeds when the method verified a peer.

## Errors

`Error` (non-exhaustive): `InvalidId`, `WeakDigest`, `UnknownDigest(String)`, `Material`,
`NotWaiting`, `AlreadyAccepted`, `NotAccepted`, `NoSuccessor`, `NotInvited`, `Expired`,
`InvalidOptions`, `InvalidCode`, `Random`, `Io(io::Error)`. `Display` never includes key
material, secrets or paths.

## On-disk store format (version 1)

For peers in other languages. UTF-8, LF. Under `<state_dir>/peers/`: `accepted/`, `waiting/`
and `successors/` hold `<64 lowercase hex>.pem`, the name being the SHA-256 id of the key bytes
(no `sha256:` prefix: `:` is not valid in Windows file names); `invitations/` holds
`<64 lowercase hex>.inv`, named by the SHA-256 of the secret. A key file is header lines, then
one PEM block:

```text
Source: 192.0.2.7:4000        waiting files only, optional; IPv6 as [addr]:port
Predecessor: <64 hex>         successors/ only: the accepted key that announced it
Method: tls                   the method name
Successor: <64 hex>           accepted only, optional: announced (pending) or promoted successor
Retires: 1800086400           accepted only, optional: unix seconds; refused from then on
-----BEGIN CERTIFICATE-----   the label the method chose
...base64 of the key bytes, 64-character lines...
-----END CERTIFICATE-----
```

A successor is pending while `successors/<new>.pem` names the accepted key and that key's
`Successor:` names it back without a `Retires:` line. An invitation file is header lines only,
never the secret:

```text
Expires: 1800086400           unix seconds
Uses: 2                       redemptions left, at least 1
Label: kitchen tablet         optional, one line
```

`Method:` is required, and a file named other than by 64 lowercase hex is not read.
Accepting rewrites a waiting file without `Source:`. Vectors: `tests/vectors/store`,
`*.fingerprint` (canonical, bare hex, grouped base32), `example-key.id`, checked by
`tests/vectors.rs`; the store tree is written at unix time 1800000000 with the invitation
secret `0xa0..=0xbf`.
