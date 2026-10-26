# `coqui-peer` — API header

Header-file-style reference for the `coqui-peer` crate: every public item with its signature,
contract and gotchas, so the crate can be used without reading its source. It ships inside the
package and is self-contained. Development documentation lives with the source at
<https://github.com/Boriken-Dev/coqui-peer>.

| Feature | Adds | Default |
| --- | --- | --- |
| `serde` | `Serialize`/`Deserialize` for `PeerId` and `Digest` as text | off |
| `tokio` | `tokio` (`io-util`): module `asynch` | off |

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
pub const FORMAT_VERSION: u32 = 3;
impl TrustStore {
    pub fn open(state_dir: &Path) -> Result<TrustStore, Error>;        // creates <state_dir>/peers/{accepted,waiting}
    pub fn with_limits(self, limits: WaitingLimits) -> TrustStore;
    pub fn with_ipv6_prefix(self, bits: u8) -> TrustStore;            // default 64; above 128 is 128
    pub fn waiting(&self) -> Result<Vec<WaitingEntry>, Error>;
    pub fn accepted(&self) -> Result<Vec<PeerId>, Error>;
    pub fn accepted_key(&self, id: &PeerId) -> Option<KeyMaterial>;
    pub fn waiting_key(&self, id: &PeerId) -> Option<KeyMaterial>;
    pub fn accept(&self, id: &PeerId) -> Result<(), Error>;             // waiting -> accepted
    pub fn accept_key(&self, key: &KeyMaterial) -> Result<PeerId, Error>;
    pub fn remove(&self, id: &PeerId) -> Result<bool, Error>;
    pub fn is_accepted(&self, id: &PeerId) -> bool;
    pub fn record_waiting(&self, key: &KeyMaterial, source: Option<SocketAddr>);
}
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
`NotWaiting`, `AlreadyAccepted`, `Io(io::Error)`. `Display` never includes key material or
paths.

## On-disk store format (version 3)

For peers in other languages. UTF-8, LF. Under `<state_dir>/peers/`: `accepted/<64 lowercase hex>.pem`
and `waiting/<64 lowercase hex>.pem`, the name being the SHA-256 id of the key bytes (no `sha256:`
prefix: `:` is not valid in Windows file names). A file is header lines, then one PEM block:

```text
Source: 192.0.2.7:4000        waiting files only, optional; IPv6 as [addr]:port
Method: tls                   the method name
-----BEGIN CERTIFICATE-----   the label the method chose
...base64 of the key bytes, 64-character lines...
-----END CERTIFICATE-----
```

Files without `Method:` (versions 1 and 2) read as `tls`; version 1 files have no `Source:`
and may be named by the grouped base32 spelling, which is also read. Accepting rewrites a
waiting file without `Source:`. Vectors: `tests/vectors/store-v{1,2,3}`, `*.fingerprint`
(canonical, bare hex, grouped base32), `example-key.id`, checked by `tests/vectors.rs`.
Format changes bump the version and the changelog; older versions stay readable.
