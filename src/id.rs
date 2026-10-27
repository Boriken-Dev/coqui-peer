use core::fmt;
use core::str::FromStr;

use sha2::{Digest as _, Sha256, Sha384, Sha512};
use subtle::ConstantTimeEq;

use crate::error::Error;

const BASE32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/// The algorithm a [`PeerId`] is made with: the `<alg>` of its `<alg>:<hash>` text.
///
/// [`Sha256`](Digest::Sha256) is the id of a peer by default. The others exist so a pin written
/// elsewhere can be read; whether a method accepts them is its own allow-list (a list of
/// `Digest` values). MD5 is not supported at all. Methods whose keys are named by another
/// algorithm add variants here, which is why the enum is non-exhaustive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum Digest {
    /// SHA-256, 32 bytes. The default and the only digest of an identity.
    Sha256,
    /// SHA-384, 48 bytes.
    Sha384,
    /// SHA-512, 64 bytes.
    Sha512,
    /// SHA-1, 20 bytes. Legacy interoperability only.
    Sha1,
}

impl Digest {
    /// The lowercase name used in text: `sha256`, `sha384`, `sha512`, `sha1`.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Sha256 => "sha256",
            Self::Sha384 => "sha384",
            Self::Sha512 => "sha512",
            Self::Sha1 => "sha1",
        }
    }

    /// The digest length in bytes.
    pub const fn size(self) -> usize {
        match self {
            Self::Sha256 => 32,
            Self::Sha384 => 48,
            Self::Sha512 => 64,
            Self::Sha1 => 20,
        }
    }

    /// The id of `data` under this algorithm: what a method hashes is its public key, or the
    /// encoding of its certificate.
    pub fn of(self, data: &[u8]) -> PeerId {
        let mut bytes = [0u8; 64];
        let out = &mut bytes[..self.size()];
        match self {
            Self::Sha256 => out.copy_from_slice(&Sha256::digest(data)),
            Self::Sha384 => out.copy_from_slice(&Sha384::digest(data)),
            Self::Sha512 => out.copy_from_slice(&Sha512::digest(data)),
            Self::Sha1 => out.copy_from_slice(&sha1::Sha1::digest(data)),
        }
        PeerId {
            digest: self,
            bytes,
        }
    }

    fn of_length(len: usize) -> Option<Self> {
        [Self::Sha256, Self::Sha384, Self::Sha512, Self::Sha1]
            .into_iter()
            .find(|digest| digest.size() == len)
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for Digest {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(self.name())
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for Digest {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = <alloc::borrow::Cow<'de, str>>::deserialize(deserializer)?;
        text.parse().map_err(serde::de::Error::custom)
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for PeerId {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for PeerId {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = <alloc::borrow::Cow<'de, str>>::deserialize(deserializer)?;
        text.parse().map_err(serde::de::Error::custom)
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.name())
    }
}

impl FromStr for Digest {
    type Err = Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.trim().to_ascii_lowercase().as_str() {
            "sha256" => Ok(Self::Sha256),
            "sha384" => Ok(Self::Sha384),
            "sha512" => Ok(Self::Sha512),
            "sha1" => Ok(Self::Sha1),
            "md5" => Err(Error::WeakDigest),
            other => Err(Error::UnknownDigest(other.to_owned())),
        }
    }
}

/// Who a peer is: the hash of its public key or certificate, the whole of what one peer is
/// told of another.
///
/// The canonical text form, and the [`Display`](fmt::Display) form, is `<alg>:<hash>`: the
/// algorithm name, a colon and lowercase hexadecimal, `sha256:3f15...`. For an X.509
/// certificate `openssl x509 -outform DER | sha256sum` reproduces the hex. [`FromStr`] also
/// accepts:
///
/// - bare hexadecimal of a supported digest's length (64 characters is SHA-256);
/// - hexadecimal pairs separated by colons (`AA:BB:...`), as most tools print it;
/// - for SHA-256 only, 52 base32 characters, grouped in fours by `-` or not
///   ([`to_base32_grouped`](PeerId::to_base32_grouped)), meant to be read aloud.
///
/// Text that is the length of an MD5 digest, or names `md5`, is [`Error::WeakDigest`].
/// Equality is constant time.
#[derive(Clone, Copy, Eq, PartialOrd, Ord)]
pub struct PeerId {
    digest: Digest,
    bytes: [u8; 64],
}

impl core::hash::Hash for PeerId {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.digest.hash(state);
        self.as_bytes().hash(state);
    }
}

impl PartialEq for PeerId {
    fn eq(&self, other: &Self) -> bool {
        // Both are compared whatever differs, so equality does not leak where it ends.
        bool::from(self.bytes.ct_eq(&other.bytes)) & (self.digest == other.digest)
    }
}

impl PeerId {
    /// The SHA-256 id of `data`.
    pub fn of(data: &[u8]) -> Self {
        Digest::Sha256.of(data)
    }

    /// A SHA-256 id from its 32 digest bytes.
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        let mut padded = [0u8; 64];
        padded[..32].copy_from_slice(&bytes);
        Self {
            digest: Digest::Sha256,
            bytes: padded,
        }
    }

    /// The hash this id is made with.
    pub const fn digest(&self) -> Digest {
        self.digest
    }

    /// The digest bytes: 32 for SHA-256.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.digest.size()]
    }

    /// Lowercase hexadecimal of the digest, without the name.
    pub fn hex(&self) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut text = String::with_capacity(self.digest.size() * 2);
        for byte in self.as_bytes() {
            text.push(char::from(HEX[usize::from(byte >> 4)]));
            text.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
        text
    }

    /// The canonical form: the digest name, a colon and [`hex`](PeerId::hex).
    pub fn canonical(&self) -> String {
        format!("{}:{}", self.digest, self.hex())
    }

    /// SHA-256 only: 52 uppercase base32 characters in 13 groups of four separated by `-`,
    /// for screens that show it and for reading aloud. Any other digest gives its
    /// [`canonical`](PeerId::canonical) form.
    pub fn to_base32_grouped(&self) -> String {
        if self.digest != Digest::Sha256 {
            return self.canonical();
        }
        let mut letters = String::with_capacity(52);
        let (mut held, mut bits) = (0u32, 0u32);
        for byte in self.as_bytes() {
            held = (held << 8) | u32::from(*byte);
            bits += 8;
            while bits >= 5 {
                bits -= 5;
                letters.push(char::from(BASE32[((held >> bits) & 31) as usize]));
            }
        }
        if bits > 0 {
            letters.push(char::from(BASE32[((held << (5 - bits)) & 31) as usize]));
        }
        letters
            .as_bytes()
            .chunks(4)
            .map(|chunk| core::str::from_utf8(chunk).unwrap_or_default())
            .collect::<Vec<_>>()
            .join("-")
    }
}

impl fmt::Display for PeerId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.canonical())
    }
}

impl fmt::Debug for PeerId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "PeerId({})", self.canonical())
    }
}

impl FromStr for PeerId {
    type Err = Error;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let value = value.trim();
        let lower = value.to_ascii_lowercase();
        let (named, body) = match lower.split_once(':') {
            Some((name, rest))
                if !name.is_empty()
                    && name.bytes().all(|b| b.is_ascii_alphanumeric())
                    && name.len() > 2 =>
            {
                (Some(name.parse::<Digest>()?), rest)
            }
            _ => (None, lower.as_str()),
        };
        // Colon-separated pairs: `AA:BB:...`.
        let hex: String = if body.contains(':') {
            let pairs: Vec<&str> = body.split(':').collect();
            if !pairs
                .iter()
                .all(|pair| pair.len() == 2 && pair.bytes().all(|b| b.is_ascii_hexdigit()))
            {
                return Err(Error::InvalidId);
            }
            pairs.concat()
        } else {
            body.to_owned()
        };
        let is_hex = hex.bytes().all(|byte| byte.is_ascii_hexdigit());
        if let Some(digest) = named {
            return from_hex(&hex, Some(digest));
        }
        if is_hex && matches!(hex.len(), 32 | 40 | 64 | 96 | 128) {
            return from_hex(&hex, None);
        }
        from_base32(value)
    }
}

fn from_hex(hex: &str, named: Option<Digest>) -> Result<PeerId, Error> {
    if hex.len() == 32 && named.is_none() {
        return Err(Error::WeakDigest);
    }
    let digest = Digest::of_length(hex.len() / 2).ok_or(Error::InvalidId)?;
    if !hex.len().is_multiple_of(2) || named.is_some_and(|named| named != digest) {
        return Err(Error::InvalidId);
    }
    let mut bytes = [0u8; 64];
    for (slot, pair) in bytes.iter_mut().zip(hex.as_bytes().chunks(2)) {
        *slot = (nibble(pair[0])? << 4) | nibble(pair[1])?;
    }
    Ok(PeerId { digest, bytes })
}

fn nibble(byte: u8) -> Result<u8, Error> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(Error::InvalidId),
    }
}

fn from_base32(value: &str) -> Result<PeerId, Error> {
    let letters: Vec<u8> = value
        .chars()
        .filter(|character| !matches!(character, '-' | ' ' | '\t' | '\n' | '\r'))
        .map(|character| u8::try_from(character.to_ascii_uppercase()).unwrap_or(0))
        .collect();
    if letters.len() != 52 {
        return Err(Error::InvalidId);
    }
    let mut bytes = Vec::with_capacity(33);
    let (mut held, mut bits) = (0u32, 0u32);
    for letter in letters {
        let value = BASE32
            .iter()
            .position(|candidate| *candidate == letter)
            .ok_or(Error::InvalidId)? as u32;
        held = (held << 5) | value;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            bytes.push(((held >> bits) & 0xff) as u8);
        }
    }
    // 52 symbols carry 260 bits: 256 of digest and four zero padding bits.
    if bytes.len() != 32 || (held & ((1 << bits) - 1)) != 0 {
        return Err(Error::InvalidId);
    }
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&bytes);
    Ok(PeerId::from_bytes(digest))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn colons(id: &PeerId) -> String {
        id.hex()
            .as_bytes()
            .chunks(2)
            .map(|pair| core::str::from_utf8(pair).unwrap().to_uppercase())
            .collect::<Vec<_>>()
            .join(":")
    }

    #[test]
    fn spellings_round_trip() {
        let id = PeerId::of(b"certificate");
        for spelling in [
            id.canonical(),
            id.hex(),
            id.hex().to_uppercase(),
            colons(&id),
            format!("sha256:{}", colons(&id)),
            id.to_base32_grouped(),
            id.to_base32_grouped().replace('-', "").to_lowercase(),
        ] {
            assert_eq!(spelling.parse::<PeerId>().unwrap(), id, "{spelling}");
        }
        assert_eq!(id.to_base32_grouped().len(), 52 + 12);
        assert_eq!(id.to_string(), id.canonical());
        assert!(id.to_string().starts_with("sha256:"));
    }

    #[test]
    fn other_digests_are_named_and_distinct() {
        for digest in [Digest::Sha384, Digest::Sha512, Digest::Sha1] {
            let id = digest.of(b"certificate");
            assert_eq!(id.digest(), digest);
            assert_eq!(id.as_bytes().len(), digest.size());
            assert!(id.to_string().starts_with(&format!("{digest}:")));
            for spelling in [id.canonical(), id.hex(), colons(&id)] {
                assert_eq!(spelling.parse::<PeerId>().unwrap(), id, "{spelling}");
            }
        }
        assert_ne!(Digest::Sha256.of(b"x"), Digest::Sha512.of(b"x"));
        // A name must agree with the length.
        let sha1 = Digest::Sha1.of(b"x").hex();
        assert!(format!("sha256:{sha1}").parse::<PeerId>().is_err());
    }

    #[test]
    fn malformed_and_md5_ids_are_refused() {
        let id = PeerId::of(b"certificate");
        for bad in ["", "not-a-id", "sha256:abcd", "AA:BB:C", "sha256:zz"] {
            assert!(
                matches!(bad.parse::<PeerId>(), Err(Error::InvalidId)),
                "{bad}"
            );
        }
        let md5 = "b".repeat(32);
        for weak in [md5.clone(), format!("md5:{md5}"), vec!["AB"; 16].join(":")] {
            assert!(
                matches!(weak.parse::<PeerId>(), Err(Error::WeakDigest)),
                "{weak}"
            );
        }
        let mut noncanonical = id.to_base32_grouped().replace('-', "");
        let last = noncanonical.pop().unwrap();
        noncanonical.push(if last == 'A' { 'B' } else { 'R' });
        assert!(noncanonical.parse::<PeerId>().is_err());
    }
}
