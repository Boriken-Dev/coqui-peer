use std::collections::{HashMap, VecDeque};
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::net::{IpAddr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::error::Error;
use crate::id::PeerId;
use crate::key::{KeyMaterial, decode_pem, encode_pem};

/// The version of the on-disk format [`TrustStore`] writes. Versions 1 and 2 stay readable.
pub const FORMAT_VERSION: u32 = 3;

/// The method of a file that has no `Method:` line: files of versions 1 and 2 only held
/// certificates.
const LEGACY_METHOD: &str = "tls";

/// The IPv6 prefix length a waiting source is grouped by, unless the store is given another:
/// one /64 is the usual end-site subnet, and its holder can use any address in it.
const DEFAULT_IPV6_PREFIX: u8 = 64;

/// Bounds on the waiting queue.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WaitingLimits {
    /// Entries one source may hold; the oldest of its own is replaced. A source is an IPv4
    /// address, or an IPv6 prefix ([`TrustStore::with_ipv6_prefix`], /64 by default).
    pub per_source: usize,
    /// Entries the whole directory may hold; past it nothing is recorded.
    pub total: usize,
    /// How long the same peer from the same source is not recorded again.
    pub rerecord: Duration,
}

impl Default for WaitingLimits {
    fn default() -> Self {
        Self {
            per_source: 16,
            total: 1_000,
            rerecord: Duration::from_secs(60),
        }
    }
}

/// A peer waiting for acceptance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WaitingEntry {
    /// The peer's id.
    pub id: PeerId,
    /// The address the handshake came from; `None` when the caller did not know it, or for an
    /// entry written before the store kept it.
    pub source: Option<SocketAddr>,
}

/// Persistent trust: peers an operator accepted, and peers that were turned away and wait to
/// be accepted (pairing).
///
/// # Pairing
///
/// 1. A server turns away a peer it does not trust, **after the peer proved it holds the
///    key it presented**, and records its key with [`record_waiting`](TrustStore::record_waiting).
/// 2. The operator lists [`waiting`](TrustStore::waiting) and either
///    [`accept`](TrustStore::accept)s an entry by id or [`remove`](TrustStore::remove)s it.
/// 3. The next handshake finds the peer [`is_accepted`](TrustStore::is_accepted).
///
/// **Every method must meet this contract:** nothing is recorded as waiting until the peer
/// has shown, inside the handshake, that it holds the private key of the public key it
/// presents (a signature over the handshake transcript, a key exchange that only the key's
/// holder can complete, ...). Presenting a key proves nothing: anyone can copy a public
/// certificate, and a store that records unproven keys lets a stranger fill the queue with
/// somebody else's identity, or put a real peer's id in front of the operator under a source
/// address that is not theirs. A handshake that fails to prove the key records nothing.
///
/// # Key material and methods
///
/// The store keeps the bytes a method hands it as a [`KeyMaterial`] and never interprets
/// them: a PEM certificate for `tls`, another method's own key for it. Each file records the
/// method name, so a store can hold the keys of several methods side by side, and a method
/// reads only the entries that name it. The id of an entry is the SHA-256 of its bytes; the
/// store checks that when it reads a file.
///
/// # On-disk format (version 3)
///
/// Under `<state_dir>/peers/`:
///
/// ```text
/// accepted/<64 lowercase hex>.pem   one PEM block; the name is the peer's id
/// waiting/<64 lowercase hex>.pem    the same, for a peer that proved its key and was refused
/// ```
///
/// Before the PEM block a file may hold header lines (PEM allows explanatory text there):
/// `Method: <name>` and, in a waiting file, `Source: <ip>:<port>` (IPv6 as `[addr]:port`),
/// the address the handshake came from. The block's label is the one the method chose
/// (`CERTIFICATE` for `tls`) and its content is the key bytes. Files of versions 1 and 2 have
/// no `Method:` line and read as `tls`; version 1 files have no `Source:` line either.
/// Names in the grouped base32 spelling are also read; new files are always written with the
/// hex name. Accepting moves a file from `waiting/` to `accepted/`, rewritten without the
/// `Source:` line.
#[derive(Debug, Clone)]
pub struct TrustStore {
    root: PathBuf,
    seen: Arc<Mutex<Seen>>,
    limits: WaitingLimits,
    ipv6_prefix: u8,
}

/// Waiting entries recorded by this process, per source ([`source_key`]), oldest first.
#[derive(Debug, Default)]
struct Seen {
    sources: HashMap<Option<IpAddr>, VecDeque<(PeerId, Instant)>>,
}

/// What a store file holds.
struct Entry {
    key: KeyMaterial,
    source: Option<SocketAddr>,
}

impl TrustStore {
    /// Opens (creating when absent) the store under `<state_dir>/peers`.
    ///
    /// # Errors
    ///
    /// [`Error::Io`] when the directories cannot be created.
    pub fn open(state_dir: &Path) -> Result<Self, Error> {
        let root = state_dir.join("peers");
        fs::create_dir_all(root.join("accepted")).map_err(Error::Io)?;
        fs::create_dir_all(root.join("waiting")).map_err(Error::Io)?;
        Ok(Self {
            root,
            seen: Arc::default(),
            limits: WaitingLimits::default(),
            ipv6_prefix: DEFAULT_IPV6_PREFIX,
        })
    }

    /// This store with other bounds on its waiting queue (the default: 16 per source, 1000 in
    /// all, 60 seconds).
    #[must_use]
    pub fn with_limits(mut self, limits: WaitingLimits) -> Self {
        self.limits = limits;
        self
    }

    /// This store with IPv6 sources grouped by their first `bits` bits for the per-source
    /// limits (64 unless set). 128 counts each address alone, which lets the holder of a
    /// subnet fill the queue; values above 128 are 128. IPv4 sources, IPv4-mapped IPv6 ones
    /// included, always count per address.
    #[must_use]
    pub fn with_ipv6_prefix(mut self, bits: u8) -> Self {
        self.ipv6_prefix = bits.min(128);
        self
    }

    /// Peers awaiting operator acceptance, sorted by id, each with the address it connected
    /// from. Every entry proved it holds its key.
    ///
    /// # Errors
    ///
    /// [`Error::Io`] when the directory cannot be read.
    pub fn waiting(&self) -> Result<Vec<WaitingEntry>, Error> {
        Ok(self
            .list("waiting")?
            .into_iter()
            .map(|id| WaitingEntry {
                id,
                source: self.read("waiting", &id).and_then(|entry| entry.source),
            })
            .collect())
    }

    /// Accepted ids, sorted.
    ///
    /// # Errors
    ///
    /// [`Error::Io`] when the directory cannot be read.
    pub fn accepted(&self) -> Result<Vec<PeerId>, Error> {
        self.list("accepted")
    }

    /// The key material of an accepted peer, when it is accepted and its file is sound.
    pub fn accepted_key(&self, id: &PeerId) -> Option<KeyMaterial> {
        self.read("accepted", id).map(|entry| entry.key)
    }

    /// The key material of a waiting peer, when it is waiting and its file is sound.
    pub fn waiting_key(&self, id: &PeerId) -> Option<KeyMaterial> {
        self.read("waiting", id).map(|entry| entry.key)
    }

    /// Accepts a waiting peer by its id.
    ///
    /// # Errors
    ///
    /// [`Error::NotWaiting`], [`Error::AlreadyAccepted`], or [`Error::Material`] when the
    /// stored key does not hash to the name.
    pub fn accept(&self, id: &PeerId) -> Result<(), Error> {
        if self.is_accepted(id) {
            return Err(Error::AlreadyAccepted);
        }
        let path = self.existing("waiting", id).ok_or(Error::NotWaiting)?;
        let text = fs::read_to_string(&path).map_err(|error| {
            if error.kind() == io::ErrorKind::NotFound {
                Error::NotWaiting
            } else {
                Error::Io(error)
            }
        })?;
        let entry = parse(&text).ok_or(Error::Material)?;
        if entry.key.id() != *id {
            return Err(Error::Material);
        }
        self.write_accepted(&entry.key)?;
        let _ = fs::remove_file(path);
        Ok(())
    }

    /// Accepts a key directly, without it having waited.
    ///
    /// # Errors
    ///
    /// [`Error::Material`] when the key is not valid, [`Error::AlreadyAccepted`] when it is
    /// accepted already, [`Error::Io`] on write failure.
    pub fn accept_key(&self, key: &KeyMaterial) -> Result<PeerId, Error> {
        key.check()?;
        let id = key.id();
        self.write_accepted(key)?;
        let _ = fs::remove_file(self.path("waiting", &id));
        Ok(id)
    }

    /// Removes an accepted or waiting peer; `true` when something was removed.
    ///
    /// # Errors
    ///
    /// [`Error::Io`] when a file cannot be removed.
    pub fn remove(&self, id: &PeerId) -> Result<bool, Error> {
        let mut removed = false;
        for section in ["accepted", "waiting"] {
            if let Some(path) = self.existing(section, id) {
                fs::remove_file(path).map_err(Error::Io)?;
                removed = true;
            }
        }
        Ok(removed)
    }

    /// Whether `id` is accepted and its stored key really hashes to it.
    pub fn is_accepted(&self, id: &PeerId) -> bool {
        self.read("accepted", id).is_some()
    }

    /// Records a turned-away peer's key as waiting. Failures are not reported to the peer.
    ///
    /// **Call this only after the peer proved it holds the key** (see the
    /// [pairing contract](TrustStore#pairing)).
    ///
    /// Bounded: invalid keys are ignored; one source holds at most
    /// [`per_source`](WaitingLimits::per_source) entries (its oldest is replaced); the same
    /// peer from the same source is recorded at most once per
    /// [`rerecord`](WaitingLimits::rerecord); the directory holds at most
    /// [`total`](WaitingLimits::total). A source is an IPv4 address (IPv4-mapped IPv6 included)
    /// or an IPv6 prefix of [`with_ipv6_prefix`](TrustStore::with_ipv6_prefix) bits, /64 by
    /// default. The full `source` address is stored with the entry. `None` is the source of
    /// callers that do not know it, which share one bucket.
    pub fn record_waiting(&self, key: &KeyMaterial, source: Option<SocketAddr>) {
        if key.check().is_err() {
            return;
        }
        let id = key.id();
        if self.existing("waiting", &id).is_some() {
            return;
        }
        let Ok(entries) = fs::read_dir(self.root.join("waiting")) else {
            return;
        };
        if entries.take(self.limits.total).count() >= self.limits.total {
            return;
        }
        let mut seen = self.seen.lock().unwrap_or_else(PoisonError::into_inner);
        let bucket = source.map(|s| source_key(s.ip(), self.ipv6_prefix));
        let held = seen.sources.entry(bucket).or_default();
        let now = Instant::now();
        if held
            .iter()
            .any(|(had, at)| *had == id && now.duration_since(*at) < self.limits.rerecord)
        {
            return;
        }
        held.retain(|(had, _)| *had != id);
        held.push_back((id, now));
        while held.len() > self.limits.per_source {
            if let Some((old, _)) = held.pop_front() {
                let _ = fs::remove_file(self.path("waiting", &old));
            }
        }
        let mut text = source.map_or_else(String::new, |s| format!("Source: {s}\n"));
        text.push_str(&format!("Method: {}\n", key.method));
        text.push_str(&encode_pem(&key.label, &key.bytes));
        let _ = write_new(&self.path("waiting", &id), &text);
    }

    fn write_accepted(&self, key: &KeyMaterial) -> Result<(), Error> {
        let text = format!(
            "Method: {}\n{}",
            key.method,
            encode_pem(&key.label, &key.bytes)
        );
        match write_new(&self.path("accepted", &key.id()), &text) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                Err(Error::AlreadyAccepted)
            }
            Err(error) => Err(Error::Io(error)),
        }
    }

    /// The sound entry for `id` in `section`: its file parses and its key hashes to `id`.
    fn read(&self, section: &str, id: &PeerId) -> Option<Entry> {
        let text = fs::read_to_string(self.existing(section, id)?).ok()?;
        parse(&text).filter(|entry| entry.key.id() == *id)
    }

    fn list(&self, section: &str) -> Result<Vec<PeerId>, Error> {
        let mut ids = Vec::new();
        for entry in fs::read_dir(self.root.join(section)).map_err(Error::Io)? {
            let path = entry.map_err(Error::Io)?.path();
            if path.extension().is_some_and(|extension| extension == "pem")
                && let Some(Ok(id)) = path
                    .file_stem()
                    .and_then(|stem| stem.to_str())
                    .map(str::parse::<PeerId>)
                && !ids.contains(&id)
            {
                ids.push(id);
            }
        }
        ids.sort();
        Ok(ids)
    }

    fn path(&self, section: &str, id: &PeerId) -> PathBuf {
        self.root.join(section).join(format!("{}.pem", id.hex()))
    }

    /// The file for `id` in `section`, under either accepted spelling of the name.
    fn existing(&self, section: &str, id: &PeerId) -> Option<PathBuf> {
        let current = self.path(section, id);
        if current.is_file() {
            return Some(current);
        }
        let legacy = self
            .root
            .join(section)
            .join(format!("{}.pem", id.to_base32_grouped()));
        legacy.is_file().then_some(legacy)
    }
}

/// The source an address counts against: IPv4 as it is, IPv4-mapped IPv6 as the IPv4 address,
/// other IPv6 cut to its first `prefix` bits.
fn source_key(address: IpAddr, prefix: u8) -> IpAddr {
    match address {
        IpAddr::V4(_) => address,
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => {
                let mask = u128::MAX.checked_shl(128 - u32::from(prefix)).unwrap_or(0);
                IpAddr::V6(Ipv6Addr::from(u128::from(v6) & mask))
            }
        },
    }
}

/// Reads a store file: header lines, then one PEM block.
fn parse(text: &str) -> Option<Entry> {
    let (headers, label, bytes) = decode_pem(text)?;
    let mut method = LEGACY_METHOD;
    let mut source = None;
    for line in headers {
        if let Some(value) = line.strip_prefix("Method: ") {
            method = value.trim();
        } else if let Some(value) = line.strip_prefix("Source: ") {
            source = value.trim().parse().ok();
        }
    }
    let key = KeyMaterial::new(method, label, bytes).ok()?;
    Some(Entry { key, source })
}

/// Writes `text` to `path` unless it exists, atomically.
fn write_new(path: &Path, text: &str) -> io::Result<()> {
    let temporary = temporary_path(path);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)?;
    let result = file
        .write_all(text.as_bytes())
        .and_then(|()| file.sync_all())
        .and_then(|()| fs::hard_link(&temporary, path));
    drop(file);
    let _ = fs::remove_file(&temporary);
    result
}

fn temporary_path(path: &Path) -> PathBuf {
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_nanos());
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(format!(".{}.{}.tmp", std::process::id(), nonce));
    path.with_file_name(name)
}
