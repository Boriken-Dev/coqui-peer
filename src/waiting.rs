//! The bounds on a waiting queue, kept apart from where its entries are stored.

use alloc::collections::VecDeque;
use core::net::{IpAddr, SocketAddr};
use core::time::Duration;
use std::collections::HashMap;
use std::time::Instant;

use crate::id::PeerId;
use crate::store::{DEFAULT_IPV6_PREFIX, WaitingLimits, source_key};

/// The least time between two new records from one source, unless
/// [`with_record_interval`](WaitingQueue::with_record_interval) says otherwise.
pub const DEFAULT_RECORD_INTERVAL: Duration = Duration::from_secs(1);

/// What a source at [`per_source`](WaitingLimits::per_source) entries does with a newcomer.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[non_exhaustive]
pub enum WhenFull {
    /// Refuses the newcomer and leaves those waiting alone. A flood can fill a source, so that
    /// nobody new is recorded from it until an operator clears it, but cannot remove anyone.
    #[default]
    Refuse,
    /// Replaces the source's oldest entry. Peers sharing a source (everyone behind one reverse
    /// proxy, when it is what connects) can then flush each other from the queue.
    ReplaceOldest,
}

/// What [`WaitingQueue::admit`] decided for one peer.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Admission {
    /// Whether to record the peer as waiting now.
    pub record: bool,
    /// Entries of the same source to remove first, oldest first; always empty unless the queue
    /// is [`WhenFull::ReplaceOldest`].
    pub evict: Vec<PeerId>,
}

/// Decides which unaccepted peers are recorded as waiting, without storing anything: the
/// policy of [`TrustStore::record_waiting`](crate::TrustStore::record_waiting), for a host
/// that keeps its waiting entries elsewhere.
///
/// A source is an IPv4 address (an IPv4-mapped IPv6 address counts as its IPv4 address), an
/// IPv6 prefix of [`with_ipv6_prefix`](WaitingQueue::with_ipv6_prefix) bits (/64 unless set,
/// since one holder controls every address of a /64), or no address at all, which is one
/// source. The queue remembers what it admitted, per source, oldest first; it forgets nothing
/// on its own, beyond the `per_source` entries it keeps for each source.
#[derive(Debug, Clone)]
pub struct WaitingQueue {
    limits: WaitingLimits,
    ipv6_prefix: u8,
    when_full: WhenFull,
    record_interval: Duration,
    sources: HashMap<Option<IpAddr>, VecDeque<(PeerId, Instant)>>,
}

impl WaitingQueue {
    /// An empty queue under `limits`, grouping IPv6 sources by /64.
    pub fn new(limits: WaitingLimits) -> Self {
        Self {
            limits,
            ipv6_prefix: DEFAULT_IPV6_PREFIX,
            when_full: WhenFull::default(),
            record_interval: DEFAULT_RECORD_INTERVAL,
            sources: HashMap::new(),
        }
    }

    /// This queue grouping IPv6 sources by their first `bits` bits (values above 128 are 128).
    #[must_use]
    pub fn with_ipv6_prefix(mut self, bits: u8) -> Self {
        self.ipv6_prefix = bits.min(128);
        self
    }

    /// This queue doing `when_full` with a newcomer to a full source; [`WhenFull::Refuse`] unless
    /// set.
    #[must_use]
    pub fn with_when_full(mut self, when_full: WhenFull) -> Self {
        self.when_full = when_full;
        self
    }

    /// This queue recording a new peer from one source at most once per `interval`, each record
    /// being a synced write a stranger can cause; [`DEFAULT_RECORD_INTERVAL`] unless set, and zero
    /// is no limit.
    #[must_use]
    pub fn with_record_interval(mut self, interval: Duration) -> Self {
        self.record_interval = interval;
        self
    }

    /// What it does with a newcomer to a full source.
    pub fn when_full(&self) -> WhenFull {
        self.when_full
    }

    /// The least time between two new records from one source.
    pub fn record_interval(&self) -> Duration {
        self.record_interval
    }

    /// The limits it applies.
    pub fn limits(&self) -> WaitingLimits {
        self.limits
    }

    /// The IPv6 prefix length sources are grouped by.
    pub fn ipv6_prefix(&self) -> u8 {
        self.ipv6_prefix
    }

    /// Decides whether `id`, from `source`, is recorded now.
    ///
    /// `stored` is how many waiting entries the host holds; at
    /// [`total`](WaitingLimits::total) or above, nothing is recorded (the newcomer waits, no
    /// entry is dropped for it). The same peer from the same source is recorded again only
    /// after [`rerecord`](WaitingLimits::rerecord). A source records a new peer at most once per
    /// [`record_interval`](WaitingQueue::record_interval). A source at
    /// [`per_source`](WaitingLimits::per_source) does what [`WhenFull`] says: by default the
    /// newcomer is not recorded; with [`WhenFull::ReplaceOldest`] its oldest entries are listed in
    /// [`Admission::evict`] for the host to remove. The host checks itself whether `id` is
    /// already stored, and does not call this then.
    pub fn admit(
        &mut self,
        id: PeerId,
        source: Option<SocketAddr>,
        stored: usize,
        now: Instant,
    ) -> Admission {
        let refused = Admission {
            record: false,
            evict: Vec::new(),
        };
        if stored >= self.limits.total {
            return refused;
        }
        let bucket = source.map(|source| source_key(source.ip(), self.ipv6_prefix));
        let held = self.sources.entry(bucket).or_default();
        if held.iter().any(|(had, at)| {
            *had == id && now.saturating_duration_since(*at) < self.limits.rerecord
        }) {
            return refused;
        }
        let interval = self.record_interval;
        if held
            .iter()
            .any(|(_, at)| now.saturating_duration_since(*at) < interval)
        {
            return refused;
        }
        held.retain(|(had, _)| *had != id);
        if self.when_full == WhenFull::Refuse && held.len() >= self.limits.per_source {
            return refused;
        }
        held.push_back((id, now));
        let mut evict = Vec::new();
        while held.len() > self.limits.per_source {
            if let Some((old, _)) = held.pop_front() {
                evict.push(old);
            }
        }
        Admission {
            record: true,
            evict,
        }
    }

    /// Remembers that `id` from `source` was recorded at `at`, for a host that seeds the queue
    /// from entries it stored earlier. Entries past `per_source` for that source are
    /// forgotten, oldest first, and returned.
    pub fn remember(&mut self, id: PeerId, source: Option<SocketAddr>, at: Instant) -> Vec<PeerId> {
        let bucket = source.map(|source| source_key(source.ip(), self.ipv6_prefix));
        let held = self.sources.entry(bucket).or_default();
        held.retain(|(had, _)| *had != id);
        let position = held
            .iter()
            .position(|(_, when)| *when > at)
            .unwrap_or(held.len());
        held.insert(position, (id, at));
        let mut forgotten = Vec::new();
        while held.len() > self.limits.per_source {
            if let Some((old, _)) = held.pop_front() {
                forgotten.push(old);
            }
        }
        forgotten
    }

    /// Forgets every entry the host no longer stores (`stored` is false for it) once its
    /// [`rerecord`](WaitingLimits::rerecord) time has passed; within it the entry still keeps
    /// the same peer from being recorded again from its source.
    ///
    /// For a host whose entries another process may accept or remove: without it, the queue
    /// remembers them, and its memory grows with every source it has seen.
    pub fn prune(&mut self, now: Instant, stored: impl Fn(&PeerId) -> bool) {
        let rerecord = self.limits.rerecord;
        for held in self.sources.values_mut() {
            held.retain(|(id, at)| stored(id) || now.saturating_duration_since(*at) < rerecord);
        }
        self.sources.retain(|_, held| !held.is_empty());
    }

    /// The number of entries remembered, across every source.
    pub fn len(&self) -> usize {
        self.sources.values().map(VecDeque::len).sum()
    }

    /// Whether nothing is remembered.
    pub fn is_empty(&self) -> bool {
        self.sources.is_empty()
    }

    /// Forgets `id` from every source, as when the host accepts or removes it.
    pub fn forget(&mut self, id: &PeerId) {
        for held in self.sources.values_mut() {
            held.retain(|(had, _)| had != id);
        }
        self.sources.retain(|_, held| !held.is_empty());
    }
}
