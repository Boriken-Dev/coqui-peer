//! The bounds on a waiting queue, kept apart from where its entries are stored.

use alloc::collections::VecDeque;
use core::net::{IpAddr, SocketAddr};
use std::collections::HashMap;
use std::time::Instant;

use crate::id::PeerId;
use crate::store::{DEFAULT_IPV6_PREFIX, WaitingLimits, source_key};

/// What [`WaitingQueue::admit`] decided for one peer.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Admission {
    /// Whether to record the peer as waiting now.
    pub record: bool,
    /// Entries of the same source to remove first, oldest first: the source holds
    /// [`per_source`](WaitingLimits::per_source) entries at most.
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
    sources: HashMap<Option<IpAddr>, VecDeque<(PeerId, Instant)>>,
}

impl WaitingQueue {
    /// An empty queue under `limits`, grouping IPv6 sources by /64.
    pub fn new(limits: WaitingLimits) -> Self {
        Self {
            limits,
            ipv6_prefix: DEFAULT_IPV6_PREFIX,
            sources: HashMap::new(),
        }
    }

    /// This queue grouping IPv6 sources by their first `bits` bits (values above 128 are 128).
    #[must_use]
    pub fn with_ipv6_prefix(mut self, bits: u8) -> Self {
        self.ipv6_prefix = bits.min(128);
        self
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
    /// after [`rerecord`](WaitingLimits::rerecord). A source past
    /// [`per_source`](WaitingLimits::per_source) gives up its oldest entries, listed in
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
        held.retain(|(had, _)| *had != id);
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

    /// Forgets `id` from every source, as when the host accepts or removes it.
    pub fn forget(&mut self, id: &PeerId) {
        for held in self.sources.values_mut() {
            held.retain(|(had, _)| had != id);
        }
        self.sources.retain(|_, held| !held.is_empty());
    }
}
