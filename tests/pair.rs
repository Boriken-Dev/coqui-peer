//! The pairing exchange, run in memory: invitations, PINs (feature `pin`) and the device flow,
//! with refusals, throttles, a relaying attacker and channels with and without a binding.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, UNIX_EPOCH};

use coqui_peer::pair::{
    Channel, CodeAlphabet, DeskLimits, Mode, PairRefusal, Paired, Pairing, PairingDesk,
    PairingError, PairingJoiner, PairingOptions, PairingResponder, Rotation, Shown,
};
use coqui_peer::{Clock, Error, InvitationOptions, KeyMaterial, Random, TrustStore};

const T0: u64 = 1_800_000_000;

/// A clock the test moves by hand.
#[derive(Clone)]
struct Hand(Arc<AtomicU64>);

impl Hand {
    fn new() -> Self {
        Self(Arc::new(AtomicU64::new(T0)))
    }

    fn clock(&self) -> Clock {
        let now = self.0.clone();
        Clock::from_fn(move || UNIX_EPOCH + Duration::from_secs(now.load(Ordering::SeqCst)))
    }

    fn advance(&self, seconds: u64) {
        self.0.fetch_add(seconds, Ordering::SeqCst);
    }
}

/// A deterministic source, for tests only: a counter starting at `start`.
fn counting(start: u64) -> Random {
    let next = Arc::new(AtomicU64::new(start));
    Random::from_fn(move |out| {
        for byte in out {
            *byte = next.fetch_add(1, Ordering::SeqCst) as u8;
        }
        Ok(())
    })
}

fn key(seed: u8) -> KeyMaterial {
    KeyMaterial::new("example", "PUBLIC KEY", vec![seed; 32]).unwrap()
}

/// The responder's world: a store, a desk and a hand-moved clock.
struct Responder {
    _directory: tempfile::TempDir,
    store: TrustStore,
    desk: PairingDesk,
    hand: Hand,
}

fn fresh() -> Responder {
    let directory = tempfile::tempdir().unwrap();
    let hand = Hand::new();
    let store = TrustStore::open(directory.path())
        .unwrap()
        .with_clock(hand.clock());
    let desk = PairingDesk::new(counting(100)).with_clock(hand.clock());
    Responder {
        _directory: directory,
        store,
        desk,
        hand,
    }
}

/// A channel that proved both keys and verified the other side (a pin), with `binding`.
fn proven(local: &KeyMaterial, remote: &KeyMaterial, binding: &[u8]) -> Channel {
    Channel {
        local: local.clone(),
        remote: Some(remote.clone()),
        verified: true,
        binding: Some(binding.to_vec()),
    }
}

/// A channel that proves nothing and has no binding.
fn plain(local: &KeyMaterial) -> Channel {
    Channel {
        local: local.clone(),
        remote: None,
        verified: false,
        binding: None,
    }
}

struct Run {
    joiner: Result<Paired, PairingError>,
    responder: Result<Paired, PairingError>,
    /// Every message, with the side that sent it.
    log: Vec<(&'static str, Vec<u8>)>,
}

/// Runs both sides to the end. `on_shown` gets what the joiner shows, once, and must settle
/// whatever the responder will wait for; `tamper` may rewrite messages in flight.
fn run(
    mut joiner: PairingJoiner,
    mut responder: PairingResponder,
    desk: &PairingDesk,
    mut on_shown: impl FnMut(&Shown),
    mut tamper: impl FnMut(&'static str, Vec<u8>) -> Vec<u8>,
) -> Run {
    let (mut joiner_error, mut responder_error) = (None, None);
    let mut shown = false;
    let mut log = Vec::new();
    loop {
        let mut moved = false;
        while let Some(message) = joiner.transmit() {
            moved = true;
            let message = tamper("joiner", message);
            log.push(("joiner", message.clone()));
            if responder_error.is_none()
                && let Err(error) = responder.receive(&message)
            {
                responder_error = Some(error);
            }
        }
        while let Some(message) = responder.transmit() {
            moved = true;
            let message = tamper("responder", message);
            log.push(("responder", message.clone()));
            if joiner_error.is_none()
                && let Err(error) = joiner.receive(&message)
            {
                joiner_error = Some(error);
            }
        }
        if !shown && let Some(what) = joiner.shown() {
            shown = true;
            on_shown(what);
        }
        if responder_error.is_none()
            && let Some(ticket) = responder.awaiting()
        {
            moved = true;
            if let Err(error) = responder.resume(desk.wait(ticket)) {
                responder_error = Some(error);
            }
        }
        if !moved {
            break;
        }
    }
    Run {
        joiner: joiner_error.map_or_else(|| joiner.finish(), Err),
        responder: responder_error.map_or_else(|| responder.finish(), Err),
        log,
    }
}

fn untouched(_: &'static str, message: Vec<u8>) -> Vec<u8> {
    message
}

fn refused(result: &Result<Paired, PairingError>) -> Option<PairRefusal> {
    match result {
        Err(PairingError::Refused(refusal)) => Some(*refusal),
        _ => None,
    }
}

// Invitations.

#[test]
fn an_invitation_pairs_once() {
    let world = fresh();
    let (joiner_key, responder_key) = (key(1), key(2));
    let invitation = world
        .store
        .invite(&counting(7), InvitationOptions::default(), "tablet")
        .unwrap();
    let pairing = || Pairing::invitation(responder_key.id(), invitation.secret);
    let start = |pairing: Pairing| {
        let joiner = pairing
            .join(proven(&joiner_key, &responder_key, b"bound"))
            .unwrap();
        let responder = PairingResponder::new(
            proven(&responder_key, &joiner_key, b"bound"),
            &world.store,
            &world.desk,
            None,
        );
        run(joiner, responder, &world.desk, |_| {}, untouched)
    };
    let first = start(pairing());
    assert_eq!(first.joiner.unwrap().peer, responder_key);
    let paired = first.responder.unwrap();
    assert_eq!(paired.peer, joiner_key);
    assert_eq!(paired.mode, Mode::Invitation);
    assert!(world.store.is_accepted(&joiner_key.id()));

    let again = start(pairing());
    assert_eq!(refused(&again.joiner), Some(PairRefusal::WrongCode));
    assert_eq!(refused(&again.responder), Some(PairRefusal::WrongCode));
}

#[test]
fn an_invitation_needs_a_channel_that_proved_the_inviter() {
    let (joiner_key, inviter) = (key(1), key(2));
    let pairing = Pairing::invitation(inviter.id(), [5; 32]);
    assert!(matches!(
        pairing.clone().join(plain(&joiner_key)),
        Err(PairingError::Unverified)
    ));
    assert!(matches!(
        pairing.join(proven(&joiner_key, &key(3), b"")),
        Err(PairingError::Unverified)
    ));
}

#[test]
fn an_expired_invitation_is_refused() {
    let world = fresh();
    let (joiner_key, responder_key) = (key(1), key(2));
    let options = InvitationOptions {
        valid_for: Duration::from_secs(60),
        uses: 1,
    };
    let invitation = world.store.invite(&counting(7), options, "").unwrap();
    world.hand.advance(60);
    let joiner = Pairing::invitation(responder_key.id(), invitation.secret)
        .join(proven(&joiner_key, &responder_key, b""))
        .unwrap();
    let responder = PairingResponder::new(
        proven(&responder_key, &joiner_key, b""),
        &world.store,
        &world.desk,
        None,
    );
    let ran = run(joiner, responder, &world.desk, |_| {}, untouched);
    assert_eq!(refused(&ran.joiner), Some(PairRefusal::Expired));
    assert!(!world.store.is_accepted(&joiner_key.id()));
}

// The device flow.

fn device_run(
    world: &Responder,
    pairing: Pairing,
    channel: Channel,
    settle: impl FnMut(&Shown),
) -> Run {
    let joiner_key = channel.local.clone();
    let responder_key = key(2);
    let joiner = pairing.join(channel).unwrap();
    let responder = PairingResponder::new(
        proven(&responder_key, &joiner_key, b"bound"),
        &world.store,
        &world.desk,
        Some("192.0.2.9:5000".parse().unwrap()),
    );
    run(joiner, responder, &world.desk, settle, untouched)
}

fn user_code(shown: &Shown) -> String {
    match shown {
        Shown::UserCode { code, .. } => code.as_str().to_owned(),
        other => panic!("not a user code: {other:?}"),
    }
}

#[test]
fn an_approved_device_pairs() {
    let world = fresh();
    let joiner_key = key(1);
    let ran = device_run(
        &world,
        Pairing::device("living room"),
        proven(&joiner_key, &key(2), b"bound"),
        |shown| {
            let code = user_code(shown);
            assert_eq!(code.len(), 8);
            let Shown::UserCode { expires, .. } = shown else {
                unreachable!()
            };
            assert_eq!(*expires, UNIX_EPOCH + Duration::from_secs(T0 + 600));
            let found = world.desk.find_device("operator", &code).unwrap();
            assert_eq!(found.peer, joiner_key.id());
            assert_eq!(found.label, "living room");
            assert_eq!(found.source, Some("192.0.2.9:5000".parse().unwrap()));
            world.desk.approve(&found).unwrap();
        },
    );
    assert_eq!(ran.joiner.unwrap().mode, Mode::Device);
    assert_eq!(ran.responder.unwrap().peer, joiner_key);
    assert!(world.store.is_accepted(&joiner_key.id()));
}

#[test]
fn a_denied_device_is_told_so() {
    let world = fresh();
    let joiner_key = key(1);
    let ran = device_run(
        &world,
        Pairing::device(""),
        proven(&joiner_key, &key(2), b"bound"),
        |shown| {
            let found = world
                .desk
                .find_device("operator", &user_code(shown))
                .unwrap();
            world.desk.deny(&found).unwrap();
        },
    );
    assert_eq!(refused(&ran.joiner), Some(PairRefusal::Denied));
    assert_eq!(refused(&ran.responder), Some(PairRefusal::Denied));
    assert!(!world.store.is_accepted(&joiner_key.id()));
}

#[test]
fn an_unapproved_device_expires() {
    let world = fresh();
    let ran = device_run(
        &world,
        Pairing::device(""),
        proven(&key(1), &key(2), b"bound"),
        |shown| {
            world.hand.advance(600);
            world.desk.sweep();
            assert!(matches!(
                world.desk.find_device("operator", &user_code(shown)),
                Err(PairingError::Refused(PairRefusal::WrongCode))
            ));
        },
    );
    assert_eq!(refused(&ran.joiner), Some(PairRefusal::Expired));
    assert_eq!(refused(&ran.responder), Some(PairRefusal::Expired));
}

#[test]
fn wrong_user_codes_are_throttled_per_approver_and_in_all() {
    let world = fresh();
    let world = Responder {
        desk: world.desk.clone().with_limits(DeskLimits {
            wrong_codes_total: 7,
            ..DeskLimits::default()
        }),
        ..world
    };
    let ran = device_run(
        &world,
        Pairing::device(""),
        proven(&key(1), &key(2), b"bound"),
        |shown| {
            let right = user_code(shown);
            let wrong = "BBBBBBBB";
            assert_ne!(right, wrong);
            for _ in 0..5 {
                assert!(matches!(
                    world.desk.find_device("mallory", wrong),
                    Err(PairingError::Refused(PairRefusal::WrongCode))
                ));
            }
            // The sixth try within the minute is refused before matching, right code or not.
            assert!(matches!(
                world.desk.find_device("mallory", &right),
                Err(PairingError::Refused(PairRefusal::Throttled))
            ));
            // Another approver is not held back by mallory, until the total runs out.
            for _ in 0..2 {
                assert!(world.desk.find_device("eve", wrong).is_err());
            }
            assert!(matches!(
                world.desk.find_device("operator", &right),
                Err(PairingError::Refused(PairRefusal::Throttled))
            ));
            // A minute later mallory's own window has passed, but the total still holds for the
            // ten minutes of the device TTL.
            world.hand.advance(60);
            assert!(matches!(
                world.desk.find_device("mallory", &right),
                Err(PairingError::Refused(PairRefusal::Throttled))
            ));
            world.hand.advance(540);
            world.desk.sweep();
        },
    );
    assert_eq!(refused(&ran.joiner), Some(PairRefusal::Expired));
}

#[test]
fn a_user_code_is_matched_exactly() {
    let world = fresh();
    let ran = device_run(
        &world,
        Pairing::device(""),
        proven(&key(1), &key(2), b"bound"),
        |shown| {
            let code = user_code(shown);
            let grouped = format!("{}-{}", &code[..4], &code[4..]);
            assert!(matches!(
                world.desk.find_device("operator", &grouped),
                Err(PairingError::Local(Error::InvalidCode))
            ));
            assert!(matches!(
                world.desk.find_device("operator", &code.to_lowercase()),
                Err(PairingError::Local(Error::InvalidCode))
            ));
            let found = world.desk.find_device("operator", &code).unwrap();
            world.desk.approve(&found).unwrap();
        },
    );
    assert!(ran.joiner.is_ok());
}

#[test]
fn the_device_flow_needs_a_verified_responder_unless_allowed() {
    let world = fresh();
    assert!(matches!(
        Pairing::device("").join(plain(&key(1))),
        Err(PairingError::Unverified)
    ));
    let pairing = Pairing::device("").allow_unverified(true);
    assert!(pairing.allows_unverified());
    let ran = device_run(&world, pairing, plain(&key(1)), |shown| {
        let found = world
            .desk
            .find_device("operator", &user_code(shown))
            .unwrap();
        world.desk.approve(&found).unwrap();
    });
    // Over a channel that proved nothing the responder's key comes from the exchange.
    assert_eq!(ran.joiner.unwrap().peer, key(2));
}

#[test]
fn a_mode_the_responder_turned_off_is_refused() {
    let world = fresh();
    let desk = world
        .desk
        .clone()
        .with_options(PairingOptions {
            device: false,
            ..PairingOptions::default()
        })
        .unwrap();
    let joiner = Pairing::device("")
        .join(proven(&key(1), &key(2), b""))
        .unwrap();
    let responder = PairingResponder::new(proven(&key(2), &key(1), b""), &world.store, &desk, None);
    let ran = run(joiner, responder, &desk, |_| {}, untouched);
    assert_eq!(refused(&ran.joiner), Some(PairRefusal::Disabled));
}

#[test]
fn pending_exchanges_are_bounded() {
    let world = fresh();
    let desk = world.desk.clone().with_limits(DeskLimits {
        pending: 1,
        ..DeskLimits::default()
    });
    let mut first = PairingResponder::new(proven(&key(2), &key(1), b""), &world.store, &desk, None);
    let mut joiner = Pairing::device("")
        .join(proven(&key(1), &key(2), b""))
        .unwrap();
    first.receive(&joiner.transmit().unwrap()).unwrap();
    let mut second =
        PairingResponder::new(proven(&key(2), &key(3), b""), &world.store, &desk, None);
    let mut other = Pairing::device("")
        .join(proven(&key(3), &key(2), b""))
        .unwrap();
    assert!(matches!(
        second.receive(&other.transmit().unwrap()),
        Err(PairingError::Refused(PairRefusal::Throttled))
    ));
    drop(first);
    let mut third = PairingResponder::new(proven(&key(2), &key(3), b""), &world.store, &desk, None);
    let mut retry = Pairing::device("")
        .join(proven(&key(3), &key(2), b""))
        .unwrap();
    assert!(third.receive(&retry.transmit().unwrap()).is_ok());
}

// Options and messages.

#[test]
fn weaker_options_are_reported_not_refused() {
    assert!(PairingOptions::default().weakened().is_empty());
    assert!(DeskLimits::default().weakened().is_empty());
    let options = PairingOptions {
        pin_alphabet: CodeAlphabet {
            chars: "0123456789".to_owned(),
            len: 4,
        },
        pin_attempts: 3,
        ..PairingOptions::default()
    };
    let desk = PairingDesk::new(counting(0))
        .with_options(options.clone())
        .unwrap();
    assert_eq!(desk.options().pin_attempts, 3);
    let weakened: Vec<String> = options.weakened().into_iter().map(|w| w.setting).collect();
    assert_eq!(weakened, ["pin_alphabet", "pin_attempts"]);
    // The one Weakening type of the crate root, with the strict value beside the current one.
    let attempts = options
        .weakened()
        .into_iter()
        .find(|w| w.setting == "pin_attempts");
    assert_eq!(
        attempts,
        Some(coqui_peer::Weakening::new("pin_attempts", "3", "1"))
    );
    let meaningless = PairingOptions {
        pin_attempts: 0,
        ..PairingOptions::default()
    };
    assert!(matches!(
        PairingDesk::new(counting(0)).with_options(meaningless),
        Err(Error::InvalidOptions)
    ));
}

#[test]
fn a_rotation_announcement_round_trips() {
    let successor = key(9);
    let message = Rotation::announce(&successor);
    assert_eq!(Rotation::parse(&message).unwrap(), successor);
    assert!(matches!(
        Rotation::parse(&message[..message.len() - 1]),
        Err(PairingError::Protocol)
    ));
    let mut wrong_version = message.clone();
    wrong_version[0] = 2;
    assert!(Rotation::parse(&wrong_version).is_err());
}

// PINs.

#[cfg(feature = "pin")]
mod pin {
    use super::*;
    use coqui_peer::pair::{Pin, PinRole};

    fn typed(
        world: &Responder,
        pin: &Pin,
        joiner_key: &KeyMaterial,
        tamper: impl FnMut(&'static str, Vec<u8>) -> Vec<u8>,
    ) -> Run {
        let responder_key = key(2);
        let joiner = Pairing::pin(pin.clone(), PinRole::Typed)
            .with_random(counting(1))
            .join(proven(joiner_key, &responder_key, b"bound"))
            .unwrap();
        let responder = PairingResponder::new(
            proven(&responder_key, joiner_key, b"bound"),
            &world.store,
            &world.desk,
            Some("192.0.2.9:5000".parse().unwrap()),
        );
        run(joiner, responder, &world.desk, |_| {}, tamper)
    }

    fn wrong(pin: &Pin) -> Pin {
        let alphabet = CodeAlphabet::pin();
        let flipped = if pin.as_str() == "000000" {
            "000001"
        } else {
            "000000"
        };
        Pin::parse(&alphabet, flipped).unwrap()
    }

    #[test]
    fn the_right_pin_pairs_both_sides() {
        let world = fresh();
        let shown = world.desk.show_pin().unwrap();
        assert_eq!(world.desk.shown_pin(), Some(shown.clone()));
        let joiner_key = key(1);
        let ran = typed(&world, &shown.pin, &joiner_key, untouched);
        assert_eq!(ran.joiner.unwrap().peer, key(2));
        let paired = ran.responder.unwrap();
        assert_eq!((paired.peer, paired.mode), (joiner_key.clone(), Mode::Pin));
        assert!(world.store.is_accepted(&joiner_key.id()));
        // The PIN was single use.
        assert!(world.desk.shown_pin().is_none());
    }

    #[test]
    fn a_wrong_pin_is_refused_and_burns_the_pin() {
        let world = fresh();
        let shown = world.desk.show_pin().unwrap();
        let ran = typed(&world, &wrong(&shown.pin), &key(1), untouched);
        assert_eq!(refused(&ran.joiner), Some(PairRefusal::WrongCode));
        assert_eq!(refused(&ran.responder), Some(PairRefusal::WrongCode));
        assert!(!world.store.is_accepted(&key(1).id()));
        let retry = typed(&world, &shown.pin, &key(1), untouched);
        assert_eq!(refused(&retry.joiner), Some(PairRefusal::Exhausted));
        assert!(!world.store.is_accepted(&key(1).id()));
    }

    #[test]
    fn more_attempts_per_pin_is_an_option() {
        let world = fresh();
        let desk = world
            .desk
            .clone()
            .with_options(PairingOptions {
                pin_attempts: 2,
                ..PairingOptions::default()
            })
            .unwrap();
        let shown = desk.show_pin().unwrap();
        assert!(
            typed(&world, &wrong(&shown.pin), &key(1), untouched)
                .joiner
                .is_err()
        );
        assert!(typed(&world, &shown.pin, &key(1), untouched).joiner.is_ok());
    }

    #[test]
    fn an_expired_pin_is_refused() {
        let world = fresh();
        let shown = world.desk.show_pin().unwrap();
        world.hand.advance(600);
        let ran = typed(&world, &shown.pin, &key(1), untouched);
        assert_eq!(refused(&ran.joiner), Some(PairRefusal::Expired));
    }

    #[test]
    fn a_relay_between_two_channels_is_refused_on_both_sides() {
        // The attacker relays every message between a channel to the joiner and another to the
        // responder; each channel has its own binding.
        let world = fresh();
        let shown = world.desk.show_pin().unwrap();
        let (joiner_key, responder_key) = (key(1), key(2));
        let joiner = Pairing::pin(shown.pin.clone(), PinRole::Typed)
            .join(proven(&joiner_key, &responder_key, b"leg one"))
            .unwrap();
        let responder = PairingResponder::new(
            proven(&responder_key, &joiner_key, b"leg two"),
            &world.store,
            &world.desk,
            None,
        );
        let ran = run(joiner, responder, &world.desk, |_| {}, untouched);
        assert_eq!(refused(&ran.joiner), Some(PairRefusal::WrongCode));
        assert_eq!(refused(&ran.responder), Some(PairRefusal::WrongCode));
        assert!(!world.store.is_accepted(&joiner_key.id()));
    }

    #[test]
    fn a_swapped_key_on_a_plain_channel_is_refused() {
        // With no binding and no proven keys, an attacker that replaces the joiner's key in its
        // first message still fails: the confirmation covers both keys.
        let world = fresh();
        let shown = world.desk.show_pin().unwrap();
        let joiner = Pairing::pin(shown.pin.clone(), PinRole::Typed)
            .join(plain(&key(1)))
            .unwrap();
        let responder = PairingResponder::new(plain(&key(2)), &world.store, &world.desk, None);
        let attacker = key(66);
        let ran = run(
            joiner,
            responder,
            &world.desk,
            |_| {},
            |side, message| {
                if side == "joiner" && message[1] == 1 {
                    let honest = key(1);
                    let mut swapped = message.clone();
                    let at = swapped
                        .windows(honest.bytes.len())
                        .position(|w| w == honest.bytes.as_slice())
                        .unwrap();
                    swapped[at..at + 32].copy_from_slice(&attacker.bytes);
                    swapped
                } else {
                    message
                }
            },
        );
        assert!(ran.joiner.is_err());
        assert!(ran.responder.is_err());
        assert!(!world.store.is_accepted(&attacker.id()));
    }

    #[test]
    fn a_plain_channel_pairs_with_the_right_pin() {
        let world = fresh();
        let shown = world.desk.show_pin().unwrap();
        let joiner = Pairing::pin(shown.pin.clone(), PinRole::Typed)
            .join(plain(&key(1)))
            .unwrap();
        let responder = PairingResponder::new(plain(&key(2)), &world.store, &world.desk, None);
        let ran = run(joiner, responder, &world.desk, |_| {}, untouched);
        assert_eq!(ran.joiner.unwrap().peer, key(2));
        assert_eq!(ran.responder.unwrap().peer, key(1));
    }

    #[test]
    fn a_joiner_shows_its_pin_with_a_slot() {
        let world = fresh();
        let pin = Pin::generate(&CodeAlphabet::pin(), &counting(40)).unwrap();
        let (joiner_key, responder_key) = (key(1), key(2));
        let joiner = Pairing::pin(pin.clone(), PinRole::Shown)
            .join(proven(&joiner_key, &responder_key, b"bound"))
            .unwrap();
        let responder = PairingResponder::new(
            proven(&responder_key, &joiner_key, b"bound"),
            &world.store,
            &world.desk,
            None,
        );
        let ran = run(
            joiner,
            responder,
            &world.desk,
            |shown| {
                let Shown::Pin(code) = shown else {
                    panic!("not a PIN")
                };
                assert_eq!(code.pin, pin);
                let slots = world.desk.slots();
                assert_eq!(slots.len(), 1);
                assert_eq!(Some(slots[0].slot), code.slot);
                assert_eq!(slots[0].peer, joiner_key.id());
                world.desk.submit_code(code).unwrap();
            },
            untouched,
        );
        assert!(ran.joiner.is_ok());
        assert!(world.store.is_accepted(&joiner_key.id()));
        assert!(world.desk.slots().is_empty());
    }

    #[test]
    fn pin_runs_are_throttled_per_source() {
        let world = fresh();
        let desk = world.desk.clone().with_limits(DeskLimits {
            pin_runs_per_source: 2,
            ..DeskLimits::default()
        });
        for attempt in 0..3 {
            desk.show_pin().unwrap();
            let pin = Pin::parse(&CodeAlphabet::pin(), "999999").unwrap();
            let ran = typed(&world, &pin, &key(1), untouched);
            let expected = if attempt < 2 {
                PairRefusal::WrongCode
            } else {
                PairRefusal::Throttled
            };
            assert_eq!(refused(&ran.joiner), Some(expected), "attempt {attempt}");
        }
    }
}

// Vectors: every message of one exchange per mode, from fixed keys, clock and random sources,
// committed under `tests/vectors/pair/` so other implementations can check themselves.
// Regenerating them is a wire-format change:
// `cargo test --all-features --test pair -- --ignored regenerate`

fn vectors() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/pair")
}

fn transcript(log: &[(&'static str, Vec<u8>)]) -> String {
    log.iter()
        .map(|(side, message)| format!("{side} {}\n", data_encoding::HEXLOWER.encode(message)))
        .collect()
}

fn vector_runs() -> Vec<(&'static str, Run)> {
    let mut runs = Vec::new();

    let world = fresh();
    let invitation = world
        .store
        .invite(&counting(7), InvitationOptions::default(), "")
        .unwrap();
    let joiner = Pairing::invitation(key(2).id(), invitation.secret)
        .join(proven(&key(1), &key(2), b"bound"))
        .unwrap();
    let responder = PairingResponder::new(
        proven(&key(2), &key(1), b"bound"),
        &world.store,
        &world.desk,
        None,
    );
    runs.push((
        "invitation",
        run(joiner, responder, &world.desk, |_| {}, untouched),
    ));

    let world = fresh();
    let ran = device_run(
        &world,
        Pairing::device("living room"),
        proven(&key(1), &key(2), b"bound"),
        |shown| {
            let found = world
                .desk
                .find_device("operator", &user_code(shown))
                .unwrap();
            world.desk.approve(&found).unwrap();
        },
    );
    runs.push(("device", ran));

    #[cfg(feature = "pin")]
    {
        use coqui_peer::pair::{Pin, PinRole};
        let world = fresh();
        let shown = world.desk.show_pin().unwrap();
        let joiner = Pairing::pin(shown.pin, PinRole::Typed)
            .with_random(counting(1))
            .join(proven(&key(1), &key(2), b"bound"))
            .unwrap();
        let responder = PairingResponder::new(
            proven(&key(2), &key(1), b"bound"),
            &world.store,
            &world.desk,
            None,
        );
        runs.push((
            "pin-typed",
            run(joiner, responder, &world.desk, |_| {}, untouched),
        ));

        let world = fresh();
        let pin = Pin::parse(&CodeAlphabet::pin(), "482913").unwrap();
        let joiner = Pairing::pin(pin, PinRole::Shown)
            .with_random(counting(1))
            .join(plain(&key(1)))
            .unwrap();
        let responder = PairingResponder::new(plain(&key(2)), &world.store, &world.desk, None);
        let ran = run(
            joiner,
            responder,
            &world.desk,
            |shown| {
                let Shown::Pin(code) = shown else {
                    panic!("not a PIN")
                };
                world.desk.submit_code(code).unwrap();
            },
            untouched,
        );
        runs.push(("pin-shown-plain", ran));
    }
    runs
}

#[test]
#[ignore = "rewrites the committed pairing vectors"]
fn regenerate() {
    std::fs::create_dir_all(vectors()).unwrap();
    for (name, ran) in vector_runs() {
        assert!(ran.joiner.is_ok() && ran.responder.is_ok(), "{name}");
        std::fs::write(vectors().join(format!("{name}.txt")), transcript(&ran.log)).unwrap();
    }
}

#[test]
fn every_exchange_matches_its_committed_vector() {
    for (name, ran) in vector_runs() {
        assert!(ran.joiner.is_ok() && ran.responder.is_ok(), "{name}");
        let committed = std::fs::read_to_string(vectors().join(format!("{name}.txt"))).unwrap();
        assert_eq!(transcript(&ran.log), committed, "{name}");
    }
}

#[test]
fn a_tiny_user_code_alphabet_runs_out_instead_of_spinning() {
    let world = fresh();
    // Each draw is one counter value, so codes alternate between the two letters.
    let step = Arc::new(AtomicU64::new(0));
    let stepping = Random::from_fn(move |out| {
        let value = step.fetch_add(1, Ordering::SeqCst) as u32;
        out.copy_from_slice(&value.to_be_bytes()[..out.len()]);
        Ok(())
    });
    let desk = PairingDesk::new(stepping)
        .with_clock(world.hand.clock())
        .with_options(PairingOptions {
            user_code_alphabet: CodeAlphabet {
                chars: "AB".to_owned(),
                len: 1,
            },
            ..PairingOptions::default()
        })
        .unwrap();
    let mut held = Vec::new();
    for seed in 10..12 {
        let mut responder =
            PairingResponder::new(proven(&key(2), &key(seed), b""), &world.store, &desk, None);
        let mut joiner = Pairing::device("")
            .join(proven(&key(seed), &key(2), b""))
            .unwrap();
        responder.receive(&joiner.transmit().unwrap()).unwrap();
        held.push(responder);
    }
    let mut third =
        PairingResponder::new(proven(&key(2), &key(12), b""), &world.store, &desk, None);
    let mut joiner = Pairing::device("")
        .join(proven(&key(12), &key(2), b""))
        .unwrap();
    assert!(matches!(
        third.receive(&joiner.transmit().unwrap()),
        Err(PairingError::Refused(PairRefusal::Throttled))
    ));
}

#[test]
fn a_proven_key_alone_does_not_verify_the_responder_for_the_device_flow() {
    // What `Trust::AnyWithKeyProof` gives: the key is proven, not that it is the one meant.
    let channel = Channel {
        verified: false,
        ..proven(&key(1), &key(2), b"bound")
    };
    assert!(matches!(
        Pairing::device("").join(channel.clone()),
        Err(PairingError::Unverified)
    ));
    assert!(
        Pairing::device("")
            .allow_unverified(true)
            .join(channel)
            .is_ok()
    );
}

#[test]
fn a_stalled_exchange_ends_at_its_deadline_and_frees_its_code() {
    let world = fresh();
    let mut responder = PairingResponder::new(
        proven(&key(2), &key(1), b""),
        &world.store,
        &world.desk,
        None,
    );
    assert_eq!(responder.deadline(), None);
    let mut joiner = Pairing::device("")
        .join(proven(&key(1), &key(2), b""))
        .unwrap();
    responder.receive(&joiner.transmit().unwrap()).unwrap();
    assert_eq!(
        responder.deadline(),
        Some(UNIX_EPOCH + Duration::from_secs(T0 + 600))
    );
    let issued = responder.transmit().unwrap();
    joiner.receive(&issued).unwrap();
    // The joiner stalls; the transport times out and checks.
    world.hand.advance(599);
    assert!(responder.check_deadline().is_ok());
    assert_eq!(responder.time_left(), Some(Duration::from_secs(1)));
    world.hand.advance(1);
    assert_eq!(responder.time_left(), Some(Duration::ZERO));
    assert!(matches!(
        responder.check_deadline(),
        Err(PairingError::Refused(PairRefusal::Expired))
    ));
    let told = responder.transmit().unwrap();
    assert!(matches!(
        joiner.receive(&told),
        Err(PairingError::Refused(PairRefusal::Expired))
    ));
    // Its pending place is free again: a source may hold four (the default), and this one
    // holds none now.
    assert_eq!(world.desk.limits().pending_per_source, 4);
    drop(responder);
    let mut held = Vec::new();
    for seed in 10..14 {
        let mut other = PairingResponder::new(
            proven(&key(2), &key(seed), b""),
            &world.store,
            &world.desk,
            None,
        );
        let mut joiner = Pairing::device("")
            .join(proven(&key(seed), &key(2), b""))
            .unwrap();
        other.receive(&joiner.transmit().unwrap()).unwrap();
        held.push(other);
    }
}

#[test]
fn pending_exchanges_are_bounded_per_source_in_every_mode() {
    let world = fresh();
    let desk = world.desk.clone().with_limits(DeskLimits {
        pending_per_source: 2,
        ..DeskLimits::default()
    });
    let from = |address: &str| Some(address.parse().unwrap());
    let mut held = Vec::new();
    for seed in 10..12 {
        let mut responder = PairingResponder::new(
            proven(&key(2), &key(seed), b""),
            &world.store,
            &desk,
            from("192.0.2.1:1000"),
        );
        let mut joiner = Pairing::device("")
            .join(proven(&key(seed), &key(2), b""))
            .unwrap();
        responder.receive(&joiner.transmit().unwrap()).unwrap();
        held.push(responder);
    }
    let mut third = PairingResponder::new(
        proven(&key(2), &key(12), b""),
        &world.store,
        &desk,
        from("192.0.2.1:2000"),
    );
    let mut joiner = Pairing::device("")
        .join(proven(&key(12), &key(2), b""))
        .unwrap();
    assert!(matches!(
        third.receive(&joiner.transmit().unwrap()),
        Err(PairingError::Refused(PairRefusal::Throttled))
    ));
    // Another source is not held back.
    let mut elsewhere = PairingResponder::new(
        proven(&key(2), &key(13), b""),
        &world.store,
        &desk,
        from("192.0.2.2:1000"),
    );
    let mut joiner = Pairing::device("")
        .join(proven(&key(13), &key(2), b""))
        .unwrap();
    assert!(elsewhere.receive(&joiner.transmit().unwrap()).is_ok());
    // Ending one frees its place.
    held.pop();
    let mut fourth = PairingResponder::new(
        proven(&key(2), &key(14), b""),
        &world.store,
        &desk,
        from("192.0.2.1:3000"),
    );
    let mut joiner = Pairing::device("")
        .join(proven(&key(14), &key(2), b""))
        .unwrap();
    assert!(fourth.receive(&joiner.transmit().unwrap()).is_ok());
}

/// A message as the wire carries it: the version, a tag, then fields.
fn message(tag: u8, fields: &[&[u8]]) -> Vec<u8> {
    let mut out = vec![1, tag];
    for field in fields {
        out.extend_from_slice(field);
    }
    out
}

fn short(bytes: &[u8]) -> Vec<u8> {
    let mut out = vec![bytes.len() as u8];
    out.extend_from_slice(bytes);
    out
}

fn wire_key(key: &KeyMaterial) -> Vec<u8> {
    let mut out = short(key.method.as_bytes());
    out.extend(short(key.label.as_bytes()));
    out.extend_from_slice(&(key.bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(&key.bytes);
    out
}

#[test]
fn a_label_or_code_that_could_read_as_another_is_refused_on_receipt() {
    for bad in ["two\nlines", "evil\u{202E}txt", "\u{2066}x", "tab\there"] {
        // A joiner refuses to send it.
        assert!(matches!(
            Pairing::device(bad).join(proven(&key(1), &key(2), b"")),
            Err(PairingError::Local(Error::InvalidOptions))
        ));
        // A responder refuses to receive it from a joiner that sent it anyway.
        let world = fresh();
        let mut responder = PairingResponder::new(
            proven(&key(2), &key(1), b""),
            &world.store,
            &world.desk,
            None,
        );
        let hello = message(1, &[&[3], &wire_key(&key(1)), &short(bad.as_bytes())]);
        assert!(matches!(
            responder.receive(&hello),
            Err(PairingError::Protocol)
        ));
        // A joiner refuses a user code that is not plain text.
        let mut joiner = Pairing::device("")
            .join(proven(&key(1), &key(2), b""))
            .unwrap();
        joiner.transmit().unwrap();
        let issued = message(
            6,
            &[
                &wire_key(&key(2)),
                &short(bad.as_bytes()),
                &1_900_000_000u64.to_be_bytes(),
            ],
        );
        assert!(matches!(
            joiner.receive(&issued),
            Err(PairingError::Protocol)
        ));
    }
}

#[test]
fn ttls_of_duration_max_mean_never_and_do_not_overflow() {
    let world = fresh();
    let desk = world
        .desk
        .clone()
        .with_options(PairingOptions {
            pin_ttl: Duration::MAX,
            device_ttl: Duration::MAX,
            ..PairingOptions::default()
        })
        .unwrap();
    let shown = desk.show_pin().unwrap();
    assert!(shown.expires > UNIX_EPOCH + Duration::from_secs(T0 + 365 * 86_400));
    let mut responder =
        PairingResponder::new(proven(&key(2), &key(1), b""), &world.store, &desk, None);
    let mut joiner = Pairing::device("")
        .join(proven(&key(1), &key(2), b""))
        .unwrap();
    responder.receive(&joiner.transmit().unwrap()).unwrap();
    joiner.receive(&responder.transmit().unwrap()).unwrap();
    assert!(responder.deadline().is_some());
    world.hand.advance(10 * 365 * 86_400);
    assert!(responder.check_deadline().is_ok());
}

#[cfg(feature = "pin")]
#[test]
fn a_decided_slot_is_listed_and_taken_no_more() {
    use coqui_peer::pair::{Pin, PinRole};
    let world = fresh();
    let pin = Pin::parse(&CodeAlphabet::pin(), "482913").unwrap();
    let mut joiner = Pairing::pin(pin, PinRole::Shown)
        .with_random(counting(1))
        .join(proven(&key(1), &key(2), b""))
        .unwrap();
    let mut responder = PairingResponder::new(
        proven(&key(2), &key(1), b""),
        &world.store,
        &world.desk,
        None,
    );
    responder.receive(&joiner.transmit().unwrap()).unwrap();
    joiner.receive(&responder.transmit().unwrap()).unwrap();
    responder.receive(&joiner.transmit().unwrap()).unwrap();
    let Some(Shown::Pin(code)) = joiner.shown().cloned() else {
        panic!("expected a PIN")
    };
    world.desk.submit_code(&code).unwrap();
    assert!(world.desk.slots().is_empty());
    assert!(matches!(
        world.desk.submit_code(&code),
        Err(PairingError::Refused(PairRefusal::WrongCode))
    ));
    // Taking the decision does not bring the slot back.
    let ticket = responder.awaiting().unwrap();
    let decision = world.desk.wait(ticket);
    assert!(world.desk.slots().is_empty());
    assert!(world.desk.submit_code(&code).is_err());
    responder.resume(decision).unwrap();
}

#[test]
fn debug_output_shows_no_binding_secret_or_pin() {
    let channel = Channel {
        binding: Some(vec![171; 32]),
        ..proven(&key(1), &key(2), b"")
    };
    let shown = format!("{channel:?}");
    assert!(!shown.contains("171"), "{shown}");
    assert!(shown.contains("verified: true"));
    let pairing = Pairing::invitation(key(2).id(), [171; 32]);
    assert!(!format!("{pairing:?}").contains("171"));
    let world = fresh();
    let invitation = world
        .store
        .invite(&counting(171), InvitationOptions::default(), "")
        .unwrap();
    assert!(!format!("{invitation:?}").contains("171"));
}
