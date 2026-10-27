//! The public types are thread-safe, text forms round-trip, and errors do not quote input.

use coqui_peer::pair::{
    Channel, CodeAlphabet, Decision, DeskLimits, Mode, PairRefusal, Paired, Pairing, PairingCode,
    PairingDesk, PairingError, PairingJoiner, PairingOptions, PairingResponder, PendingDevice,
    PendingSlot, Pin, PinRole, Shown, ShownPin, Ticket, UserCode,
};
use coqui_peer::{
    Clock, Digest, DriveError, Error, Established, Framing, Invitation, InvitationEntry,
    InvitationId, InvitationOptions, KeyMaterial, PeerId, Random, Retiring, RotationEvent,
    RotationOptions, Successor, TrustStore, WaitingEntry, WaitingLimits,
};

fn assert_send_sync<T: Send + Sync>() {}

#[test]
fn every_public_type_is_send_and_sync() {
    assert_send_sync::<Clock>();
    assert_send_sync::<Digest>();
    assert_send_sync::<DriveError<Error>>();
    assert_send_sync::<Error>();
    assert_send_sync::<Established<()>>();
    assert_send_sync::<Framing>();
    assert_send_sync::<Invitation>();
    assert_send_sync::<InvitationEntry>();
    assert_send_sync::<InvitationId>();
    assert_send_sync::<InvitationOptions>();
    assert_send_sync::<KeyMaterial>();
    assert_send_sync::<PeerId>();
    assert_send_sync::<Random>();
    assert_send_sync::<Retiring>();
    assert_send_sync::<RotationEvent>();
    assert_send_sync::<RotationOptions>();
    assert_send_sync::<Successor>();
    assert_send_sync::<TrustStore>();
    assert_send_sync::<WaitingEntry>();
    assert_send_sync::<WaitingLimits>();
    assert_send_sync::<Channel>();
    assert_send_sync::<CodeAlphabet>();
    assert_send_sync::<Decision>();
    assert_send_sync::<DeskLimits>();
    assert_send_sync::<Mode>();
    assert_send_sync::<PairRefusal>();
    assert_send_sync::<Paired>();
    assert_send_sync::<Pairing>();
    assert_send_sync::<PairingCode>();
    assert_send_sync::<PairingDesk>();
    assert_send_sync::<PairingError>();
    assert_send_sync::<PairingJoiner>();
    assert_send_sync::<PairingOptions>();
    assert_send_sync::<PairingResponder>();
    assert_send_sync::<PendingDevice>();
    assert_send_sync::<PendingSlot>();
    assert_send_sync::<Pin>();
    assert_send_sync::<PinRole>();
    assert_send_sync::<Shown>();
    assert_send_sync::<ShownPin>();
    assert_send_sync::<Ticket>();
    assert_send_sync::<UserCode>();
}

#[test]
fn an_id_and_a_digest_parse_back_from_their_display() -> Result<(), Error> {
    for digest in [Digest::Sha256, Digest::Sha384, Digest::Sha512, Digest::Sha1] {
        let id = digest.of(b"a public key");
        assert_eq!(id.to_string().parse::<PeerId>()?, id);
        assert_eq!(digest.to_string().parse::<Digest>()?, digest);
    }
    let id = PeerId::of(b"a public key");
    assert_eq!(id.to_base32_grouped().parse::<PeerId>()?, id);
    assert_eq!(id.hex().parse::<PeerId>()?, id);
    let invitation = InvitationId::of(&[7; 32]);
    assert_eq!(invitation.to_string().parse::<InvitationId>()?, invitation);
    Ok(())
}

#[test]
fn an_unknown_digest_name_is_carried_but_not_quoted() {
    let error = "secret-name".parse::<Digest>().expect_err("not a digest");
    assert!(matches!(&error, Error::UnknownDigest(name) if name == "secret-name"));
    assert!(!error.to_string().contains("secret-name"), "{error}");
}
