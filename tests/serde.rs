//! With the `serde` feature an id is its canonical text, in any format.
#![cfg(feature = "serde")]

use coqui_peer::{Digest, PeerId};

#[test]
fn an_id_and_a_digest_are_text() {
    let id = PeerId::of(b"key");
    let json = serde_json::to_string(&id).unwrap();
    assert_eq!(json, format!("\"{id}\""));
    assert_eq!(serde_json::from_str::<PeerId>(&json).unwrap(), id);
    // Every spelling an id parses from is read.
    let grouped = format!("\"{}\"", id.to_base32_grouped());
    assert_eq!(serde_json::from_str::<PeerId>(&grouped).unwrap(), id);

    assert_eq!(
        serde_json::to_string(&Digest::Sha384).unwrap(),
        "\"sha384\""
    );
    assert_eq!(
        serde_json::from_str::<Digest>("\"sha512\"").unwrap(),
        Digest::Sha512
    );
    assert!(serde_json::from_str::<Digest>("\"md5\"").is_err());
    assert!(serde_json::from_str::<PeerId>("\"sha256:zz\"").is_err());
}
