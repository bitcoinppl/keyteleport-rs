#![no_main]

use keyteleport::DecryptedPayload;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(decrypted) = DecryptedPayload::from_bytes(data.to_vec()) else {
        return;
    };
    let Ok(payload) = decrypted.decode() else {
        return;
    };
    let encoded = payload.encode().expect("decoded payload must encode");
    let decoded = encoded.decode().expect("encoded payload must decode");

    assert_eq!(decoded, payload);
});
