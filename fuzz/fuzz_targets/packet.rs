#![no_main]

use keyteleport::{Packet, PsbtPacket, ReceiverPacket, SenderPacket};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let _ = Packet::from_url(&text);
    let _ = Packet::from_bbqr_part(&text);
    let parts = data
        .split(|byte| *byte == 0)
        .take(8)
        .map(|part| String::from_utf8_lossy(part).into_owned())
        .collect();
    let _ = Packet::from_bbqr_parts(parts);

    exercise_packet_roundtrip(ReceiverPacket::new(data.to_vec()).map(Packet::Receiver));
    exercise_packet_roundtrip(SenderPacket::new(data.to_vec()).map(Packet::Sender));
    exercise_packet_roundtrip(PsbtPacket::new(data.to_vec()).map(Packet::Psbt));
});

fn exercise_packet_roundtrip(packet: keyteleport::Result<Packet>) {
    let Ok(packet) = packet else {
        return;
    };
    let part = packet.to_bbqr_part().expect("validated packet must fit one BBQr");
    let decoded = Packet::from_bbqr_part(&part).expect("encoded packet must decode");

    assert_eq!(decoded, packet);
}
