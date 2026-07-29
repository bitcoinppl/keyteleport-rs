# keyteleport

`keyteleport` implements the
[COLDCARD Key Teleport protocol](https://github.com/Coldcard/firmware/blob/master/docs/key-teleport.md)
in Rust.

The crate owns the wire protocol:

- typed one-time sender and receiver sessions
- all six payload type codes
- lossless retention of unknown future payloads
- Base32 BBQr packet encoding and multipart joining
- strict `keyteleport.com` URL parsing
- pre-shared multisig key derivation and encrypted PSBT `E` packets
- secret redaction and zeroization

Wallet policy, secret storage, scanning, signing, and user interfaces are outside this crate.

## Protocol support

| Protocol payload | Code | Send | Receive | Result |
| --- | --- | --- | --- | --- |
| BIP39 mnemonic | `s` | Yes | Yes | `Payload::Mnemonic` |
| Raw BIP32 master secret | `s` | Yes | Yes | `Payload::MasterSecret` |
| Master XPRV | `s` or `x` | Yes | Yes | `Payload::Xprv` |
| Secure Notes & Passwords | `n` | Yes | Yes | `Payload::Notes` |
| Seed Vault entry | `v` | Yes | Yes | `Payload::Vault` |
| Binary PSBT | `p` | Yes | Yes | `Payload::Psbt` |
| Full COLDCARD backup | `b` | Yes | Yes | `Payload::Backup` |
| Future payload type | other | Yes | Yes | `Payload::Unknown` |

The crate validates PSBTs but does not sign or finalize them. Backup payloads remain secret bytes
because backup restore policy belongs to the receiving application.

## Security

This crate implements a device interoperability protocol. It is not a general encryption API.

Key Teleport uses a short numeric receiver code, an eight-character transfer password,
AES-256-CTR, and two-byte checksums. These are protocol constraints. The checksums are not a
general-purpose message authentication code.

Follow these rules:

1. Send the BBQr data and its numeric code or transfer password through different channels.
2. Store an exported receiver-session secret only in protected secret storage.
3. Delete each persisted receiver-session secret after `DecodedTransfer::accept`.
4. Treat passwords, mnemonics, master secrets, XPRVs, notes, vault entries, backups, decrypted
   payloads, and PSBT metadata as sensitive.
5. Do not reuse a completed receiver session.

See [SECURITY.md](SECURITY.md) and the
[COLDCARD operating procedure](https://coldcard.com/docs/key-teleport/) for more details.

## Send a standard transfer

```rust,no_run
use std::str::FromStr as _;

use bip39::Mnemonic;
use keyteleport::{NumericCode, Packet, Payload, SenderSession};

fn prepare_transfer(
    receiver_url: &str,
    receiver_code: &str,
    mnemonic: Mnemonic,
) -> Result<(String, String), Box<dyn std::error::Error>> {
    let request = Packet::from_url(receiver_url)?;
    let Packet::Receiver(receiver_packet) = request else {
        return Err("expected a receiver packet".into());
    };
    let receiver_code = NumericCode::from_str(receiver_code)?;
    let response = SenderSession::new(&receiver_packet, &receiver_code)?
        .send(Payload::mnemonic(mnemonic)?)?;

    Ok((response.packet.to_url()?, response.password.grouped()))
}
```

Send the returned URL and password through different channels.

## Receive a standard transfer

```rust,no_run
use std::str::FromStr as _;

use keyteleport::{Packet, Payload, ReceiverSession, TeleportPassword};

fn receive(
    sender_url: &str,
    password_text: &str,
) -> Result<Payload, Box<dyn std::error::Error>> {
    let receiver = ReceiverSession::new();
    let request = receiver.request()?;
    let receiver_url = request.packet.to_url()?;
    let receiver_code = request.numeric_code.grouped();
    let session_secret = receiver.export_secret();

    // send the receiver URL and code through different channels
    // store the session secret in protected storage
    let _ = (receiver_url, receiver_code, session_secret);

    let Packet::Sender(sender_packet) = Packet::from_url(sender_url)? else {
        return Err("expected a sender packet".into());
    };
    let password = TeleportPassword::from_str(password_text)?;
    let pending = receiver.decode_step1(&sender_packet)?;
    let transfer = pending.complete(&password)?;

    match transfer.payload() {
        Payload::Mnemonic(_) => {}
        Payload::Xprv(_) => {}
        Payload::MasterSecret(_) => {}
        Payload::Notes(_) => {}
        Payload::Vault(_) => {}
        Payload::Psbt(_) => {}
        Payload::Backup(_) => {}
        Payload::Unknown(_) => {}
    }

    // delete the persisted session secret after acceptance
    Ok(transfer.accept())
}
```

`decode_step1` and `PendingPayload::complete` return their state with a `RetryableError` after a
failure. The application can retry a scanned packet or a transfer password without retaining
separate copies of cryptographic state. `DecodedTransfer::reject` also returns the active receiver
session.

## Multipart BBQr

```rust
use keyteleport::{BbqrOptions, Packet};

fn reencode(parts: Vec<String>) -> keyteleport::Result<Vec<String>> {
    let packet = Packet::from_bbqr_parts(parts)?;

    Ok(packet.to_bbqr(BbqrOptions::default())?.parts)
}
```

Key Teleport BBQr data must use uncompressed Base32 encoding. The parser rejects Hex and Zlib
encodings even when the underlying BBQr library can decode them.

## Lossless payload inspection

`DecryptedPayload` retains the exact plaintext wire bytes before typed decoding. This is useful
when an application must store or relay an unknown future payload without data loss.

```rust
use keyteleport::{DecryptedPayload, PayloadKind};

fn canonicalize_unknown(
    bytes: Vec<u8>,
) -> keyteleport::Result<Option<DecryptedPayload>> {
    let decrypted = DecryptedPayload::from_bytes(bytes)?;
    if !matches!(decrypted.kind(), PayloadKind::Unknown(_)) {
        return Ok(None);
    }

    let unknown = decrypted.decode()?;
    Ok(Some(unknown.encode()?))
}
```

## Multisig PSBT `E` packets

The caller supplies the local private key and peer public key at their shared multisig derivation
levels. The crate derives `m/20250317/{nonce}` as required by the protocol.

```rust,no_run
use bitcoin::bip32::{Xpriv, Xpub};
use keyteleport::{
    PsbtPayload, PsbtReceiverSession, PsbtSenderSession,
};

fn transfer_psbt(
    sender_xpriv: Xpriv,
    sender_xpub: Xpub,
    receiver_xpriv: Xpriv,
    receiver_xpub: Xpub,
    psbt_bytes: Vec<u8>,
) -> keyteleport::Result<PsbtPayload> {
    let response = PsbtSenderSession::new(&sender_xpriv, &receiver_xpub)?
        .send(PsbtPayload::new(psbt_bytes)?)?;
    let receiver = PsbtReceiverSession::new(
        &receiver_xpriv,
        &sender_xpub,
        response.packet.nonce(),
    )?;

    receiver.decode(&response.packet, &response.password)
}
```

## What remains outside the crate

A full wallet integration still needs:

- QR image rendering, camera scanning, and multipart scan progress
- secure persistence and deletion of receiver-session secrets
- separate-channel exchange of codes and passwords
- wallet selection, import approval, and duplicate-wallet policy
- secure-note and backup storage or restore policy
- Seed Vault update policy
- PSBT wallet matching, signing, finalization, and broadcast
- application alerts, navigation, and user interfaces

The crate does not parse COLDCARD backup text into wallet fields. It validates and retains the
complete backup bytes. The crate also does not assign a Bitcoin network to compact stash XPRVs
because that wire format does not carry a network. Call `XprvPayload::to_xpriv` with the network
selected by the application.

Only English BIP39 mnemonic payloads are accepted. The wire format carries entropy, not a word-list
identifier. Accepting another language and returning English words would change the BIP39 seed.

## Validation

The test suite includes deterministic COLDCARD-compatible vectors, payload and lifecycle tests,
multipart and malformed-input tests, property tests, and `cargo-fuzz` targets for packet and
payload parsers.

```text
cargo fmt --check
cargo fmt --manifest-path fuzz/Cargo.toml -- --check
cargo clippy --locked --all-targets --all-features -- -D warnings
cargo test --locked --all-targets --all-features
cargo test --locked --doc --all-features
RUSTDOCFLAGS="-D warnings" cargo doc --locked --no-deps --all-features
cargo package --locked
cargo +nightly fuzz check
```
