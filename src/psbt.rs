use std::fmt;

use bitcoin::{
    bip32::{ChildNumber, Xpriv, Xpub},
    secp256k1::{PublicKey, Secp256k1},
};
use zeroize::Zeroizing;

use crate::{
    DecryptedPayload, Error, Payload, PsbtNonce, PsbtPacket, PsbtPayload, Result, TeleportPassword,
    crypto::{self, EphemeralPrivateKey, SessionKey},
};

const KEY_TELEPORT_DERIVATION_INDEX: u32 = 20_250_317;

/// A sender session for an encrypted multisig PSBT `E` packet
#[derive(Debug)]
pub struct PsbtSenderSession {
    private_key: EphemeralPrivateKey,
    receiver_public_key: PublicKey,
    nonce: PsbtNonce,
    password: TeleportPassword,
}

impl PsbtSenderSession {
    /// Creates a session from the sender private key and receiver public key at their shared
    /// multisig derivation levels
    pub fn new(sender_xpriv: &Xpriv, receiver_xpub: &Xpub) -> Result<Self> {
        Self::with_nonce_and_password(
            sender_xpriv,
            receiver_xpub,
            PsbtNonce::generate(),
            TeleportPassword::generate(),
        )
    }

    /// Encrypts a PSBT for the selected multisig co-signer
    pub fn send(self, psbt: PsbtPayload) -> Result<PsbtSendResponse> {
        let Self { private_key, receiver_public_key, nonce, password } = self;
        let session_key = private_key.session_key(&receiver_public_key);
        let paranoid_key = session_key.paranoid_key(password.expose_bytes());
        let plaintext = Payload::Psbt(psbt).encode()?.into_bytes();
        let inner = crypto::encrypt_inner(&paranoid_key, &plaintext);
        let outer = session_key.encrypt_outer(&inner);
        let packet = PsbtPacket::from_parts(nonce, outer)?;

        Ok(PsbtSendResponse { packet, password })
    }

    fn with_nonce_and_password(
        sender_xpriv: &Xpriv,
        receiver_xpub: &Xpub,
        nonce: PsbtNonce,
        password: TeleportPassword,
    ) -> Result<Self> {
        let secp = Secp256k1::new();
        let path = key_teleport_path(nonce);
        let sender_child = sender_xpriv.derive_priv(&secp, &path)?;
        let receiver_child = receiver_xpub.derive_pub(&secp, &path)?;
        let private_key = EphemeralPrivateKey::from_bytes(sender_child.private_key.secret_bytes())?;

        Ok(Self { private_key, receiver_public_key: receiver_child.public_key, nonce, password })
    }
}

/// An encrypted multisig PSBT packet and its transfer password
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PsbtSendResponse {
    /// The encrypted `E` packet
    pub packet: PsbtPacket,
    /// The password that must use a separate channel
    pub password: TeleportPassword,
}

/// A receiver key context for one encrypted multisig PSBT packet
#[derive(Debug)]
pub struct PsbtReceiverSession {
    private_key: EphemeralPrivateKey,
    sender_public_key: PublicKey,
    nonce: PsbtNonce,
}

impl PsbtReceiverSession {
    /// Derives a receiver session from the receiver private key, sender public key, and packet
    /// nonce at their shared multisig derivation levels
    pub fn new(receiver_xpriv: &Xpriv, sender_xpub: &Xpub, nonce: PsbtNonce) -> Result<Self> {
        let secp = Secp256k1::new();
        let path = key_teleport_path(nonce);
        let receiver_child = receiver_xpriv.derive_priv(&secp, &path)?;
        let sender_child = sender_xpub.derive_pub(&secp, &path)?;
        let private_key =
            EphemeralPrivateKey::from_bytes(receiver_child.private_key.secret_bytes())?;

        Ok(Self { private_key, sender_public_key: sender_child.public_key, nonce })
    }

    /// Decrypts the outer `E` packet layer
    ///
    /// Callers can try this operation with candidate multisig key pairs until the checksum
    /// identifies the matching sender and wallet
    pub fn decode_step1(&self, packet: &PsbtPacket) -> Result<PendingPsbtPayload> {
        if packet.nonce() != self.nonce {
            return Err(Error::PsbtNonceMismatch {
                expected: self.nonce.value(),
                actual: packet.nonce().value(),
            });
        }

        let session_key = self.private_key.session_key(&self.sender_public_key);
        let inner = session_key.decrypt_outer(packet.encrypted_body())?;

        Ok(PendingPsbtPayload { session_key, inner: Zeroizing::new(inner) })
    }

    /// Decrypts and validates the PSBT payload
    pub fn decode(&self, packet: &PsbtPacket, password: &TeleportPassword) -> Result<PsbtPayload> {
        self.decode_step1(packet)?.complete(password)
    }
}

/// An encrypted PSBT payload awaiting its transfer password
pub struct PendingPsbtPayload {
    session_key: SessionKey,
    inner: Zeroizing<Vec<u8>>,
}

impl PendingPsbtPayload {
    /// Decrypts and validates the binary PSBT
    pub fn complete(&self, password: &TeleportPassword) -> Result<PsbtPayload> {
        let paranoid_key = self.session_key.paranoid_key(password.expose_bytes());
        let plaintext = crypto::decrypt_inner(&paranoid_key, &self.inner)?;
        let payload = DecryptedPayload::from_bytes(plaintext)?.decode()?;
        let Payload::Psbt(psbt) = payload else {
            return Err(Error::InvalidPsbtPayload);
        };

        Ok(psbt)
    }
}

impl fmt::Debug for PendingPsbtPayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PendingPsbtPayload")
            .field("session_key", &self.session_key)
            .field("inner", &format_args!("{} encrypted bytes", self.inner.len()))
            .finish()
    }
}

fn key_teleport_path(nonce: PsbtNonce) -> [ChildNumber; 2] {
    [
        ChildNumber::Normal { index: KEY_TELEPORT_DERIVATION_INDEX },
        ChildNumber::Normal { index: nonce.value() },
    ]
}

#[cfg(test)]
mod tests {
    use bitcoin::{
        Amount, NetworkKind, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness,
        absolute::LockTime, psbt::Psbt, transaction::Version,
    };

    use super::*;

    const EXPECTED_PSBT_PACKET: &str = "0000000789ac95b5f0ba2fe7c2a5738f4d8c088a0cd032858c5907df73cb4ea0c55dbfd431064fe7557a3247a2a08009cba3587eb06c086b14de987c28ee6af3153532e7b741ff38c58b93c52f6cea5d";

    #[test]
    fn multisig_psbt_roundtrips_between_preshared_keys() {
        let sender = Xpriv::new_master(NetworkKind::Main, &[1; 32]).unwrap();
        let receiver = Xpriv::new_master(NetworkKind::Main, &[2; 32]).unwrap();
        let secp = Secp256k1::new();
        let sender_xpub = Xpub::from_priv(&secp, &sender);
        let receiver_xpub = Xpub::from_priv(&secp, &receiver);
        let nonce = PsbtNonce::new(7).unwrap();
        let password = TeleportPassword::from_bytes([0x12, 0x34, 0x56, 0x78, 0x9a]);
        let sender_session =
            PsbtSenderSession::with_nonce_and_password(&sender, &receiver_xpub, nonce, password)
                .unwrap();
        let psbt = test_psbt();
        let expected = psbt.expose_bytes().to_vec();
        let response = sender_session.send(psbt).unwrap();
        let receiver_session =
            PsbtReceiverSession::new(&receiver, &sender_xpub, response.packet.nonce()).unwrap();
        let decoded = receiver_session.decode(&response.packet, &response.password).unwrap();

        assert_eq!(decoded.expose_bytes(), expected);
    }

    #[test]
    fn wrong_multisig_key_fails_outer_checksum() {
        let sender = Xpriv::new_master(NetworkKind::Main, &[1; 32]).unwrap();
        let receiver = Xpriv::new_master(NetworkKind::Main, &[2; 32]).unwrap();
        let wrong_sender = Xpriv::new_master(NetworkKind::Main, &[3; 32]).unwrap();
        let secp = Secp256k1::new();
        let receiver_xpub = Xpub::from_priv(&secp, &receiver);
        let wrong_sender_xpub = Xpub::from_priv(&secp, &wrong_sender);
        let response = PsbtSenderSession::with_nonce_and_password(
            &sender,
            &receiver_xpub,
            PsbtNonce::new(7).unwrap(),
            TeleportPassword::from_bytes([1; 5]),
        )
        .unwrap()
        .send(test_psbt())
        .unwrap();
        let wrong_receiver =
            PsbtReceiverSession::new(&receiver, &wrong_sender_xpub, response.packet.nonce())
                .unwrap();

        assert!(matches!(wrong_receiver.decode_step1(&response.packet), Err(Error::Checksum)));
    }

    #[test]
    fn coldcard_multisig_psbt_protocol_vector_matches() {
        let sender = Xpriv::new_master(NetworkKind::Main, &[1; 32]).unwrap();
        let receiver = Xpriv::new_master(NetworkKind::Main, &[2; 32]).unwrap();
        let receiver_xpub = Xpub::from_priv(&Secp256k1::new(), &receiver);
        let response = PsbtSenderSession::with_nonce_and_password(
            &sender,
            &receiver_xpub,
            PsbtNonce::new(7).unwrap(),
            TeleportPassword::from_bytes([0x12, 0x34, 0x56, 0x78, 0x9a]),
        )
        .unwrap()
        .send(test_psbt())
        .unwrap();

        assert_eq!(hex_string(response.packet.as_bytes()), EXPECTED_PSBT_PACKET);
    }

    fn test_psbt() -> PsbtPayload {
        let transaction = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint::null(),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            }],
            output: vec![TxOut { value: Amount::ZERO, script_pubkey: ScriptBuf::new() }],
        };
        let bytes = Psbt::from_unsigned_tx(transaction).unwrap().serialize();

        PsbtPayload::new(bytes).unwrap()
    }

    fn hex_string(bytes: &[u8]) -> String {
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }
}
