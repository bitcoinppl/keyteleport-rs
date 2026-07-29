use std::fmt;

use bitcoin::secp256k1::{PublicKey, SecretKey};
use zeroize::Zeroizing;

use crate::{
    DecryptedPayload, Error, NumericCode, Payload, ReceiverPacket, Result, SenderPacket,
    TeleportPassword,
    crypto::{self, EphemeralPrivateKey, SessionKey},
};

/// A zeroizing receiver-session secret used for persistence
#[derive(Clone, PartialEq, Eq)]
pub struct ReceiverSessionSecret(Zeroizing<[u8; 32]>);

impl ReceiverSessionSecret {
    /// Validates receiver private-key bytes
    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self> {
        let bytes = Zeroizing::new(bytes);
        SecretKey::from_slice(bytes.as_ref())?;

        Ok(Self(bytes))
    }

    /// Exposes the receiver private-key bytes for protected persistence
    pub fn expose_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for ReceiverSessionSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ReceiverSessionSecret(****)")
    }
}

/// A failed operation that returns its state for another attempt
pub struct RetryableError<S> {
    state: Box<S>,
    error: Error,
}

impl<S> RetryableError<S> {
    fn new(state: S, error: Error) -> Self {
        Self { state: Box::new(state), error }
    }

    /// Returns the protocol error
    pub fn error(&self) -> &Error {
        &self.error
    }

    /// Returns the reusable protocol state
    pub fn state(&self) -> &S {
        &self.state
    }

    /// Returns the reusable state and protocol error
    pub fn into_parts(self) -> (S, Error) {
        (*self.state, self.error)
    }
}

impl<S: fmt::Debug> fmt::Debug for RetryableError<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RetryableError")
            .field("state", &self.state)
            .field("error", &self.error)
            .finish()
    }
}

impl<S> fmt::Display for RetryableError<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.error.fmt(f)
    }
}

impl<S: fmt::Debug> std::error::Error for RetryableError<S> {}

/// A receiver-side Key Teleport session
#[derive(Debug)]
pub struct ReceiverSession {
    private_key: EphemeralPrivateKey,
}

impl ReceiverSession {
    /// Creates a receiver session with a new ephemeral private key
    pub fn new() -> Self {
        Self { private_key: EphemeralPrivateKey::generate() }
    }

    /// Restores a receiver session from a protected secret
    pub fn from_secret(secret: ReceiverSessionSecret) -> Result<Self> {
        let private_key = EphemeralPrivateKey::from_bytes(*secret.expose_bytes())?;

        Ok(Self { private_key })
    }

    /// Exports a zeroizing secret for protected session persistence
    pub fn export_secret(&self) -> ReceiverSessionSecret {
        ReceiverSessionSecret(Zeroizing::new(self.private_key.expose_bytes()))
    }

    /// Creates the receiver request to share with a sender
    pub fn request(&self) -> Result<ReceiveRequest> {
        let (numeric_code, payload) = crypto::generate_receiver_packet(&self.private_key)?;

        Ok(ReceiveRequest { numeric_code, packet: ReceiverPacket::new(payload.to_vec())? })
    }

    /// Decrypts the outer sender-packet layer and consumes the active session
    ///
    /// A failure returns the session in [`RetryableError`] so the caller can try another packet
    pub fn decode_step1(
        self,
        packet: &SenderPacket,
    ) -> std::result::Result<PendingPayload, RetryableError<Self>> {
        let sender_pubkey = match PublicKey::from_slice(packet.sender_pubkey_bytes()) {
            Ok(sender_pubkey) => sender_pubkey,
            Err(error) => return Err(RetryableError::new(self, error.into())),
        };
        let session_key = self.private_key.session_key(&sender_pubkey);
        let inner = match session_key.decrypt_outer(packet.encrypted_body()) {
            Ok(inner) => inner,
            Err(error) => return Err(RetryableError::new(self, error)),
        };

        Ok(PendingPayload { receiver: Some(self), session_key, inner: Zeroizing::new(inner) })
    }
}

impl Default for ReceiverSession {
    fn default() -> Self {
        Self::new()
    }
}

/// A receiver request containing the numeric code and packet to share
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReceiveRequest {
    /// The numeric code needed by the sender
    pub numeric_code: NumericCode,
    /// The receiver packet needed by the sender
    pub packet: ReceiverPacket,
}

/// A sender payload awaiting password-based decryption
pub struct PendingPayload {
    receiver: Option<ReceiverSession>,
    session_key: SessionKey,
    inner: Zeroizing<Vec<u8>>,
}

impl PendingPayload {
    /// Decrypts the exact plaintext without consuming this password-attempt state
    pub fn decrypt(&self, password: &TeleportPassword) -> Result<DecryptedPayload> {
        let noid_key = password.expose_bytes();
        let paranoid_key = self.session_key.paranoid_key(noid_key);
        let plaintext = crypto::decrypt_inner(&paranoid_key, &self.inner)?;

        DecryptedPayload::from_bytes(plaintext)
    }

    /// Decrypts and decodes the payload
    ///
    /// A failure returns this pending state so the caller can retry the password
    pub fn complete(
        mut self,
        password: &TeleportPassword,
    ) -> std::result::Result<DecodedTransfer, RetryableError<Self>> {
        let payload = match self.decrypt(password).and_then(DecryptedPayload::decode) {
            Ok(payload) => payload,
            Err(error) => return Err(RetryableError::new(self, error)),
        };
        let receiver =
            self.receiver.take().expect("pending payload always owns its receiver session");

        Ok(DecodedTransfer { receiver, payload })
    }

    /// Cancels the pending transfer and returns the active receiver session
    pub fn into_receiver(mut self) -> ReceiverSession {
        self.receiver.take().expect("pending payload always owns its receiver session")
    }
}

impl fmt::Debug for PendingPayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PendingPayload")
            .field("receiver", &self.receiver)
            .field("session_key", &self.session_key)
            .field("inner", &format_args!("{} encrypted bytes", self.inner.len()))
            .finish()
    }
}

/// A decoded transfer awaiting application acceptance
#[derive(Debug)]
pub struct DecodedTransfer {
    receiver: ReceiverSession,
    payload: Payload,
}

impl DecodedTransfer {
    /// Returns the decoded payload for review
    pub fn payload(&self) -> &Payload {
        &self.payload
    }

    /// Accepts the transfer, consumes the receiver session, and returns the payload
    ///
    /// The caller must also delete every persisted copy of the exported receiver secret
    pub fn accept(self) -> Payload {
        self.payload
    }

    /// Rejects the transfer and restores the active receiver session
    pub fn reject(self) -> ReceiverSession {
        self.receiver
    }
}
