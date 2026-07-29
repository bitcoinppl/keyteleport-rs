#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod crypto;
mod numeric_code;
mod packet;
mod password;
mod payload;
mod psbt;
mod receiver;
mod sender;

pub use numeric_code::NumericCode;
pub use packet::{BbqrOptions, Packet, PsbtNonce, PsbtPacket, ReceiverPacket, SenderPacket};
pub use password::TeleportPassword;
pub use payload::{
    BackupPayload, DecryptedPayload, MasterSecret, NoteRecord, NotesPayload, NotesRecord,
    PasswordRecord, Payload, PayloadKind, PsbtPayload, UnknownPayload, VaultPayload, VaultSecret,
    XprvPayload, XprvWireFormat,
};
pub use psbt::{PendingPsbtPayload, PsbtReceiverSession, PsbtSendResponse, PsbtSenderSession};
pub use receiver::{
    DecodedTransfer, PendingPayload, ReceiveRequest, ReceiverSession, ReceiverSessionSecret,
    RetryableError,
};
pub use sender::{SendResponse, SenderSession};

/// A KeyTeleport operation result
pub type Result<T> = std::result::Result<T, Error>;

/// An error produced while processing a KeyTeleport transfer
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// The numeric receiver code is invalid
    #[error("invalid numeric receiver code")]
    InvalidNumericCode,

    /// The transfer password is invalid
    #[error("invalid teleport password")]
    InvalidTeleportPassword,

    /// The receiver packet is invalid
    #[error("invalid receiver packet")]
    InvalidReceiverPacket,

    /// The sender packet is invalid
    #[error("invalid sender packet")]
    InvalidSenderPacket,

    /// The packet type or encoding is invalid
    #[error("invalid KeyTeleport packet")]
    InvalidPacket,

    /// A Key Teleport BBQr uses an encoding other than Base32
    #[error("Key Teleport BBQr must use Base32 encoding")]
    InvalidBbqrEncoding,

    /// The decrypted payload is empty or invalid
    #[error("invalid KeyTeleport payload")]
    InvalidPayload,

    /// The KeyTeleport URL is invalid
    #[error("invalid KeyTeleport URL")]
    InvalidUrl,

    /// A COLDCARD stash payload is invalid
    #[error("invalid KeyTeleport stash payload")]
    InvalidStashPayload,

    /// The mnemonic word count is unsupported
    #[error("unsupported KeyTeleport mnemonic word count {0}; expected 12, 18, or 24 words")]
    UnsupportedMnemonicWordCount(usize),

    /// The mnemonic language cannot be transferred without changing its BIP39 seed
    #[error("Key Teleport mnemonic payloads must use the English BIP39 word list")]
    UnsupportedMnemonicLanguage,

    /// The raw master-secret length is invalid
    #[error("invalid raw master-secret length {0}; expected 16 to 64 bytes")]
    InvalidMasterSecretLength(usize),

    /// The extended private key payload is invalid
    #[error("invalid xprv payload")]
    InvalidXprvPayload,

    /// The extended private key payload contains a derived key
    #[error("xprv payload is not a master key")]
    NonMasterXprvPayload,

    /// A compact stash XPRV has no network for full XPRV encoding
    #[error("a network is required for full xprv encoding")]
    MissingXprvNetwork,

    /// The Secure Notes & Passwords payload is invalid
    #[error("invalid secure notes payload")]
    InvalidNotesPayload,

    /// The Seed Vault payload is invalid
    #[error("invalid Seed Vault payload")]
    InvalidVaultPayload,

    /// The backup payload is invalid
    #[error("invalid backup payload")]
    InvalidBackupPayload,

    /// The PSBT payload is invalid
    #[error("invalid PSBT payload")]
    InvalidPsbtPayload,

    /// The encrypted PSBT packet is invalid
    #[error("invalid encrypted PSBT packet")]
    InvalidPsbtPacket,

    /// The multisig PSBT nonce is outside its 28-bit range
    #[error("invalid multisig PSBT nonce {0}")]
    InvalidPsbtNonce(u32),

    /// The derived PSBT receiver session does not match the packet nonce
    #[error("PSBT nonce mismatch: expected {expected}, got {actual}")]
    PsbtNonceMismatch {
        /// The nonce used to derive the session
        expected: u32,
        /// The nonce carried by the packet
        actual: u32,
    },

    /// A known payload code was used for an unknown payload
    #[error("payload code 0x{0:02x} is already known")]
    KnownPayloadCode(u8),

    /// Packet checksum verification failed
    #[error("checksum verification failed")]
    Checksum,

    /// A secp256k1 key is invalid
    #[error("invalid secp256k1 key")]
    Secp256k1(#[from] bitcoin::secp256k1::Error),

    /// A BIP39 mnemonic is invalid
    #[error("invalid BIP39 mnemonic")]
    Bip39(#[from] bip39::Error),

    /// BBQr parts could not be joined
    #[error("invalid BBQr data")]
    BbqrJoin(#[from] bbqr::join::JoinError),

    /// BBQr data could not be split
    #[error("failed to build BBQr data")]
    BbqrSplit(#[from] bbqr::split::SplitError),

    /// Base32 data is invalid
    #[error("invalid base32 data")]
    Base32(#[from] data_encoding::DecodeError),

    /// A BIP32 key is invalid
    #[error("invalid BIP32 key")]
    Bip32(#[from] bitcoin::bip32::Error),

    /// A URL is invalid
    #[error("invalid URL")]
    Url(#[from] url::ParseError),
}
