#![doc = include_str!("../README.md")]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

mod crypto;
mod numeric_code;
mod packet;
mod password;
mod payload;
mod receiver;
mod sender;

pub use numeric_code::NumericCode;
pub use packet::{Packet, PsbtPacket, ReceiverPacket, SenderPacket};
pub use password::TeleportPassword;
pub use payload::{
    DecodedPayload, NoteRecord, NotesPayload, NotesRecord, PasswordRecord, Payload,
    UnsupportedPayloadKind, XprvPayload,
};
pub use receiver::{PendingPayload, ReceiveRequest, ReceiverSession};
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

    /// The KeyTeleport URL is invalid
    #[error("invalid KeyTeleport URL")]
    InvalidUrl,

    /// The payload type is valid but unsupported
    #[error("unsupported KeyTeleport payload type {0}")]
    UnsupportedPayload(UnsupportedPayloadKind),

    /// The mnemonic payload is invalid
    #[error("invalid mnemonic payload")]
    InvalidMnemonicPayload,

    /// The mnemonic word count is unsupported
    #[error("unsupported KeyTeleport mnemonic word count {0}; expected 12, 18, or 24 words")]
    UnsupportedMnemonicWordCount(usize),

    /// The mnemonic language cannot be transferred without changing its BIP39 seed
    #[error("Key Teleport mnemonic payloads must use the English BIP39 word list")]
    UnsupportedMnemonicLanguage,

    /// The extended private key payload is invalid
    #[error("invalid xprv payload")]
    InvalidXprvPayload,

    /// The extended private key payload contains a derived key
    #[error("xprv payload is not a master key")]
    NonMasterXprvPayload,

    /// The extended private key payload is not for mainnet
    #[error("xprv payload is not a mainnet key")]
    NonMainnetXprvPayload,

    /// The Secure Notes & Passwords payload is invalid
    #[error("invalid secure notes payload")]
    InvalidNotesPayload,

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

    /// Base58 data is invalid
    #[error("invalid base58 data")]
    Base58(#[from] bitcoin::base58::Error),

    /// A BIP32 key is invalid
    #[error("invalid BIP32 key")]
    Bip32(#[from] bitcoin::bip32::Error),

    /// A URL is invalid
    #[error("invalid URL")]
    Url(#[from] url::ParseError),
}
