use std::fmt;

use bip39::{Language, Mnemonic};
use zeroize::Zeroizing;

use crate::{Error, Result};

mod notes;
mod stash;
mod xprv;

pub use notes::{NoteRecord, NotesPayload, NotesRecord, PasswordRecord};
pub use xprv::XprvPayload;

// keyteleport payload type codes use the first decrypted body byte
const PAYLOAD_CODE_STASH: u8 = b's';
const PAYLOAD_CODE_XPRV: u8 = b'x';
const PAYLOAD_CODE_NOTES: u8 = b'n';
const PAYLOAD_CODE_VAULT: u8 = b'v';
const PAYLOAD_CODE_PSBT: u8 = b'p';
const PAYLOAD_CODE_BACKUP: u8 = b'b';

/// A recognized KeyTeleport payload type that this crate cannot decode
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UnsupportedPayloadKind {
    /// A COLDCARD vault payload
    Vault,
    /// A PSBT payload
    Psbt,
    /// A COLDCARD backup payload
    Backup,
    /// An unknown payload code
    Unknown(u8),
}

impl fmt::Display for UnsupportedPayloadKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Vault => write!(f, "{}", PAYLOAD_CODE_VAULT as char),
            Self::Psbt => write!(f, "{}", PAYLOAD_CODE_PSBT as char),
            Self::Backup => write!(f, "{}", PAYLOAD_CODE_BACKUP as char),
            Self::Unknown(code) => write!(f, "0x{code:02x}"),
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
enum PayloadKind {
    Mnemonic(Mnemonic),
    Xprv(XprvPayload),
}

/// A secret payload that can be transferred by COLDCARD KeyTeleport
#[derive(Clone, PartialEq, Eq)]
pub struct Payload(PayloadKind);

impl Payload {
    /// Creates a mnemonic payload when its word count is supported by COLDCARD
    pub fn mnemonic(mnemonic: Mnemonic) -> Result<Self> {
        if mnemonic.language() != Language::English {
            return Err(Error::UnsupportedMnemonicLanguage);
        }

        let word_count = mnemonic.word_count();
        if !matches!(word_count, 12 | 18 | 24) {
            return Err(Error::UnsupportedMnemonicWordCount(word_count));
        }

        Ok(Self(PayloadKind::Mnemonic(mnemonic)))
    }

    /// Creates an xprv payload
    pub fn xprv(value: impl AsRef<str>) -> Result<Self> {
        Ok(Self(PayloadKind::Xprv(XprvPayload::parse(value.as_ref())?)))
    }

    pub(crate) fn encode(&self) -> Result<Zeroizing<Vec<u8>>> {
        match &self.0 {
            PayloadKind::Mnemonic(mnemonic) => stash::encode_mnemonic(mnemonic),
            PayloadKind::Xprv(xprv) => stash::encode_xprv(xprv),
        }
    }
}

impl fmt::Debug for Payload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            PayloadKind::Mnemonic(_) => f.write_str("Payload::Mnemonic(****)"),
            PayloadKind::Xprv(_) => f.write_str("Payload::Xprv(****)"),
        }
    }
}

/// A payload decoded from a sender response
#[derive(Clone, PartialEq, Eq)]
pub enum DecodedPayload {
    /// A BIP39 mnemonic
    Mnemonic(Mnemonic),
    /// A BIP32 master extended private key
    Xprv(XprvPayload),
    /// COLDCARD Secure Notes & Passwords records
    Notes(NotesPayload),
}

impl From<stash::DecodedStash> for DecodedPayload {
    fn from(payload: stash::DecodedStash) -> Self {
        match payload {
            stash::DecodedStash::Mnemonic(mnemonic) => Self::Mnemonic(mnemonic),
            stash::DecodedStash::Xprv(xprv) => Self::Xprv(xprv),
        }
    }
}

impl DecodedPayload {
    pub(crate) fn decode(bytes: &[u8]) -> Result<Self> {
        let (&code, body) = bytes.split_first().ok_or(Error::InvalidPacket)?;

        match code {
            PAYLOAD_CODE_STASH => stash::decode(body).map(Self::from),
            PAYLOAD_CODE_XPRV => xprv::decode_body(body).map(Self::Xprv),
            PAYLOAD_CODE_NOTES => notes::decode_body(body).map(Self::Notes),
            PAYLOAD_CODE_VAULT => Err(Error::UnsupportedPayload(UnsupportedPayloadKind::Vault)),
            PAYLOAD_CODE_PSBT => Err(Error::UnsupportedPayload(UnsupportedPayloadKind::Psbt)),
            PAYLOAD_CODE_BACKUP => Err(Error::UnsupportedPayload(UnsupportedPayloadKind::Backup)),
            other => Err(Error::UnsupportedPayload(UnsupportedPayloadKind::Unknown(other))),
        }
    }
}

impl fmt::Debug for DecodedPayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Mnemonic(_) => f.write_str("DecodedPayload::Mnemonic(****)"),
            Self::Xprv(_) => f.write_str("DecodedPayload::Xprv(****)"),
            Self::Notes(_) => f.write_str("DecodedPayload::Notes(****)"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn other_unsupported_payload_types_remain_typed() {
        for (code, expected) in [
            (PAYLOAD_CODE_VAULT, UnsupportedPayloadKind::Vault),
            (PAYLOAD_CODE_PSBT, UnsupportedPayloadKind::Psbt),
            (PAYLOAD_CODE_BACKUP, UnsupportedPayloadKind::Backup),
            (b'?', UnsupportedPayloadKind::Unknown(b'?')),
        ] {
            assert!(matches!(
                DecodedPayload::decode(&[code]),
                Err(Error::UnsupportedPayload(kind)) if kind == expected
            ));
        }
    }
}
