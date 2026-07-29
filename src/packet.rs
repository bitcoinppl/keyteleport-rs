use bbqr::{
    encode::Encoding,
    file_type::FileType,
    join::Joined,
    qr::Version,
    split::{Split, SplitOptions},
};
use bitcoin::secp256k1::PublicKey;
use rand::RngExt as _;

use crate::{Error, Result, crypto};

const KEY_TELEPORT_DOMAIN: &str = "keyteleport.com";
const MIN_SENDER_PACKET_LEN: usize = 33 + 5;
const MIN_PSBT_PACKET_LEN: usize = 4 + 5;
const MAX_PSBT_NONCE: u32 = 1 << 28;

/// Options for Base32 Key Teleport BBQr splitting
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BbqrOptions {
    /// The minimum number of parts
    pub min_parts: usize,
    /// The maximum number of parts
    pub max_parts: usize,
    /// The minimum QR version
    pub min_version: Version,
    /// The maximum QR version
    pub max_version: Version,
}

impl Default for BbqrOptions {
    fn default() -> Self {
        let defaults = SplitOptions::default();

        Self {
            min_parts: defaults.min_split_number,
            max_parts: defaults.max_split_number,
            min_version: defaults.min_version,
            max_version: defaults.max_version,
        }
    }
}

impl BbqrOptions {
    fn into_split_options(self) -> SplitOptions {
        SplitOptions {
            encoding: Encoding::Base32,
            min_split_number: self.min_parts,
            max_split_number: self.max_parts,
            min_version: self.min_version,
            max_version: self.max_version,
        }
    }
}

/// A decoded Key Teleport packet
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Packet {
    /// A receiver request packet
    Receiver(ReceiverPacket),
    /// An encrypted sender response packet
    Sender(SenderPacket),
    /// An encrypted multisig PSBT packet
    Psbt(PsbtPacket),
}

impl Packet {
    /// Parses one complete BBQr part
    pub fn from_bbqr_part(value: &str) -> Result<Self> {
        Self::from_bbqr_parts(vec![value.to_string()])
    }

    /// Joins and parses all parts of a Key Teleport BBQr
    pub fn from_bbqr_parts(parts: Vec<String>) -> Result<Self> {
        if parts.iter().any(|part| !part.is_ascii()) {
            return Err(Error::InvalidPacket);
        }

        Joined::try_from_parts(parts)?.try_into()
    }

    /// Parses a Key Teleport URL or one complete BBQr part
    pub fn from_url(value: &str) -> Result<Self> {
        let value = value.trim();
        if value.to_ascii_uppercase().starts_with("B$") {
            return Self::from_bbqr_part(value);
        }

        let url = parse_keyteleport_url(value)?;
        let fragment = url.fragment().ok_or(Error::InvalidUrl)?;

        Self::from_bbqr_part(fragment)
    }

    /// Encodes the packet as Base32 BBQr parts
    pub fn to_bbqr(&self, options: BbqrOptions) -> Result<Split> {
        let (bytes, file_type) = match self {
            Self::Receiver(packet) => (packet.as_bytes(), FileType::KeyTeleportReceiver),
            Self::Sender(packet) => (packet.as_bytes(), FileType::KeyTeleportSender),
            Self::Psbt(packet) => (packet.as_bytes(), FileType::KeyTeleportPsbt),
        };

        Split::try_from_data(bytes, file_type, options.into_split_options()).map_err(Into::into)
    }

    /// Encodes the packet as one Base32 BBQr part
    pub fn to_bbqr_part(&self) -> Result<String> {
        let split =
            self.to_bbqr(BbqrOptions { min_parts: 1, max_parts: 1, ..Default::default() })?;

        split.parts.into_iter().next().ok_or(Error::InvalidPacket)
    }

    /// Encodes the packet as a Key Teleport URL
    pub fn to_url(&self) -> Result<String> {
        Ok(format!("https://{KEY_TELEPORT_DOMAIN}/#{}", self.to_bbqr_part()?))
    }
}

impl TryFrom<Joined> for Packet {
    type Error = Error;

    fn try_from(joined: Joined) -> Result<Self> {
        if joined.encoding != Encoding::Base32 {
            return Err(Error::InvalidBbqrEncoding);
        }

        match joined.file_type {
            FileType::KeyTeleportReceiver => ReceiverPacket::new(joined.data).map(Self::Receiver),
            FileType::KeyTeleportSender => SenderPacket::new(joined.data).map(Self::Sender),
            FileType::KeyTeleportPsbt => PsbtPacket::new(joined.data).map(Self::Psbt),
            _ => Err(Error::InvalidPacket),
        }
    }
}

/// A validated receiver request packet
#[derive(Clone, PartialEq, Eq)]
pub struct ReceiverPacket(Vec<u8>);

impl ReceiverPacket {
    /// Validates and wraps a receiver packet
    pub fn new(payload: Vec<u8>) -> Result<Self> {
        if payload.len() != crypto::RECEIVER_PACKET_LEN {
            return Err(Error::InvalidReceiverPacket);
        }

        Ok(Self(payload))
    }

    /// Returns the encoded packet bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Encodes the packet as Base32 BBQr parts
    pub fn to_bbqr(&self, options: BbqrOptions) -> Result<Split> {
        Packet::Receiver(self.clone()).to_bbqr(options)
    }

    /// Encodes the packet as one Base32 BBQr part
    pub fn to_bbqr_part(&self) -> Result<String> {
        Packet::Receiver(self.clone()).to_bbqr_part()
    }

    /// Encodes the packet as a Key Teleport URL
    pub fn to_url(&self) -> Result<String> {
        Packet::Receiver(self.clone()).to_url()
    }
}

impl std::fmt::Debug for ReceiverPacket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("ReceiverPacket").field(&format_args!("{} bytes", self.0.len())).finish()
    }
}

/// A validated encrypted sender response packet
#[derive(Clone, PartialEq, Eq)]
pub struct SenderPacket(Vec<u8>);

impl SenderPacket {
    /// Validates and wraps a sender packet
    pub fn new(payload: Vec<u8>) -> Result<Self> {
        if payload.len() < MIN_SENDER_PACKET_LEN || PublicKey::from_slice(&payload[..33]).is_err() {
            return Err(Error::InvalidSenderPacket);
        }

        Ok(Self(payload))
    }

    /// Returns the encoded packet bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Returns the encoded sender public key
    pub fn sender_pubkey_bytes(&self) -> &[u8] {
        &self.0[..33]
    }

    /// Returns the encrypted payload body
    pub fn encrypted_body(&self) -> &[u8] {
        &self.0[33..]
    }

    /// Encodes the packet as Base32 BBQr parts
    pub fn to_bbqr(&self, options: BbqrOptions) -> Result<Split> {
        Packet::Sender(self.clone()).to_bbqr(options)
    }

    /// Encodes the packet as one Base32 BBQr part
    pub fn to_bbqr_part(&self) -> Result<String> {
        Packet::Sender(self.clone()).to_bbqr_part()
    }

    /// Encodes the packet as a Key Teleport URL
    pub fn to_url(&self) -> Result<String> {
        Packet::Sender(self.clone()).to_url()
    }
}

impl std::fmt::Debug for SenderPacket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("SenderPacket").field(&format_args!("{} bytes", self.0.len())).finish()
    }
}

/// A validated 28-bit multisig PSBT nonce
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PsbtNonce(u32);

impl PsbtNonce {
    /// Validates a nonce in the COLDCARD range
    pub fn new(value: u32) -> Result<Self> {
        if value >= MAX_PSBT_NONCE {
            return Err(Error::InvalidPsbtNonce(value));
        }

        Ok(Self(value))
    }

    /// Generates a random nonce
    pub fn generate() -> Self {
        Self(rand::rng().random_range(0..MAX_PSBT_NONCE))
    }

    /// Returns the numeric nonce
    pub fn value(self) -> u32 {
        self.0
    }

    fn from_bytes(bytes: [u8; 4]) -> Result<Self> {
        Self::new(u32::from_be_bytes(bytes))
    }
}

/// An encrypted PSBT packet transported with BBQr type `E`
#[derive(Clone, PartialEq, Eq)]
pub struct PsbtPacket(Vec<u8>);

impl PsbtPacket {
    /// Validates and wraps an encrypted PSBT packet
    pub fn new(payload: Vec<u8>) -> Result<Self> {
        if payload.len() < MIN_PSBT_PACKET_LEN {
            return Err(Error::InvalidPsbtPacket);
        }

        let nonce_bytes: [u8; 4] = payload[..4].try_into().map_err(|_| Error::InvalidPsbtPacket)?;
        PsbtNonce::from_bytes(nonce_bytes)?;

        Ok(Self(payload))
    }

    /// Builds a packet from a validated nonce and encrypted body
    pub fn from_parts(nonce: PsbtNonce, encrypted_body: Vec<u8>) -> Result<Self> {
        if encrypted_body.len() < MIN_PSBT_PACKET_LEN - 4 {
            return Err(Error::InvalidPsbtPacket);
        }

        let mut payload = Vec::with_capacity(4 + encrypted_body.len());
        payload.extend_from_slice(&nonce.value().to_be_bytes());
        payload.extend_from_slice(&encrypted_body);
        Self::new(payload)
    }

    /// Returns the packet nonce
    pub fn nonce(&self) -> PsbtNonce {
        let bytes = self.0[..4].try_into().expect("validated PSBT packet has a nonce");
        PsbtNonce::from_bytes(bytes).expect("validated PSBT packet has a valid nonce")
    }

    /// Returns the encrypted payload body
    pub fn encrypted_body(&self) -> &[u8] {
        &self.0[4..]
    }

    /// Returns the encoded packet bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Encodes the packet as Base32 BBQr parts
    pub fn to_bbqr(&self, options: BbqrOptions) -> Result<Split> {
        Packet::Psbt(self.clone()).to_bbqr(options)
    }

    /// Encodes the packet as one Base32 BBQr part
    pub fn to_bbqr_part(&self) -> Result<String> {
        Packet::Psbt(self.clone()).to_bbqr_part()
    }
}

impl std::fmt::Debug for PsbtPacket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PsbtPacket")
            .field("nonce", &self.nonce())
            .field("encrypted_body", &format_args!("{} bytes", self.encrypted_body().len()))
            .finish()
    }
}

fn parse_keyteleport_url(value: &str) -> Result<url::Url> {
    let trimmed = value.trim();
    let parseable = if trimmed.to_ascii_lowercase().starts_with(&format!("{KEY_TELEPORT_DOMAIN}/"))
    {
        format!("https://{trimmed}")
    } else {
        trimmed.to_string()
    };
    let url = url::Url::parse(&parseable)?;

    if url.scheme() != "https"
        || url.host_str().is_none_or(|host| !host.eq_ignore_ascii_case(KEY_TELEPORT_DOMAIN))
        || url.port().is_some()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.path() != "/"
        || url.query().is_some()
    {
        return Err(Error::InvalidUrl);
    }

    Ok(url)
}
