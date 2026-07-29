use std::{fmt, str::FromStr};

use bip39::{Language, Mnemonic};
use bitcoin::{
    NetworkKind,
    bip32::{ChainCode, ChildNumber, Fingerprint, Xpriv},
    psbt::Psbt,
    secp256k1::SecretKey,
};
use data_encoding::HEXLOWER;
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, Zeroizing};

use crate::{Error, Result};

const PAYLOAD_CODE_STASH: u8 = b's';
const PAYLOAD_CODE_XPRV: u8 = b'x';
const PAYLOAD_CODE_NOTES: u8 = b'n';
const PAYLOAD_CODE_VAULT: u8 = b'v';
const PAYLOAD_CODE_PSBT: u8 = b'p';
const PAYLOAD_CODE_BACKUP: u8 = b'b';

const STASH_LEN: usize = 72;
const STASH_MARKER_XPRV: u8 = 0x01;
const STASH_MARKER_MNEMONIC_FLAG: u8 = 0x80;
const STASH_MNEMONIC_ENTROPY_UNITS_MASK: u8 = 0x03;
const STASH_RAW_MASTER_SECRET_LEN: std::ops::RangeInclusive<u8> = 0x10..=0x40;

/// A Key Teleport payload type code
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PayloadKind {
    /// A COLDCARD stash payload
    Stash,
    /// A full binary XPRV payload
    Xprv,
    /// A Secure Notes & Passwords JSON payload
    Notes,
    /// A Seed Vault JSON payload
    Vault,
    /// A binary PSBT payload
    Psbt,
    /// A full COLDCARD backup payload
    Backup,
    /// An unrecognized payload code
    Unknown(u8),
}

impl PayloadKind {
    /// Returns the wire type code
    pub fn code(self) -> u8 {
        match self {
            Self::Stash => PAYLOAD_CODE_STASH,
            Self::Xprv => PAYLOAD_CODE_XPRV,
            Self::Notes => PAYLOAD_CODE_NOTES,
            Self::Vault => PAYLOAD_CODE_VAULT,
            Self::Psbt => PAYLOAD_CODE_PSBT,
            Self::Backup => PAYLOAD_CODE_BACKUP,
            Self::Unknown(code) => code,
        }
    }

    fn from_code(code: u8) -> Self {
        match code {
            PAYLOAD_CODE_STASH => Self::Stash,
            PAYLOAD_CODE_XPRV => Self::Xprv,
            PAYLOAD_CODE_NOTES => Self::Notes,
            PAYLOAD_CODE_VAULT => Self::Vault,
            PAYLOAD_CODE_PSBT => Self::Psbt,
            PAYLOAD_CODE_BACKUP => Self::Backup,
            other => Self::Unknown(other),
        }
    }

    fn is_known_code(code: u8) -> bool {
        !matches!(Self::from_code(code), Self::Unknown(_))
    }
}

impl fmt::Display for PayloadKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unknown(code) => write!(f, "0x{code:02x}"),
            known => write!(f, "{}", known.code() as char),
        }
    }
}

/// A decrypted payload that retains the exact plaintext wire bytes
#[derive(Clone, PartialEq, Eq)]
pub struct DecryptedPayload(Zeroizing<Vec<u8>>);

impl DecryptedPayload {
    /// Validates and retains decrypted payload bytes
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Self> {
        if bytes.is_empty() {
            return Err(Error::InvalidPayload);
        }

        Ok(Self(Zeroizing::new(bytes)))
    }

    /// Returns the payload type
    pub fn kind(&self) -> PayloadKind {
        PayloadKind::from_code(self.0[0])
    }

    /// Exposes the complete plaintext wire payload
    pub fn expose_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Exposes the plaintext body without the type code
    pub fn expose_body(&self) -> &[u8] {
        &self.0[1..]
    }

    /// Decodes the plaintext into a typed payload
    pub fn decode(self) -> Result<Payload> {
        let Self(mut bytes) = self;
        let code = bytes.remove(0);

        match PayloadKind::from_code(code) {
            PayloadKind::Stash => decode_stash_body(&bytes).map(Payload::from),
            PayloadKind::Xprv => {
                decode_full_xprv_body(&bytes).map(|value| Payload::Xprv(value.with_full_format()))
            }
            PayloadKind::Notes => decode_notes_body(&bytes).map(Payload::Notes),
            PayloadKind::Vault => decode_vault_body(&bytes).map(Payload::Vault),
            PayloadKind::Psbt => PsbtPayload::new(std::mem::take(&mut *bytes)).map(Payload::Psbt),
            PayloadKind::Backup => {
                BackupPayload::new(std::mem::take(&mut *bytes)).map(Payload::Backup)
            }
            PayloadKind::Unknown(code) => Ok(Payload::Unknown(UnknownPayload {
                code,
                body: Zeroizing::new(std::mem::take(&mut *bytes)),
            })),
        }
    }

    pub(crate) fn into_bytes(mut self) -> Zeroizing<Vec<u8>> {
        Zeroizing::new(std::mem::take(&mut *self.0))
    }
}

impl fmt::Debug for DecryptedPayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DecryptedPayload")
            .field("kind", &self.kind())
            .field("body_len", &self.expose_body().len())
            .finish_non_exhaustive()
    }
}

/// A typed Key Teleport payload
#[derive(Clone, PartialEq, Eq)]
pub enum Payload {
    /// A BIP39 mnemonic stash
    Mnemonic(Mnemonic),
    /// A BIP32 master extended private key
    Xprv(XprvPayload),
    /// A raw BIP32 master secret
    MasterSecret(MasterSecret),
    /// COLDCARD Secure Notes & Passwords records
    Notes(NotesPayload),
    /// A COLDCARD Seed Vault entry
    Vault(VaultPayload),
    /// A binary PSBT
    Psbt(PsbtPayload),
    /// A full COLDCARD backup
    Backup(BackupPayload),
    /// An unrecognized future payload
    Unknown(UnknownPayload),
}

impl Payload {
    /// Creates a mnemonic payload when its word count is supported by COLDCARD
    pub fn mnemonic(mnemonic: Mnemonic) -> Result<Self> {
        validate_mnemonic(&mnemonic)?;

        Ok(Self::Mnemonic(mnemonic))
    }

    /// Creates a canonical stash-encoded master XPRV payload
    pub fn xprv(value: impl AsRef<str>) -> Result<Self> {
        XprvPayload::parse(value.as_ref()).map(Self::Xprv)
    }

    /// Creates a full binary XPRV payload
    pub fn full_xprv(value: impl AsRef<str>) -> Result<Self> {
        XprvPayload::parse(value.as_ref()).map(|value| Self::Xprv(value.with_full_format()))
    }

    /// Creates a raw BIP32 master-secret stash payload
    pub fn master_secret(bytes: Vec<u8>) -> Result<Self> {
        MasterSecret::new(bytes).map(Self::MasterSecret)
    }

    /// Creates a Secure Notes & Passwords payload
    pub fn notes(records: Vec<NotesRecord>) -> Result<Self> {
        NotesPayload::new(records).map(Self::Notes)
    }

    /// Creates a Seed Vault payload
    pub fn vault(value: VaultPayload) -> Self {
        Self::Vault(value)
    }

    /// Creates a validated PSBT payload
    pub fn psbt(bytes: Vec<u8>) -> Result<Self> {
        PsbtPayload::new(bytes).map(Self::Psbt)
    }

    /// Creates a full-backup payload
    pub fn backup(bytes: Vec<u8>) -> Result<Self> {
        BackupPayload::new(bytes).map(Self::Backup)
    }

    /// Creates an unrecognized future payload
    pub fn unknown(code: u8, body: Vec<u8>) -> Result<Self> {
        UnknownPayload::new(code, body).map(Self::Unknown)
    }

    /// Returns the semantic payload type
    pub fn kind(&self) -> PayloadKind {
        match self {
            Self::Mnemonic(_) | Self::MasterSecret(_) => PayloadKind::Stash,
            Self::Xprv(value) => match value.wire_format() {
                XprvWireFormat::Stash => PayloadKind::Stash,
                XprvWireFormat::Full => PayloadKind::Xprv,
            },
            Self::Notes(_) => PayloadKind::Notes,
            Self::Vault(_) => PayloadKind::Vault,
            Self::Psbt(_) => PayloadKind::Psbt,
            Self::Backup(_) => PayloadKind::Backup,
            Self::Unknown(value) => PayloadKind::Unknown(value.code()),
        }
    }

    /// Encodes the typed value as exact decrypted wire bytes
    pub fn encode(&self) -> Result<DecryptedPayload> {
        let mut encoded = match self {
            Self::Mnemonic(mnemonic) => {
                encode_stash_payload(&VaultSecret::Mnemonic(mnemonic.clone()))?
            }
            Self::Xprv(xprv) if xprv.wire_format() == XprvWireFormat::Full => {
                encode_full_xprv_payload(xprv)?
            }
            Self::Xprv(xprv) => encode_stash_payload(&VaultSecret::Xprv(xprv.clone()))?,
            Self::MasterSecret(secret) => {
                encode_stash_payload(&VaultSecret::MasterSecret(secret.clone()))?
            }
            Self::Notes(notes) => encode_notes_payload(notes)?,
            Self::Vault(vault) => encode_vault_payload(vault)?,
            Self::Psbt(psbt) => encode_raw_payload(PAYLOAD_CODE_PSBT, psbt.expose_bytes()),
            Self::Backup(backup) => encode_raw_payload(PAYLOAD_CODE_BACKUP, backup.expose_bytes()),
            Self::Unknown(unknown) => encode_raw_payload(unknown.code, unknown.expose_body()),
        };

        DecryptedPayload::from_bytes(std::mem::take(&mut *encoded))
    }
}

impl From<VaultSecret> for Payload {
    fn from(value: VaultSecret) -> Self {
        match value {
            VaultSecret::Mnemonic(value) => Self::Mnemonic(value),
            VaultSecret::Xprv(value) => Self::Xprv(value),
            VaultSecret::MasterSecret(value) => Self::MasterSecret(value),
        }
    }
}

impl fmt::Debug for Payload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Mnemonic(_) => f.write_str("Payload::Mnemonic(****)"),
            Self::Xprv(_) => f.write_str("Payload::Xprv(****)"),
            Self::MasterSecret(_) => f.write_str("Payload::MasterSecret(****)"),
            Self::Notes(value) => f
                .debug_struct("Payload::Notes")
                .field("record_count", &value.records().len())
                .finish_non_exhaustive(),
            Self::Vault(_) => f.write_str("Payload::Vault(****)"),
            Self::Psbt(value) => f
                .debug_struct("Payload::Psbt")
                .field("byte_len", &value.expose_bytes().len())
                .finish_non_exhaustive(),
            Self::Backup(value) => f
                .debug_struct("Payload::Backup")
                .field("byte_len", &value.expose_bytes().len())
                .finish_non_exhaustive(),
            Self::Unknown(value) => f
                .debug_struct("Payload::Unknown")
                .field("code", &format_args!("0x{:02x}", value.code()))
                .field("body_len", &value.expose_body().len())
                .finish_non_exhaustive(),
        }
    }
}

/// The wire representation used for a master XPRV
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum XprvWireFormat {
    /// The compact COLDCARD stash representation
    Stash,
    /// The full 78-byte binary BIP32 representation
    Full,
}

/// A validated master extended private key transferred by Key Teleport
#[derive(Clone, PartialEq, Eq)]
pub struct XprvPayload {
    chain_code: ChainCode,
    private_key: SecretKey,
    network: Option<NetworkKind>,
    wire_format: XprvWireFormat,
}

impl XprvPayload {
    /// Parses and validates a master extended private key
    pub fn parse(value: &str) -> Result<Self> {
        let xprv = Xpriv::from_str(value).map_err(|_| Error::InvalidXprvPayload)?;
        validate_master_xprv(&xprv)?;

        Ok(Self::from_xpriv(xprv))
    }

    /// Returns the network encoded by a full XPRV when one is available
    ///
    /// A compact stash does not carry a network
    pub fn network(&self) -> Option<NetworkKind> {
        self.network
    }

    /// Builds a master extended private key for the selected network
    pub fn to_xpriv(&self, network: NetworkKind) -> Xpriv {
        Xpriv {
            network,
            depth: 0,
            parent_fingerprint: Fingerprint::default(),
            child_number: ChildNumber::Normal { index: 0 },
            private_key: self.private_key,
            chain_code: self.chain_code,
        }
    }

    /// Returns a Base58Check master extended private key for the selected network
    pub fn encode_string(&self, network: NetworkKind) -> String {
        self.to_xpriv(network).to_string()
    }

    /// Returns the selected wire representation
    pub fn wire_format(&self) -> XprvWireFormat {
        self.wire_format
    }

    fn with_full_format(mut self) -> Self {
        self.wire_format = XprvWireFormat::Full;
        self
    }

    fn from_xpriv(xprv: Xpriv) -> Self {
        Self {
            chain_code: xprv.chain_code,
            private_key: xprv.private_key,
            network: Some(xprv.network),
            wire_format: XprvWireFormat::Stash,
        }
    }

    fn from_stash(chain_code: ChainCode, private_key: SecretKey) -> Self {
        Self { chain_code, private_key, network: None, wire_format: XprvWireFormat::Stash }
    }
}

impl fmt::Debug for XprvPayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("XprvPayload")
            .field("network", &self.network)
            .field("wire_format", &self.wire_format)
            .finish_non_exhaustive()
    }
}

impl Drop for XprvPayload {
    fn drop(&mut self) {
        self.private_key.non_secure_erase();
    }
}

/// A raw BIP32 master secret between 16 and 64 bytes
#[derive(Clone, PartialEq, Eq)]
pub struct MasterSecret(Zeroizing<Vec<u8>>);

impl MasterSecret {
    /// Validates and retains raw master-secret bytes
    pub fn new(bytes: Vec<u8>) -> Result<Self> {
        if !matches!(bytes.len(), 16..=64) {
            return Err(Error::InvalidMasterSecretLength(bytes.len()));
        }

        Ok(Self(Zeroizing::new(bytes)))
    }

    /// Exposes the raw master-secret bytes
    pub fn expose_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Derives the corresponding master XPRV
    pub fn derive_xprv(&self, network: NetworkKind) -> Result<XprvPayload> {
        let xprv = Xpriv::new_master(network, &self.0).map_err(|_| Error::InvalidXprvPayload)?;

        XprvPayload::parse(&xprv.to_string())
    }
}

impl fmt::Debug for MasterSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("MasterSecret").field(&format_args!("{} bytes", self.0.len())).finish()
    }
}

/// A decoded collection of COLDCARD Secure Notes & Passwords records
#[derive(Clone, PartialEq, Eq, Zeroize)]
#[zeroize(drop)]
pub struct NotesPayload(Vec<NotesRecord>);

impl NotesPayload {
    /// Validates a nonempty collection of notes and passwords
    pub fn new(records: Vec<NotesRecord>) -> Result<Self> {
        if records.is_empty() {
            return Err(Error::InvalidNotesPayload);
        }

        Ok(Self(records))
    }

    /// Returns records in transmitted order
    pub fn records(&self) -> &[NotesRecord] {
        &self.0
    }

    /// Consumes the payload and returns its records
    pub fn into_records(mut self) -> Vec<NotesRecord> {
        std::mem::take(&mut self.0)
    }
}

impl fmt::Debug for NotesPayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("NotesPayload").field("record_count", &self.0.len()).finish()
    }
}

/// A decoded COLDCARD secure note or password record
#[derive(Clone, PartialEq, Eq, Zeroize)]
#[zeroize(drop)]
pub enum NotesRecord {
    /// A free-form secure note
    Note(NoteRecord),
    /// A structured password record
    Password(PasswordRecord),
}

impl NotesRecord {
    /// Returns the record title
    pub fn title(&self) -> &str {
        match self {
            Self::Note(note) => note.title(),
            Self::Password(password) => password.title(),
        }
    }

    /// Returns the optional record group
    pub fn group(&self) -> &str {
        match self {
            Self::Note(note) => note.group(),
            Self::Password(password) => password.group(),
        }
    }
}

impl fmt::Debug for NotesRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Note(_) => f.write_str("NotesRecord::Note(****)"),
            Self::Password(_) => f.write_str("NotesRecord::Password(****)"),
        }
    }
}

/// A COLDCARD free-form secure note
#[derive(Clone, PartialEq, Eq, Zeroize)]
#[zeroize(drop)]
pub struct NoteRecord {
    title: String,
    text: String,
    group: String,
}

impl NoteRecord {
    /// Creates a secure note
    pub fn new(title: String, text: String, group: String) -> Result<Self> {
        if title.is_empty() {
            return Err(Error::InvalidNotesPayload);
        }

        Ok(Self { title, text, group })
    }

    /// Returns the note title
    pub fn title(&self) -> &str {
        &self.title
    }

    /// Returns the free-form note text
    pub fn text(&self) -> &str {
        &self.text
    }

    /// Returns the optional group
    pub fn group(&self) -> &str {
        &self.group
    }
}

impl fmt::Debug for NoteRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("NoteRecord(****)")
    }
}

/// A COLDCARD structured password record
#[derive(Clone, PartialEq, Eq, Zeroize)]
#[zeroize(drop)]
pub struct PasswordRecord {
    title: String,
    username: String,
    password: String,
    site: String,
    notes: String,
    group: String,
}

impl PasswordRecord {
    /// Creates a structured password record
    pub fn new(
        title: String,
        username: String,
        password: String,
        site: String,
        notes: String,
        group: String,
    ) -> Result<Self> {
        if title.is_empty() {
            return Err(Error::InvalidNotesPayload);
        }

        Ok(Self { title, username, password, site, notes, group })
    }

    /// Returns the password record title
    pub fn title(&self) -> &str {
        &self.title
    }

    /// Returns the username
    pub fn username(&self) -> &str {
        &self.username
    }

    /// Returns the password
    pub fn password(&self) -> &str {
        &self.password
    }

    /// Returns the site
    pub fn site(&self) -> &str {
        &self.site
    }

    /// Returns the free-form notes
    pub fn notes(&self) -> &str {
        &self.notes
    }

    /// Returns the optional group
    pub fn group(&self) -> &str {
        &self.group
    }
}

impl fmt::Debug for PasswordRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PasswordRecord(****)")
    }
}

/// A secret stored in a COLDCARD Seed Vault entry
#[derive(Clone, PartialEq, Eq)]
pub enum VaultSecret {
    /// A BIP39 mnemonic
    Mnemonic(Mnemonic),
    /// A BIP32 master XPRV
    Xprv(XprvPayload),
    /// A raw BIP32 master secret
    MasterSecret(MasterSecret),
}

impl fmt::Debug for VaultSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Mnemonic(_) => f.write_str("VaultSecret::Mnemonic(****)"),
            Self::Xprv(_) => f.write_str("VaultSecret::Xprv(****)"),
            Self::MasterSecret(_) => f.write_str("VaultSecret::MasterSecret(****)"),
        }
    }
}

/// A typed COLDCARD Seed Vault entry
#[derive(Clone, PartialEq, Eq)]
pub struct VaultPayload {
    fingerprint: String,
    secret: VaultSecret,
    label: String,
    origin: String,
}

impl VaultPayload {
    /// Creates a validated Seed Vault entry
    pub fn new(
        fingerprint: impl AsRef<str>,
        secret: VaultSecret,
        label: String,
        origin: String,
    ) -> Result<Self> {
        if let VaultSecret::Mnemonic(mnemonic) = &secret {
            validate_mnemonic(mnemonic)?;
        }
        let fingerprint = normalize_fingerprint(fingerprint.as_ref())?;

        Ok(Self { fingerprint, secret, label, origin })
    }

    /// Returns the eight-digit hexadecimal master fingerprint
    pub fn fingerprint(&self) -> &str {
        &self.fingerprint
    }

    /// Returns the stored secret
    pub fn secret(&self) -> &VaultSecret {
        &self.secret
    }

    /// Returns the entry label
    pub fn label(&self) -> &str {
        &self.label
    }

    /// Returns the entry origin
    pub fn origin(&self) -> &str {
        &self.origin
    }
}

impl fmt::Debug for VaultPayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("VaultPayload(****)")
    }
}

impl Drop for VaultPayload {
    fn drop(&mut self) {
        self.fingerprint.zeroize();
        self.label.zeroize();
        self.origin.zeroize();
    }
}

/// A validated binary PSBT payload
#[derive(Clone, PartialEq, Eq)]
pub struct PsbtPayload(Zeroizing<Vec<u8>>);

impl PsbtPayload {
    /// Parses and retains a binary PSBT
    pub fn new(bytes: Vec<u8>) -> Result<Self> {
        Psbt::deserialize(&bytes).map_err(|_| Error::InvalidPsbtPayload)?;

        Ok(Self(Zeroizing::new(bytes)))
    }

    /// Exposes the binary PSBT bytes
    pub fn expose_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Parses the retained bytes as a Bitcoin PSBT
    pub fn parse(&self) -> Result<Psbt> {
        Psbt::deserialize(&self.0).map_err(|_| Error::InvalidPsbtPayload)
    }
}

impl fmt::Debug for PsbtPayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("PsbtPayload").field(&format_args!("{} bytes", self.0.len())).finish()
    }
}

/// A full COLDCARD backup payload retained as secret bytes
#[derive(Clone, PartialEq, Eq)]
pub struct BackupPayload(Zeroizing<Vec<u8>>);

impl BackupPayload {
    /// Validates and retains a nonempty backup
    pub fn new(bytes: Vec<u8>) -> Result<Self> {
        if bytes.is_empty() {
            return Err(Error::InvalidBackupPayload);
        }

        Ok(Self(Zeroizing::new(bytes)))
    }

    /// Exposes the backup bytes
    pub fn expose_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Returns the backup as UTF-8 text when possible
    pub fn as_text(&self) -> Result<&str> {
        std::str::from_utf8(&self.0).map_err(|_| Error::InvalidBackupPayload)
    }
}

impl fmt::Debug for BackupPayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("BackupPayload").field(&format_args!("{} bytes", self.0.len())).finish()
    }
}

/// An unrecognized future payload retained without data loss
#[derive(Clone, PartialEq, Eq)]
pub struct UnknownPayload {
    code: u8,
    body: Zeroizing<Vec<u8>>,
}

impl UnknownPayload {
    /// Creates a payload for an unrecognized type code
    pub fn new(code: u8, body: Vec<u8>) -> Result<Self> {
        if PayloadKind::is_known_code(code) {
            return Err(Error::KnownPayloadCode(code));
        }

        Ok(Self { code, body: Zeroizing::new(body) })
    }

    /// Returns the unrecognized type code
    pub fn code(&self) -> u8 {
        self.code
    }

    /// Exposes the unknown plaintext body
    pub fn expose_body(&self) -> &[u8] {
        &self.body
    }
}

impl fmt::Debug for UnknownPayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UnknownPayload")
            .field("code", &format_args!("0x{:02x}", self.code))
            .field("body_len", &self.body.len())
            .finish_non_exhaustive()
    }
}

#[derive(Deserialize, Serialize)]
struct WireNotesRecord {
    title: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    user: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    password: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    site: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    misc: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    group: Option<String>,
}

impl Drop for WireNotesRecord {
    fn drop(&mut self) {
        self.title.zeroize();
        self.user.zeroize();
        self.password.zeroize();
        self.site.zeroize();
        self.misc.zeroize();
        self.group.zeroize();
    }
}

#[derive(Deserialize)]
struct WireVaultPayload(String, String, String, String);

impl Drop for WireVaultPayload {
    fn drop(&mut self) {
        self.0.zeroize();
        self.1.zeroize();
        self.2.zeroize();
        self.3.zeroize();
    }
}

fn encode_stash_payload(secret: &VaultSecret) -> Result<Zeroizing<Vec<u8>>> {
    let body = encode_stash_body(secret)?;
    let mut encoded = Zeroizing::new(Vec::with_capacity(1 + body.len()));
    encoded.push(PAYLOAD_CODE_STASH);
    encoded.extend_from_slice(&body);

    Ok(encoded)
}

fn encode_stash_body(secret: &VaultSecret) -> Result<Zeroizing<Vec<u8>>> {
    let mut encoded = Zeroizing::new(Vec::with_capacity(STASH_LEN));

    match secret {
        VaultSecret::Mnemonic(mnemonic) => {
            let entropy = Zeroizing::new(mnemonic_entropy(mnemonic)?);
            if !matches!(entropy.len(), 16 | 24 | 32) {
                return Err(Error::UnsupportedMnemonicWordCount(mnemonic.word_count()));
            }

            let marker = STASH_MARKER_MNEMONIC_FLAG | ((entropy.len() / 8) - 2) as u8;
            encoded.push(marker);
            encoded.extend_from_slice(&entropy);
        }
        VaultSecret::Xprv(xprv) => {
            let private_key = Zeroizing::new(xprv.private_key.secret_bytes());
            encoded.push(STASH_MARKER_XPRV);
            encoded.extend_from_slice(xprv.chain_code.as_bytes());
            encoded.extend_from_slice(private_key.as_ref());
        }
        VaultSecret::MasterSecret(secret) => {
            encoded.push(secret.expose_bytes().len() as u8);
            encoded.extend_from_slice(secret.expose_bytes());
        }
    }

    trim_stash_padding(&mut encoded);
    Ok(encoded)
}

fn encode_full_xprv_payload(xprv: &XprvPayload) -> Result<Zeroizing<Vec<u8>>> {
    let network = xprv.network.ok_or(Error::MissingXprvNetwork)?;
    let xprv = xprv.to_xpriv(network);
    let encoded_xprv = Zeroizing::new(xprv.encode());
    let mut encoded = Zeroizing::new(Vec::with_capacity(1 + encoded_xprv.len()));
    encoded.push(PAYLOAD_CODE_XPRV);
    encoded.extend_from_slice(encoded_xprv.as_ref());

    Ok(encoded)
}

fn encode_notes_payload(notes: &NotesPayload) -> Result<Zeroizing<Vec<u8>>> {
    let records = notes.records().iter().map(WireNotesRecord::from).collect::<Vec<_>>();
    let json =
        Zeroizing::new(serde_json::to_vec(&records).map_err(|_| Error::InvalidNotesPayload)?);
    let mut encoded = Zeroizing::new(Vec::with_capacity(1 + json.len()));
    encoded.push(PAYLOAD_CODE_NOTES);
    encoded.extend_from_slice(&json);

    Ok(encoded)
}

fn encode_vault_payload(vault: &VaultPayload) -> Result<Zeroizing<Vec<u8>>> {
    let secret = encode_stash_body(&vault.secret)?;
    let encoded_secret = Zeroizing::new(HEXLOWER.encode(&secret));
    let wire = (
        vault.fingerprint.as_str(),
        encoded_secret.as_str(),
        vault.label.as_str(),
        vault.origin.as_str(),
    );
    let json = Zeroizing::new(serde_json::to_vec(&wire).map_err(|_| Error::InvalidVaultPayload)?);
    let mut encoded = Zeroizing::new(Vec::with_capacity(1 + json.len()));
    encoded.push(PAYLOAD_CODE_VAULT);
    encoded.extend_from_slice(&json);

    Ok(encoded)
}

fn encode_raw_payload(code: u8, body: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut encoded = Zeroizing::new(Vec::with_capacity(1 + body.len()));
    encoded.push(code);
    encoded.extend_from_slice(body);
    encoded
}

fn decode_stash_body(body: &[u8]) -> Result<VaultSecret> {
    if body.is_empty() || body.len() > STASH_LEN {
        return Err(Error::InvalidStashPayload);
    }

    let mut stash = Zeroizing::new([0_u8; STASH_LEN]);
    stash[..body.len()].copy_from_slice(body);
    let marker = stash[0];
    let rest = &stash[1..];

    if marker == STASH_MARKER_XPRV {
        return decode_stash_xprv(rest).map(VaultSecret::Xprv);
    }

    if STASH_RAW_MASTER_SECRET_LEN.contains(&marker) {
        let secret = MasterSecret::new(rest[..usize::from(marker)].to_vec())?;
        return Ok(VaultSecret::MasterSecret(secret));
    }

    if marker & STASH_MARKER_MNEMONIC_FLAG == 0 {
        return Err(Error::InvalidStashPayload);
    }

    let entropy_len = usize::from((marker & STASH_MNEMONIC_ENTROPY_UNITS_MASK) + 2) * 8;
    if !matches!(entropy_len, 16 | 24 | 32) || rest.len() < entropy_len {
        return Err(Error::InvalidStashPayload);
    }

    let mnemonic = Mnemonic::from_entropy(&rest[..entropy_len])?;
    Ok(VaultSecret::Mnemonic(mnemonic))
}

fn decode_stash_xprv(body: &[u8]) -> Result<XprvPayload> {
    if body.len() != STASH_LEN - 1 {
        return Err(Error::InvalidXprvPayload);
    }

    let chain_code =
        ChainCode::from(<[u8; 32]>::try_from(&body[..32]).expect("chain code is 32 bytes"));
    let private_key =
        SecretKey::from_slice(&body[32..64]).map_err(|_| Error::InvalidXprvPayload)?;

    Ok(XprvPayload::from_stash(chain_code, private_key))
}

fn decode_full_xprv_body(body: &[u8]) -> Result<XprvPayload> {
    let xprv = Xpriv::decode(body).map_err(|_| Error::InvalidXprvPayload)?;
    validate_master_xprv(&xprv)?;

    Ok(XprvPayload::from_xpriv(xprv))
}

fn decode_notes_body(body: &[u8]) -> Result<NotesPayload> {
    let mut records: Vec<WireNotesRecord> =
        serde_json::from_slice(body).map_err(|_| Error::InvalidNotesPayload)?;
    let records = records.iter_mut().map(NotesRecord::try_from).collect::<Result<Vec<_>>>()?;

    NotesPayload::new(records)
}

fn decode_vault_body(body: &[u8]) -> Result<VaultPayload> {
    let mut wire: WireVaultPayload =
        serde_json::from_slice(body).map_err(|_| Error::InvalidVaultPayload)?;
    let secret_bytes = decode_hex_secret(&wire.1)?;
    let secret = decode_stash_body(&secret_bytes)?;

    VaultPayload::new(
        std::mem::take(&mut wire.0),
        secret,
        std::mem::take(&mut wire.2),
        std::mem::take(&mut wire.3),
    )
}

fn decode_hex_secret(value: &str) -> Result<Zeroizing<Vec<u8>>> {
    let mut normalized = Zeroizing::new(value.to_string());
    normalized.make_ascii_lowercase();
    if !normalized.len().is_multiple_of(2) {
        normalized.push('0');
    }

    HEXLOWER
        .decode(normalized.as_bytes())
        .map(Zeroizing::new)
        .map_err(|_| Error::InvalidVaultPayload)
}

fn normalize_fingerprint(value: &str) -> Result<String> {
    if value.len() != 8 || !value.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(Error::InvalidVaultPayload);
    }

    let normalized = value.to_ascii_uppercase();
    Fingerprint::from_str(&normalized).map_err(|_| Error::InvalidVaultPayload)?;
    Ok(normalized)
}

fn validate_master_xprv(xprv: &Xpriv) -> Result<()> {
    if xprv.depth != 0
        || xprv.parent_fingerprint != Fingerprint::default()
        || xprv.child_number != (ChildNumber::Normal { index: 0 })
    {
        return Err(Error::NonMasterXprvPayload);
    }

    Ok(())
}

fn trim_stash_padding(encoded: &mut Vec<u8>) {
    while encoded.last() == Some(&0) {
        encoded.pop();
    }
}

fn mnemonic_entropy(mnemonic: &Mnemonic) -> Result<Vec<u8>> {
    validate_mnemonic(mnemonic)?;

    let entropy_len = mnemonic.word_count() / 3 * 4;
    let mut entropy = vec![0_u8; entropy_len];

    for (word_position, word_index) in mnemonic.word_indices().enumerate() {
        for word_bit in 0..11 {
            let entropy_bit = word_position * 11 + word_bit;
            if entropy_bit >= entropy_len * 8 {
                return Ok(entropy);
            }
            if word_index & (1 << (10 - word_bit)) != 0 {
                entropy[entropy_bit / 8] |= 1 << (7 - entropy_bit % 8);
            }
        }
    }

    Ok(entropy)
}

fn validate_mnemonic(mnemonic: &Mnemonic) -> Result<()> {
    if mnemonic.language() != Language::English {
        return Err(Error::UnsupportedMnemonicLanguage);
    }

    let word_count = mnemonic.word_count();
    if !matches!(word_count, 12 | 18 | 24) {
        return Err(Error::UnsupportedMnemonicWordCount(word_count));
    }

    Ok(())
}

impl From<&NotesRecord> for WireNotesRecord {
    fn from(value: &NotesRecord) -> Self {
        match value {
            NotesRecord::Note(note) => Self {
                title: note.title.clone(),
                user: None,
                password: None,
                site: None,
                misc: nonempty(&note.text),
                group: nonempty(&note.group),
            },
            NotesRecord::Password(password) => Self {
                title: password.title.clone(),
                user: Some(password.username.clone()),
                password: nonempty(&password.password),
                site: nonempty(&password.site),
                misc: nonempty(&password.notes),
                group: nonempty(&password.group),
            },
        }
    }
}

impl TryFrom<&mut WireNotesRecord> for NotesRecord {
    type Error = Error;

    fn try_from(record: &mut WireNotesRecord) -> Result<Self> {
        if record.title.is_empty() {
            return Err(Error::InvalidNotesPayload);
        }

        let group = record.group.take().unwrap_or_default();
        if let Some(username) = record.user.take() {
            return PasswordRecord::new(
                std::mem::take(&mut record.title),
                username,
                record.password.take().unwrap_or_default(),
                record.site.take().unwrap_or_default(),
                record.misc.take().unwrap_or_default(),
                group,
            )
            .map(Self::Password);
        }

        if record.password.is_some() || record.site.is_some() {
            return Err(Error::InvalidNotesPayload);
        }

        NoteRecord::new(
            std::mem::take(&mut record.title),
            record.misc.take().unwrap_or_default(),
            group,
        )
        .map(Self::Note)
    }
}

fn nonempty(value: &str) -> Option<String> {
    (!value.is_empty()).then(|| value.to_string())
}
