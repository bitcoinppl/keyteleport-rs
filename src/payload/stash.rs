use std::str::FromStr;

use bip39::{Language, Mnemonic};
use bitcoin::{NetworkKind, bip32::Xpriv, secp256k1::SecretKey};
use zeroize::Zeroizing;

use crate::{Error, Result};

use super::{PAYLOAD_CODE_STASH, XprvPayload};

const MAINNET_XPRV_VERSION: [u8; 4] = [0x04, 0x88, 0xad, 0xe4];

// COLDCARD 72-byte stash layout uses the first body byte as a marker
//
// - 0x01: master xprv as chain_code || private_key
// - 0x10..=0x40: raw BIP32 master secret; marker is the secret length in bytes
// - high bit set: BIP39 entropy; low bits encode length as ((marker & 0x03) + 2) * 8
const STASH_LEN: usize = 72;
const STASH_MARKER_XPRV: u8 = 0x01;
const STASH_MARKER_MNEMONIC_FLAG: u8 = 0x80;
const STASH_MNEMONIC_ENTROPY_UNITS_MASK: u8 = 0x03;
const STASH_RAW_MASTER_SECRET_LEN: std::ops::RangeInclusive<u8> = 0x10..=0x40;

pub(super) enum DecodedStash {
    Mnemonic(Mnemonic),
    Xprv(XprvPayload),
}

pub(super) fn encode_mnemonic(mnemonic: &Mnemonic) -> Result<Zeroizing<Vec<u8>>> {
    let entropy = Zeroizing::new(mnemonic_entropy(mnemonic)?);
    if !matches!(entropy.len(), 16 | 24 | 32) {
        return Err(Error::UnsupportedMnemonicWordCount(mnemonic.word_count()));
    }

    let marker = STASH_MARKER_MNEMONIC_FLAG | ((entropy.len() / 8) - 2) as u8;
    let mut encoded = Zeroizing::new(Vec::with_capacity(1 + 1 + entropy.len()));
    encoded.push(PAYLOAD_CODE_STASH);
    encoded.push(marker);
    encoded.extend_from_slice(&entropy);
    trim_padding(&mut encoded);

    Ok(encoded)
}

pub(super) fn encode_xprv(xprv: &XprvPayload) -> Result<Zeroizing<Vec<u8>>> {
    let xprv = Xpriv::from_str(xprv.expose_string()).map_err(|_| Error::InvalidXprvPayload)?;
    let private_key = Zeroizing::new(xprv.private_key.secret_bytes());

    let mut encoded = Zeroizing::new(Vec::with_capacity(66));
    encoded.push(PAYLOAD_CODE_STASH);
    encoded.push(STASH_MARKER_XPRV);
    encoded.extend_from_slice(xprv.chain_code.as_bytes());
    encoded.extend_from_slice(private_key.as_ref());
    trim_padding(&mut encoded);

    Ok(encoded)
}

pub(super) fn decode(body: &[u8]) -> Result<DecodedStash> {
    if body.is_empty() || body.len() > STASH_LEN {
        return Err(Error::InvalidMnemonicPayload);
    }

    // COLDCARD strips trailing zeroes from its 72-byte stash before transport
    let mut stash = Zeroizing::new([0_u8; STASH_LEN]);
    stash[..body.len()].copy_from_slice(body);
    let marker = stash[0];
    let rest = &stash[1..];

    if marker == STASH_MARKER_XPRV {
        return decode_xprv(rest).map(DecodedStash::Xprv);
    }

    // COLDCARD raw BIP32 master secret: marker is the byte length (16-64),
    // body is the raw seed, and the wallet key is the BIP32 master derived
    // from it (HMAC-SHA512 "Bitcoin seed"), matching COLDCARD's hd.from_master
    if STASH_RAW_MASTER_SECRET_LEN.contains(&marker) {
        let xprv = Xpriv::new_master(NetworkKind::Main, &rest[..usize::from(marker)])
            .map_err(|_| Error::InvalidXprvPayload)?;
        return Ok(DecodedStash::Xprv(XprvPayload::try_from_xpriv(xprv)?));
    }

    if marker & STASH_MARKER_MNEMONIC_FLAG == 0 {
        return Err(Error::InvalidMnemonicPayload);
    }

    let entropy_len = usize::from((marker & STASH_MNEMONIC_ENTROPY_UNITS_MASK) + 2) * 8;
    if !matches!(entropy_len, 16 | 24 | 32) || rest.len() < entropy_len {
        return Err(Error::InvalidMnemonicPayload);
    }

    Ok(DecodedStash::Mnemonic(Mnemonic::from_entropy(&rest[..entropy_len])?))
}

fn mnemonic_entropy(mnemonic: &Mnemonic) -> Result<Vec<u8>> {
    if mnemonic.language() != Language::English {
        return Err(Error::UnsupportedMnemonicLanguage);
    }

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

fn decode_xprv(body: &[u8]) -> Result<XprvPayload> {
    if body.len() != 71 {
        return Err(Error::InvalidXprvPayload);
    }

    let chain_code = &body[..32];
    let private_key = &body[32..64];
    SecretKey::from_slice(private_key).map_err(|_| Error::InvalidXprvPayload)?;

    let mut encoded = Zeroizing::new([0_u8; 78]);
    encoded[0..4].copy_from_slice(&MAINNET_XPRV_VERSION);
    encoded[13..45].copy_from_slice(chain_code);
    encoded[45] = 0;
    encoded[46..78].copy_from_slice(private_key);
    let xprv = Xpriv::decode(&encoded[..])?;

    XprvPayload::try_from_xpriv(xprv)
}

fn trim_padding(encoded: &mut Vec<u8>) {
    while encoded.last() == Some(&0) {
        encoded.pop();
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use bip39::Mnemonic;
    use bitcoin::{NetworkKind, bip32::Xpriv, secp256k1::SecretKey};

    use crate::payload::{DecodedPayload, Payload};

    use super::{PAYLOAD_CODE_STASH, STASH_MARKER_MNEMONIC_FLAG, STASH_MARKER_XPRV, trim_padding};

    const XPRV: &str = "xprv9s21ZrQH143K4BwRCYKSEPwcAMYweWkfKLURabnnv2GLNhJN1LSCgDQyGWyNcat72najQKwyshCBXWfHHVbcdxPAZPqByMyWDbWp5SjCfEa";

    #[test]
    fn mnemonic_stash_roundtrips_coldcard_trailing_zero_trimming() {
        let mnemonic = Mnemonic::from_entropy(&[0_u8; 16]).unwrap();
        let encoded = Payload::mnemonic(mnemonic.clone()).unwrap().encode().unwrap();

        assert_eq!(encoded.as_slice(), &[PAYLOAD_CODE_STASH, STASH_MARKER_MNEMONIC_FLAG]);
        assert_eq!(DecodedPayload::decode(&encoded).unwrap(), DecodedPayload::Mnemonic(mnemonic));
    }

    #[test]
    fn xprv_encoder_uses_coldcard_stash_layout() {
        let xprv = Xpriv::from_str(XPRV).unwrap();
        let encoded = Payload::xprv(XPRV).unwrap().encode().unwrap();

        assert_eq!(&encoded[..2], &[PAYLOAD_CODE_STASH, STASH_MARKER_XPRV]);
        assert_eq!(&encoded[2..34], xprv.chain_code.as_bytes());
        assert_eq!(&encoded[34..66], &xprv.private_key.secret_bytes());
    }

    #[test]
    fn xprv_stash_decodes_after_coldcard_trims_private_key_zero() {
        let chain_code = [2_u8; 32];
        let mut private_key = [1_u8; 32];
        private_key[31] = 0;
        SecretKey::from_slice(&private_key).unwrap();
        let mut encoded = vec![PAYLOAD_CODE_STASH, STASH_MARKER_XPRV];
        encoded.extend_from_slice(&chain_code);
        encoded.extend_from_slice(&private_key);
        trim_padding(&mut encoded);

        let DecodedPayload::Xprv(decoded) = DecodedPayload::decode(&encoded).unwrap() else {
            panic!("expected xprv")
        };
        let decoded = Xpriv::from_str(decoded.expose_string()).unwrap();

        assert_eq!(decoded.chain_code.as_bytes(), &chain_code);
        assert_eq!(decoded.private_key.secret_bytes(), private_key);
    }

    #[test]
    fn raw_master_secret_stash_decodes_as_bip32_master() {
        for seed_len in [16_usize, 32, 64] {
            let seed = vec![7_u8; seed_len];
            let mut encoded = vec![PAYLOAD_CODE_STASH, seed_len as u8];
            encoded.extend_from_slice(&seed);

            let DecodedPayload::Xprv(decoded) = DecodedPayload::decode(&encoded).unwrap() else {
                panic!("expected xprv for seed length {seed_len}")
            };
            let expected = Xpriv::new_master(NetworkKind::Main, &seed).unwrap();

            assert_eq!(decoded.expose_string(), expected.to_string());
        }
    }

    #[test]
    fn raw_master_secret_stash_restores_trimmed_trailing_zeros() {
        let mut seed = [9_u8; 24];
        seed[20..].fill(0);
        let mut encoded = vec![PAYLOAD_CODE_STASH, 24];
        encoded.extend_from_slice(&seed);
        trim_padding(&mut encoded);
        assert!(encoded.len() < 26);

        let DecodedPayload::Xprv(decoded) = DecodedPayload::decode(&encoded).unwrap() else {
            panic!("expected xprv")
        };
        let expected = Xpriv::new_master(NetworkKind::Main, &seed).unwrap();

        assert_eq!(decoded.expose_string(), expected.to_string());
    }

    #[test]
    fn raw_master_secret_stash_rejects_out_of_range_lengths() {
        for marker in [0x02_u8, 0x0f, 0x41, 0x7f] {
            let mut encoded = vec![PAYLOAD_CODE_STASH, marker];
            encoded.extend_from_slice(&[3_u8; 70]);

            assert!(
                matches!(
                    DecodedPayload::decode(&encoded),
                    Err(crate::Error::InvalidMnemonicPayload)
                ),
                "marker 0x{marker:02x} should be rejected"
            );
        }
    }
}
