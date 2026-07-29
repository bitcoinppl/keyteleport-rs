use std::{fmt, str::FromStr};

use bitcoin::{
    NetworkKind,
    bip32::{ChildNumber, Fingerprint, Xpriv},
};
use zeroize::Zeroize;

use crate::{Error, Result};

/// A validated master extended private key transferred by KeyTeleport
#[derive(Clone, PartialEq, Eq)]
pub struct XprvPayload {
    value: String,
}

impl XprvPayload {
    /// Parses and validates a master extended private key
    ///
    /// # Errors
    ///
    /// Returns an error when the value is invalid, is not a mainnet key, or represents a derived
    /// child key
    pub fn parse(value: &str) -> Result<Self> {
        let xprv = Xpriv::from_str(value).map_err(|_| Error::InvalidXprvPayload)?;
        Self::try_from_xpriv(xprv)
    }

    pub(super) fn try_from_xpriv(xprv: Xpriv) -> Result<Self> {
        if xprv.network != NetworkKind::Main {
            return Err(Error::NonMainnetXprvPayload);
        }

        if !is_master(&xprv) {
            return Err(Error::NonMasterXprvPayload);
        }

        Ok(Self { value: xprv.to_string() })
    }

    /// Exposes the encoded extended private key
    pub fn expose_string(&self) -> &str {
        &self.value
    }
}

impl fmt::Debug for XprvPayload {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("XprvPayload(****)")
    }
}

impl Drop for XprvPayload {
    fn drop(&mut self) {
        self.value.zeroize();
    }
}

pub(super) fn decode_body(body: &[u8]) -> Result<XprvPayload> {
    let xprv = Xpriv::decode(body).map_err(|_| Error::InvalidXprvPayload)?;

    XprvPayload::try_from_xpriv(xprv)
}

fn is_master(xprv: &Xpriv) -> bool {
    xprv.depth == 0
        && xprv.parent_fingerprint == Fingerprint::default()
        && xprv.child_number == ChildNumber::Normal { index: 0 }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use bitcoin::{
        NetworkKind,
        bip32::{ChildNumber, Xpriv},
    };
    use zeroize::Zeroizing;

    use crate::{
        Error,
        payload::{DecodedPayload, PAYLOAD_CODE_XPRV},
    };

    const XPRV: &str = "xprv9s21ZrQH143K4BwRCYKSEPwcAMYweWkfKLURabnnv2GLNhJN1LSCgDQyGWyNcat72najQKwyshCBXWfHHVbcdxPAZPqByMyWDbWp5SjCfEa";

    #[test]
    fn full_xprv_payload_rejects_child_keys() {
        let master = Xpriv::from_str(XPRV).unwrap();
        let secp = bitcoin::secp256k1::Secp256k1::new();
        let child = master.derive_priv(&secp, &[ChildNumber::Hardened { index: 7 }]).unwrap();
        let mut payload = vec![PAYLOAD_CODE_XPRV];
        payload.extend_from_slice(&child.encode());

        assert!(matches!(DecodedPayload::decode(&payload), Err(Error::NonMasterXprvPayload)));
    }

    #[test]
    fn full_xprv_payload_rejects_non_mainnet_keys() {
        let testnet = Xpriv::new_master(NetworkKind::Test, &[42; 32]).unwrap();
        let mut payload = Zeroizing::new(vec![PAYLOAD_CODE_XPRV]);
        payload.extend_from_slice(&testnet.encode());

        assert!(matches!(DecodedPayload::decode(&payload), Err(Error::NonMainnetXprvPayload)));
    }
}
