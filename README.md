WIP DO NOT USE

# keyteleport

`keyteleport` implements the parts of the [COLDCARD Key Teleport protocol](https://github.com/Coldcard/firmware/blob/master/docs/key-teleport.md)
that Cove uses.

## Support

| Protocol data | Send | Receive |
| --- | --- | --- |
| English BIP39 mnemonic | Yes | Yes |
| Mainnet master XPRV | Yes | Yes |
| Secure Notes & Passwords | No | Yes |
| Seed Vault entry | No | Recognized |
| Full COLDCARD backup | No | Recognized |
| Multisig PSBT | Packet framing only | Packet framing only |

The crate supports single-part, uncompressed Base32 BBQr packets and `keyteleport.com` URLs.

## Security

This crate implements a device interoperability protocol. It is not a general encryption API.
Send each transfer password through a different channel from its encrypted packet. Treat receiver
session keys, passwords, mnemonics, XPRVs, secure notes, and decrypted payloads as secrets.

## Not included

This version does not include multipart BBQr joining, lossless unknown payloads, Seed Vault or
backup codecs, Secure Notes encoding, or multisig PSBT encryption and decryption.
