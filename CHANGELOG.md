# Changelog

## [Unreleased]

## [0.1.0] - 2026-07-29

### Added

- Initial public release of the COLDCARD Key Teleport protocol parts used by Cove
- Sender and receiver sessions for English BIP39 mnemonics (12, 18, or 24 words)
- Sender and receiver sessions for mainnet master XPRV payloads
- Receiver decoding for Secure Notes & Passwords payloads
- Recognition of Seed Vault and full COLDCARD backup payload kinds without codecs
- Multisig PSBT packet framing only (no encryption or decryption)
- Single-part, uncompressed Base32 BBQr packet encoding and decoding
- `keyteleport.com` URL encoding and decoding for transfers
- Typed domain models for numeric receiver codes, teleport passwords, packets,
  and decoded payloads
- Protocol integration tests covering send/receive round-trips
