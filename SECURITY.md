# Security

## Scope

`keyteleport` implements the COLDCARD Key Teleport wire protocol. It must not be used as a
general-purpose encryption system.

The protocol uses AES-256-CTR and short checksums. It also uses a short receiver code and a
five-byte transfer password. These values match the protocol. They do not provide the properties
of a modern authenticated-encryption API.

## Required application controls

- Exchange the encrypted packet and its code or password through different channels.
- Store receiver-session secrets only in protected secret storage.
- Delete all persisted copies of a receiver-session secret after transfer acceptance.
- Do not log secret values or decrypted payload bytes.
- Keep wallet import, backup restore, PSBT signing, and user approval in the application.
- Apply limits to scanned input and stored payload sizes that are suitable for the application.

The crate redacts its secret-bearing `Debug` implementations and zeroizes retained secret buffers
where the Rust types allow it. These controls do not protect copies made by callers, allocators,
operating systems, crash reports, or device backups.

## Report a vulnerability

Report vulnerabilities with a private
[GitHub security advisory](https://github.com/bitcoinppl/keyteleport-rs/security/advisories/new).
Do not include active secrets, wallet backups, or production PSBTs in a report.
