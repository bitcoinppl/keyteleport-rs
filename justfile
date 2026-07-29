# Runtime tags describe warm, incremental runs on a development machine:
# - [quick]: normally finishes within one minute
# - [bounded]: normally finishes within five minutes
# - [long]: may take longer than five minutes
# Cold caches can move quick commands into bounded and bounded commands into long

# [quick] List available recipes
[default]
list:
    @just --list

# ------------------------------------------------------------------------------
# ci
# ------------------------------------------------------------------------------

# [bounded] Run all CI checks
[group('ci')]
[script('bash')]
ci:
    set -e
    just fmt
    cargo fmt --check
    just lint
    just test

# ------------------------------------------------------------------------------
# test
# ------------------------------------------------------------------------------

# [bounded] Run all tests
[group('test')]
test test="" flags="":
    cargo test {{ test }} {{ flags }}

# [bounded] Run tests the same way as GitHub Actions
[group('test')]
test-gh test="" flags="":
    cargo test {{ test }} {{ flags }}

# ------------------------------------------------------------------------------
# lint
# ------------------------------------------------------------------------------

# [quick] Lint Rust code
[group('lint')]
lint *flags="":
    cargo clippy --all-targets --all-features -- -D warnings {{ flags }}

alias clippy := lint

# ------------------------------------------------------------------------------
# format
# ------------------------------------------------------------------------------

# [quick] Format Rust code
[group('format')]
fmt:
    cargo fmt --all

# ------------------------------------------------------------------------------
# dev
# ------------------------------------------------------------------------------

# [bounded] Run cargo check
[group('dev')]
check *flags="--all-targets --all-features":
    cargo check {{ flags }}

# [bounded] Apply cargo fix
[group('dev')]
fix *flags="":
    cargo fix {{ flags }}
