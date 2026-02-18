# Changelog

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog, and this project adheres to Semantic Versioning.

## [0.1.3] - 2026-02-18

### Added

- App-state sync implementation (snapshot + patch processing, key request flow, and in-memory model application)
- Group Sender Keys (`skmsg`) support for group E2E decrypt/encrypt
- Expanded media support (video, stickers) plus media metadata helpers
- End-to-end smoke runner (`tools/e2e_smoke.sh`) that exercises real CLI flows and media round-trips

### Changed

- App-state sync retry now includes per-collection fallback on MAC mismatch with warning events

## [0.1.2] - 2026-02-17

### Added

- Best-effort contact/profile metadata (names from History Sync + `notify`, profile picture URL fetch, "about"/status fetch)
- Simple CLI enhancements (resolved names on receive; commands: `name`, `ppic`, `status`)

## [0.1.1] - 2026-02-16

### Added

- Chatstate support (typing/recording indications)

### Fixed

- Release workflow version check (tag vs `pyproject.toml` + `__init__.__version__`)

## [0.1.0] - 2026-02-16

### Added

- Initial open source release
- WhatsApp Web MD connect + QR pairing, Baileys-like auth persistence
- Basic 1:1 Signal E2E decrypt/encrypt (`pkmsg`/`msg`)
- Basic text + media send (image, PTT voice note, documents, static location, contacts)
- Media download/decrypt helpers (image, audio/PTT, documents)
- History Sync ingestion demo store
- CI (pytest + ruff + mypy) and PyPI release workflow (Trusted Publishing)
