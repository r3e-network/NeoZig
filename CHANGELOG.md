# Changelog

## Unreleased

- (none)

## 1.0.1 - 2025-12-14

- Fix Neo N3 network magic constants to match `getversion` (`NEO3` / `N3T5`).
- Make `getversion` parsing accept real node payloads where `wsport` may be omitted.
- Add `TransactionBroadcaster.deinit()` and fix `BroadcastUtils.localhost()` endpoint ownership.
- Add safer NeoZig ownership helpers (`initFromService`, `buildFromService`, pointer-based factory constructors) and make `cloneWithConfig` non-owning to avoid double-free.
- Tighten demos/examples around secret handling (WIF decode zeroization, proper `deinit` usage).
- Expand `.gitignore` to cover Zig caches and other generated directories.
- Add `docs/USAGE.md` and `docs/ARCHITECTURE.md`.
- Refresh README/SECURITY wording to avoid unverifiable performance/security claims.

## 1.0.0

- Initial public release.
