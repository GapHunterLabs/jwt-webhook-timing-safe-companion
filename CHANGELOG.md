<!-- Keep a Changelog guide -> https://keepachangelog.com -->

# JWT Webhook Signature Timing-Safe Comparison Companion Changelog

## [Unreleased]

## [0.1.0]

### Added

- Warning on a webhook/HMAC signature comparison using `.equals()`/
  `Arrays.equals()` instead of `MessageDigest.isEqual(...)` --
  CWE-208, Observable Timing Discrepancy.
- Detection scoped to methods that themselves compute an HMAC,
  recognizing signature-related identifiers by naming convention.

[Unreleased]: https://github.com/GapHunterLabs/jwt-webhook-timing-safe-companion/compare/0.1.0...HEAD
[0.1.0]: https://github.com/GapHunterLabs/jwt-webhook-timing-safe-companion/commits/0.1.0
