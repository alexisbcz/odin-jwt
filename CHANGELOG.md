# Changelog

This file records all notable changes to this project.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-10-29

### Added

- `encode` and `encode_claims` sign compact JWS tokens with HS256, HS384, HS512 and EdDSA.
- `decode` verifies the signature, then parses the token and validates its claims.
- `decode_unverified` reads a token without a key, for example to pick a key by `kid`.
- `verify_signature` checks a compact JWS whose payload doesn't have to be JSON.
- `validate_claims` checks `exp`, `nbf` and `iat` with leeway, and `iss`, `sub` and `aud` against expected values.
- `claim`, `claim_string`, `claim_int` and `claim_bool` read private claims.
- `base64url_encode` and `base64url_decode` implement canonical unpadded base64url.
- `Format_Error`, `Signature_Error` and `Claim_Error`, joined in the `Error` union.

### Security

- Decoding rejects `alg: "none"` in every letter case, and encoding can't produce it.
- The key type fixes the algorithm family, which prevents algorithm confusion.
- HMAC verification compares tags in constant time and refuses keys shorter than the hash output.
- Strict input checks: canonical base64url, strict JSON without duplicate members, `i64` integers, limited nesting, a 64 KiB default size limit and no `crit` headers.

[Unreleased]: https://github.com/alexisbcz/odin-jwt/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/alexisbcz/odin-jwt/releases/tag/v0.1.0
