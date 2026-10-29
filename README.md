# jwt

[![CI](https://github.com/alexisbcz/odin-jwt/actions/workflows/ci.yml/badge.svg)](https://github.com/alexisbcz/odin-jwt/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Odin](https://img.shields.io/badge/Odin-dev--2026--09-1e5a99.svg)](https://odin-lang.org)

JSON Web Tokens for Odin: sign, verify and validate HS256, HS384, HS512 and EdDSA tokens with strict defaults and no dependencies outside `core`.

## Install

The repository root is the package, so you can vendor it in two ways.

As a Git submodule inside your project:

```sh
git submodule add https://github.com/alexisbcz/odin-jwt libs/jwt
```

```odin
import "libs/jwt"
```

As a copy in a shared collection that all your projects use:

```sh
git clone https://github.com/alexisbcz/odin-jwt ~/odin-shared/jwt
odin build . -collection:shared=$HOME/odin-shared
```

```odin
import "shared:jwt"
```

Odin names an import after its directory. If you keep the directory name `odin-jwt`, give the import a name: `import jwt "libs/odin-jwt"`.

## Quick start

```odin
package main

import "core:fmt"
import "core:time"
import "shared:jwt"

main :: proc() {
	key := jwt.Hmac_Key(transmute([]byte)string("replace-me-with-32-random-bytes!!"))
	now := time.to_unix_seconds(time.now())

	token, err := jwt.encode_claims({iss = "auth", sub = "alice", exp = now + 900}, .HS256, key)
	if err != nil {
		fmt.eprintln("encode failed:", err)
		return
	}
	defer delete(token)

	decoded, derr := jwt.decode(token, key, {issuer = "auth", leeway = 30})
	if derr != nil {
		fmt.eprintln("rejected:", derr) // For example Expired or Invalid_Signature.
		return
	}
	defer jwt.token_destroy(&decoded)
	fmt.println("hello,", decoded.claims.sub)
}
```

### Private claims

`encode` signs any JSON object, so marshal your own struct and read the extra members back with `claim_string`, `claim_int` and `claim_bool`:

```odin
Session :: struct {
	sub:  string,
	exp:  i64,
	role: string,
}

issue_and_read :: proc(key: jwt.Hmac_Key, now: i64) -> (role: string, ok: bool) {
	payload, merr := json.marshal(Session{sub = "alice", exp = now + 900, role = "editor"})
	if merr != nil {
		return "", false
	}
	defer delete(payload)

	token, err := jwt.encode(payload, .HS256, key)
	if err != nil {
		return "", false
	}
	defer delete(token)

	decoded, derr := jwt.decode(token, key, {now = now})
	if derr != nil {
		return "", false
	}
	defer jwt.token_destroy(&decoded)

	r := jwt.claim_string(&decoded, "role") or_return
	return strings.clone(r), true
}
```

### EdDSA

Sign with an `^ed25519.Private_Key` and verify with the matching `^ed25519.Public_Key`. See [`examples/eddsa`](examples/eddsa/main.odin) for the full program.

```odin
token, err := jwt.encode_claims({sub = "device-42", exp = now + 3600}, .EdDSA, &priv, kid = "2026-10")
decoded, derr := jwt.decode(token, &pub)
```

## API overview

| Declaration | Purpose | Allocates | Free with |
| --- | --- | --- | --- |
| `encode(payload, alg, key, kid, allocator)` | Sign a JSON object payload | Yes | `delete` |
| `encode_claims(claims, alg, key, kid, allocator)` | Serialize registered claims and sign them | Yes | `delete` |
| `decode(token, key, validation, allocator)` | Verify the signature, parse and validate claims | Yes | `token_destroy` |
| `decode_unverified(token, max_size, allocator)` | Parse without verifying, for example to read `kid` | Yes | `token_destroy` |
| `verify_signature(token, key, algorithms, max_size, allocator)` | Check only the signature of a compact JWS | Scratch only | Not needed |
| `validate_claims(claims, validation)` | Check `exp`, `nbf`, `iat`, `iss`, `sub` and `aud` | No | Not needed |
| `claim`, `claim_string`, `claim_int`, `claim_bool` | Read private claims from a `Token` | No | Not needed |
| `base64url_encode`, `base64url_decode` | Unpadded, canonical base64url | Yes | `delete` |
| `algorithm_name`, `algorithm_from_name`, `key_algorithms` | Map between algorithms, names and keys | No | Not needed |
| `Validation` | Clock, leeway, expected issuer, subject and audience, allowed algorithms | No | Not needed |
| `Error` | Union of `Format_Error`, `Signature_Error`, `Claim_Error` and `runtime.Allocator_Error` | No | Not needed |

### Keys

| Key | Signs | Verifies |
| --- | --- | --- |
| `Hmac_Key` of at least 32, 48 or 64 bytes | HS256, HS384, HS512 | HS256, HS384, HS512 |
| `^ed25519.Private_Key` | EdDSA | EdDSA |
| `^ed25519.Public_Key` | No | EdDSA |

### Validation defaults

The zero `Validation{}` is the strict choice:

- `exp` must be present and in the future. Set `allow_missing_exp` to accept tokens without it.
- Time comes from the system clock. Set `now` to pin it, for example in tests.
- Leeway is zero. Set `leeway` in seconds to allow for clock skew.
- Decoding rejects a token that carries `aud` unless `audience` names one of its values, as RFC 7519 requires.
- The key allows every algorithm of its family. Set `algorithms` to narrow the set.
- Decoding refuses tokens larger than `DEFAULT_MAX_TOKEN_SIZE` (64 KiB) before any parsing.

## Examples

Each directory under `examples/` is a runnable program:

```sh
odin run examples/basic
odin run examples/eddsa
```

## Design notes

- `alg: "none"` has no `Algorithm` value, so the package can't produce or accept unsecured tokens. Decoding rejects it in any letter case.
- The key type picks the algorithm family. An HMAC secret never verifies an EdDSA token and the reverse, which rules out algorithm confusion attacks.
- HMAC verification compares tags in constant time. `decode` checks the signature before it parses the payload, so unauthenticated payloads never reach the JSON parser.
- Headers and payloads must be strict RFC 8259 JSON with no duplicate members, integers within the `i64` range and at most `MAX_JSON_DEPTH` levels of nesting. Base64url must be canonical.
- Decoding rejects headers with `crit`, because the package implements no JWS extensions.
- Decoding rounds fractional NumericDate values down to whole seconds.
- Every allocating procedure takes `allocator := context.allocator` and says who owns the result. A failed `decode` returns a zero `Token` that owns nothing.
- The package keeps no global mutable state. Keys are only read, so one key can verify tokens on several threads at once.
- RSA and ECDSA algorithms and JWE encryption aren't supported yet.

## Testing

```sh
odin check . -vet -strict-style -disallow-do -no-entry-point
odin test tests -vet -strict-style -disallow-do
vale sync && vale *.md
```

The tests include the vectors from RFC 7515 appendices A.1 and A.5 and RFC 8037 appendix A.4, and run under a tracking allocator that fails on any leak.

## Contributing

Read [CONTRIBUTING.md](CONTRIBUTING.md). Commits follow Conventional Commits, and every change that users can see gets a line in [CHANGELOG.md](CHANGELOG.md).

## License

MIT. See [LICENSE](LICENSE).
