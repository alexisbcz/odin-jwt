/*
Package jwt encodes, decodes and verifies JSON Web Tokens (RFC 7519).

It supports the compact JWS serialization (RFC 7515) with these algorithms:

- HS256, HS384 and HS512: HMAC with SHA-2, keyed by an `Hmac_Key`.
- EdDSA: Ed25519 signatures (RFC 8037), keyed by `core:crypto/ed25519` keys.

The package is strict by default:

- `alg: "none"` is never accepted, in any letter case, and no `Algorithm`
  value represents it.
- The key decides which algorithms a token may use, which blocks algorithm
  confusion attacks. `Validation.algorithms` narrows the set further.
- Signatures are compared in constant time and checked before the payload is
  parsed.
- `decode` requires an `exp` claim unless `Validation.allow_missing_exp` is set,
  rejects unknown `crit` headers, duplicate JSON keys and non-canonical base64url.

Example:
	import "shared:jwt"

	main :: proc() {
		key := jwt.Hmac_Key(transmute([]byte)string("a-secret-of-at-least-32-bytes!!!"))

		token, err := jwt.encode_claims({sub = "alice", exp = 2000000000}, .HS256, key)
		if err != nil {
			return
		}
		defer delete(token)

		decoded, derr := jwt.decode(token, key, {now = 1700000000})
		if derr != nil {
			return
		}
		defer jwt.token_destroy(&decoded)
	}

Thread safety: keys are only read, so one key may verify tokens on several
threads at once. A `Token` is safe to use from one thread at a time.
*/
package jwt

import "base:runtime"
import "core:crypto/ed25519"
import "core:encoding/json"

// DEFAULT_MAX_TOKEN_SIZE is the largest token, in bytes, that decoding accepts when `Validation.max_token_size` is zero.
DEFAULT_MAX_TOKEN_SIZE :: 64 * 1024

/*
Algorithm is a JWS signature algorithm that this package implements.

There is deliberately no member for `none`: unsecured tokens can't be
expressed, encoded or decoded.
*/
Algorithm :: enum u8 {
	// Unknown is the zero value. No token or key ever uses it.
	Unknown,
	// HS256 is HMAC using SHA-256. It needs an `Hmac_Key` of at least 32 bytes.
	HS256,
	// HS384 is HMAC using SHA-384. It needs an `Hmac_Key` of at least 48 bytes.
	HS384,
	// HS512 is HMAC using SHA-512. It needs an `Hmac_Key` of at least 64 bytes.
	HS512,
	// EdDSA is Ed25519 as specified by RFC 8037.
	EdDSA,
}

// Algorithms is a set of algorithms, used to restrict what decoding accepts.
Algorithms :: bit_set[Algorithm]

// HMAC_ALGORITHMS holds every algorithm that an `Hmac_Key` can sign and verify.
HMAC_ALGORITHMS :: Algorithms{.HS256, .HS384, .HS512}

// ED25519_ALGORITHMS holds every algorithm that an Ed25519 key can sign and verify.
ED25519_ALGORITHMS :: Algorithms{.EdDSA}

/*
Hmac_Key is a shared secret for the HS256, HS384 and HS512 algorithms.

RFC 7518 section 3.2 requires a key at least as long as the hash output, so
encoding and decoding reject shorter keys with `.Key_Too_Short`. The package
only reads the bytes and never keeps them after a call returns.
*/
Hmac_Key :: distinct []byte

/*
Key is the key material for signing or verifying a token.

- `Hmac_Key` signs and verifies HS256, HS384 and HS512 tokens.
- `^ed25519.Private_Key` signs EdDSA tokens, and verifies them through its public half.
- `^ed25519.Public_Key` verifies EdDSA tokens. It can't sign.

The key type decides which algorithms a token may claim, so a token signed with
HMAC never verifies against an Ed25519 key and the reverse.
*/
Key :: union {
	Hmac_Key,
	^ed25519.Private_Key,
	^ed25519.Public_Key,
}

// Format_Error lists the ways a token or an input payload can be structurally malformed.
Format_Error :: enum {
	None,
	// The token is longer than the configured maximum size.
	Token_Too_Large,
	// The token doesn't have exactly three dot-separated segments.
	Wrong_Segment_Count,
	// A segment isn't canonical unpadded base64url.
	Invalid_Base64,
	// A segment, or a payload passed to encode, isn't valid JSON.
	Invalid_Json,
	// The JOSE header isn't a JSON object.
	Header_Not_Object,
	// The payload isn't a JSON object.
	Payload_Not_Object,
	// A header member such as `typ` or `kid` has the wrong JSON type.
	Invalid_Header,
	// The header lists critical extensions in `crit`, which this package doesn't support.
	Unsupported_Critical_Header,
	// A string passed to encode isn't valid UTF-8.
	Invalid_Utf8,
}

// Signature_Error lists the ways the algorithm, the key or the signature can be wrong.
Signature_Error :: enum {
	None,
	// The header has no `alg` member, or it isn't a string.
	Missing_Algorithm,
	// The header names the `none` algorithm, which is always rejected.
	Algorithm_None,
	// The header names an algorithm this package doesn't implement.
	Unsupported_Algorithm,
	// The algorithm isn't in `Validation.algorithms`.
	Algorithm_Not_Allowed,
	// The algorithm doesn't match the type of the key, for example HS256 with an Ed25519 key.
	Key_Algorithm_Mismatch,
	// The `Hmac_Key` is shorter than the hash output of the algorithm.
	Key_Too_Short,
	// The key is nil, or an Ed25519 key that was never initialized.
	Invalid_Key,
	// The key can't sign, for example an Ed25519 public key.
	Key_Cannot_Sign,
	// The signature doesn't match the header and payload.
	Invalid_Signature,
}

// Claim_Error lists the ways the registered claims can fail validation.
Claim_Error :: enum {
	None,
	// A registered claim has the wrong JSON type, for example a string `exp`.
	Invalid_Claim_Type,
	// A claim listed in `Validation.required`, or `exp` by default, is absent.
	Missing_Claim,
	// The current time is at or after `exp`, after allowing for leeway.
	Expired,
	// The current time is before `nbf`, after allowing for leeway.
	Not_Yet_Valid,
	// The `iat` claim lies in the future, after allowing for leeway.
	Issued_In_Future,
	// The `iss` claim is absent or differs from `Validation.issuer`.
	Invalid_Issuer,
	// The `aud` claim doesn't contain `Validation.audience`, or is present when no audience is expected.
	Invalid_Audience,
	// The `sub` claim is absent or differs from `Validation.subject`.
	Invalid_Subject,
	// `Validation.leeway` is negative.
	Invalid_Leeway,
}

/*
Error is the error type returned by every fallible procedure in this package.
`nil` means success. Use a type switch to find the failure domain, or compare
against a specific value such as `Claim_Error.Expired`.
*/
Error :: union #shared_nil {
	Format_Error,
	Signature_Error,
	Claim_Error,
	runtime.Allocator_Error,
}

/*
Header is the decoded JOSE header of a token.

The strings borrow from the `Token` they belong to and stay valid until
token_destroy. Empty strings mean the member was absent.
*/
Header :: struct {
	// alg is the signature algorithm. It's never `.Unknown` in a decoded token.
	alg: Algorithm,
	// typ is the media type of the whole token, usually "JWT".
	typ: string,
	// cty is the media type of the payload, set for nested tokens.
	cty: string,
	// kid is a hint that identifies the key that signed the token.
	kid: string,
}

/*
Claims holds the registered claims of RFC 7519 section 4.1.

When encoding, empty strings, an empty `aud` slice and nil times are left out.
When decoding, the strings borrow from the `Token` and `aud` is owned by it.
Times are NumericDate values: seconds since the Unix epoch, rounded down.
*/
Claims :: struct {
	// iss identifies the principal that issued the token.
	iss: string,
	// sub identifies the principal that the token is about.
	sub: string,
	// aud lists the recipients the token is intended for. One entry is encoded as a plain string.
	aud: []string,
	// exp is the expiration time. The token is invalid at or after it.
	exp: Maybe(i64),
	// nbf is the time before which the token is invalid.
	nbf: Maybe(i64),
	// iat is the time at which the token was issued.
	iat: Maybe(i64),
	// jti is a unique identifier for the token.
	jti: string,
}

/*
Token is a decoded token.

Create one with decode or decode_unverified and release it with token_destroy.
`header` and `claims` borrow strings from `payload` and `header_object`, so
don't use them after token_destroy.
*/
Token :: struct {
	// header holds the decoded JOSE header members.
	header:        Header,
	// claims holds the registered claims taken from the payload.
	claims:        Claims,
	// header_object is the whole JOSE header, including members not listed in `header`.
	header_object: json.Object,
	// payload is the whole claims set, including private claims.
	payload:       json.Object,
	// allocator owns every allocation of the token.
	allocator:     runtime.Allocator,
}

// token_destroy frees everything the token owns and zeroes it. Calling it on a zero `Token` is safe.
token_destroy :: proc(t: ^Token) {
	if t.allocator.procedure == nil {
		t^ = {}
		return
	}
	delete(t.claims.aud, t.allocator)
	json.destroy_value(t.header_object, t.allocator)
	json.destroy_value(t.payload, t.allocator)
	t^ = {}
}

/*
algorithm_name returns the JWA name of `alg`, such as "HS256".
It returns an empty string for `.Unknown` or an out-of-range value.
*/
algorithm_name :: proc(alg: Algorithm) -> string {
	switch alg {
	case .HS256:
		return "HS256"
	case .HS384:
		return "HS384"
	case .HS512:
		return "HS512"
	case .EdDSA:
		return "EdDSA"
	case .Unknown:
	}
	return ""
}

/*
algorithm_from_name parses a JWA algorithm name. Names are case-sensitive, as
RFC 7515 requires.

Returns:
- alg: the algorithm, or `.Unknown` on failure.
- err: `.Algorithm_None` for "none" in any letter case, `.Missing_Algorithm`
  for an empty name, otherwise `.Unsupported_Algorithm` for names this package
  doesn't implement.
*/
algorithm_from_name :: proc(name: string) -> (alg: Algorithm, err: Signature_Error) {
	switch name {
	case "HS256":
		return .HS256, .None
	case "HS384":
		return .HS384, .None
	case "HS512":
		return .HS512, .None
	case "EdDSA":
		return .EdDSA, .None
	case "":
		return .Unknown, .Missing_Algorithm
	}
	if ascii_equal_fold(name, "none") {
		return .Unknown, .Algorithm_None
	}
	return .Unknown, .Unsupported_Algorithm
}

/*
key_algorithms returns the algorithms that `key` can be used with:
`HMAC_ALGORITHMS` for an `Hmac_Key`, `ED25519_ALGORITHMS` for an Ed25519 key,
and an empty set for a nil key.
*/
key_algorithms :: proc(key: Key) -> Algorithms {
	switch _ in key {
	case Hmac_Key:
		return HMAC_ALGORITHMS
	case ^ed25519.Private_Key, ^ed25519.Public_Key:
		return ED25519_ALGORITHMS
	}
	return {}
}

@(private)
ascii_equal_fold :: proc(a, b: string) -> bool {
	if len(a) != len(b) {
		return false
	}
	for i in 0 ..< len(a) {
		x, y := a[i], b[i]
		if 'A' <= x && x <= 'Z' {
			x += 'a' - 'A'
		}
		if 'A' <= y && y <= 'Z' {
			y += 'a' - 'A'
		}
		if x != y {
			return false
		}
	}
	return true
}
