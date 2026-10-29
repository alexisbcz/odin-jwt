package jwt

import "base:runtime"
import "core:crypto"
import "core:crypto/ed25519"
import "core:crypto/hash"
import "core:crypto/hmac"
import "core:encoding/json"
import "core:strconv"
import "core:unicode/utf8"

// MAX_SIGNATURE_SIZE is the largest signature any supported algorithm produces, in bytes.
MAX_SIGNATURE_SIZE :: 64

/*
encode signs `payload` and returns a compact JWS token.

The header is `{"alg":"<alg>","typ":"JWT"}`, plus `"kid"` when `kid` isn't
empty. The payload is copied byte for byte, so marshal your own claims struct
with `core:encoding/json` to add private claims.

Inputs:
- payload: a JSON object, for example the output of `json.marshal`. It must be
  strict JSON (not JSON5) without duplicate keys.
- alg: the algorithm to sign with. It must match the key type.
- key: an `Hmac_Key` for HS256, HS384 and HS512, or an `^ed25519.Private_Key` for EdDSA.
- kid: an optional key identifier for the header.
- allocator: allocates the result and scratch memory, which is freed before returning.

Returns:
- token: a new string owned by the caller; free it with `delete(token, allocator)`.
- err: a `Format_Error` for a bad payload or `kid`, a `Signature_Error` for a
  bad algorithm or key, or an allocator error.
*/
encode :: proc(payload: []byte, alg: Algorithm, key: Key, kid := "", allocator := context.allocator) -> (token: string, err: Error) {
	check_signing_key(alg, key) or_return
	check_payload(payload, allocator) or_return

	header := build_header(alg, kid, allocator) or_return
	defer delete(header, allocator)

	header_len := base64url_encoded_len(len(header))
	payload_len := base64url_encoded_len(len(payload))
	sig_size := signature_size(alg)
	signing_len := header_len + 1 + payload_len
	total := signing_len + 1 + base64url_encoded_len(sig_size)

	buf := make([]byte, total, allocator) or_return
	encode_into(buf[:header_len], header)
	buf[header_len] = '.'
	encode_into(buf[header_len + 1:signing_len], payload)
	buf[signing_len] = '.'

	sig: [MAX_SIGNATURE_SIZE]byte
	defer crypto.zero_explicit(&sig, size_of(sig))
	compute_signature(alg, key, buf[:signing_len], sig[:sig_size])
	encode_into(buf[signing_len + 1:], sig[:sig_size])

	return string(buf), nil
}

/*
encode_claims serializes the registered claims in `claims` and signs them
with encode.

Members are written in the order iss, sub, aud, exp, nbf, iat, jti. Empty
strings, an empty `aud` and nil times are left out. A single audience is
written as a string, several as an array.

Inputs:
- claims: the claims to encode.
- alg, key, kid: as for encode.
- allocator: allocates the result and scratch memory, which is freed before returning.

Returns:
- token: a new string owned by the caller; free it with `delete(token, allocator)`.
- err: `Format_Error.Invalid_Utf8` for a claim string that isn't UTF-8, a
  `Signature_Error`, or an allocator error.
*/
encode_claims :: proc(claims: Claims, alg: Algorithm, key: Key, kid := "", allocator := context.allocator) -> (token: string, err: Error) {
	check_signing_key(alg, key) or_return

	b := make([dynamic]byte, 0, 128, allocator) or_return
	defer delete(b)

	first := true
	put(&b, "{") or_return
	put_string_member(&b, &first, "iss", claims.iss) or_return
	put_string_member(&b, &first, "sub", claims.sub) or_return
	switch len(claims.aud) {
	case 0:
	case 1:
		put_string_member(&b, &first, "aud", claims.aud[0]) or_return
	case:
		put_member_name(&b, &first, "aud") or_return
		put(&b, "[") or_return
		for aud, i in claims.aud {
			if i > 0 {
				put(&b, ",") or_return
			}
			put_json_string(&b, aud) or_return
		}
		put(&b, "]") or_return
	}
	put_time_member(&b, &first, "exp", claims.exp) or_return
	put_time_member(&b, &first, "nbf", claims.nbf) or_return
	put_time_member(&b, &first, "iat", claims.iat) or_return
	put_string_member(&b, &first, "jti", claims.jti) or_return
	put(&b, "}") or_return

	return encode(b[:], alg, key, kid, allocator)
}

// check_signing_key reports whether `key` can sign with `alg`.
@(private)
check_signing_key :: proc(alg: Algorithm, key: Key) -> Signature_Error {
	check_key(alg, key) or_return
	if _, is_public := key.(^ed25519.Public_Key); is_public {
		return .Key_Cannot_Sign
	}
	return .None
}

// check_key reports whether `key` is usable with `alg`, for signing or for verifying.
@(private)
check_key :: proc(alg: Algorithm, key: Key) -> Signature_Error {
	if alg == .Unknown || alg > max(Algorithm) {
		return .Unsupported_Algorithm
	}
	if key == nil {
		return .Invalid_Key
	}
	if alg not_in key_algorithms(key) {
		return .Key_Algorithm_Mismatch
	}
	switch k in key {
	case Hmac_Key:
		if len(k) < signature_size(alg) {
			return .Key_Too_Short
		}
	case ^ed25519.Private_Key:
		if k == nil || !k._is_initialized {
			return .Invalid_Key
		}
	case ^ed25519.Public_Key:
		if k == nil || !k._is_initialized {
			return .Invalid_Key
		}
	}
	return .None
}

// signature_size returns the signature length of `alg` in bytes, or 0 for `.Unknown`.
@(private)
signature_size :: proc(alg: Algorithm) -> int {
	switch alg {
	case .HS256, .HS384, .HS512:
		return hash.DIGEST_SIZES[hmac_hash(alg)]
	case .EdDSA:
		return ed25519.SIGNATURE_SIZE
	case .Unknown:
	}
	return 0
}

@(private)
hmac_hash :: proc(alg: Algorithm) -> hash.Algorithm {
	#partial switch alg {
	case .HS256:
		return .SHA256
	case .HS384:
		return .SHA384
	case .HS512:
		return .SHA512
	}
	return .Invalid
}

// compute_signature signs `msg` into `sig`. The caller has already validated `alg` and `key` with check_signing_key.
@(private)
compute_signature :: proc(alg: Algorithm, key: Key, msg, sig: []byte) {
	switch k in key {
	case Hmac_Key:
		hmac.sum(hmac_hash(alg), sig, msg, ([]byte)(k))
	case ^ed25519.Private_Key:
		ed25519.sign(k, msg, sig)
	case ^ed25519.Public_Key:
		unreachable()
	}
}

/*
verify_bytes checks `sig` over `msg`. HMAC tags are compared in constant time.
The caller has already validated `alg` and `key` with check_key.
*/
@(private)
verify_bytes :: proc(alg: Algorithm, key: Key, msg, sig: []byte) -> Signature_Error {
	if len(sig) != signature_size(alg) {
		return .Invalid_Signature
	}
	switch k in key {
	case Hmac_Key:
		expected: [MAX_SIGNATURE_SIZE]byte
		defer crypto.zero_explicit(&expected, size_of(expected))
		tag := expected[:len(sig)]
		hmac.sum(hmac_hash(alg), tag, msg, ([]byte)(k))
		if crypto.compare_constant_time(tag, sig) != 1 {
			return .Invalid_Signature
		}
	case ^ed25519.Private_Key:
		pub: ed25519.Public_Key
		ed25519.public_key_set_priv(&pub, k)
		if !ed25519.verify(&pub, msg, sig) {
			return .Invalid_Signature
		}
	case ^ed25519.Public_Key:
		if !ed25519.verify(k, msg, sig) {
			return .Invalid_Signature
		}
	}
	return .None
}

// check_payload makes sure `payload` is one strict JSON object with no duplicate keys.
@(private = "file")
check_payload :: proc(payload: []byte, allocator: runtime.Allocator) -> Error {
	obj, is_object := parse_json_object(payload, allocator) or_return
	defer json.destroy_value(obj, allocator)
	if !is_object {
		return .Payload_Not_Object
	}
	return nil
}

@(private = "file")
build_header :: proc(alg: Algorithm, kid: string, allocator: runtime.Allocator) -> (header: []byte, err: Error) {
	b := make([dynamic]byte, 0, 64, allocator) or_return
	defer if err != nil {
		delete(b)
	}
	put(&b, `{"alg":"`) or_return
	put(&b, algorithm_name(alg)) or_return
	put(&b, `","typ":"JWT"`) or_return
	if kid != "" {
		put(&b, `,"kid":`) or_return
		put_json_string(&b, kid) or_return
	}
	put(&b, "}") or_return
	return b[:], nil
}

// put appends `s` to `b`.
@(private = "file")
put :: proc(b: ^[dynamic]byte, s: string) -> Error {
	_, err := append(b, s)
	return err
}

@(private = "file")
put_member_name :: proc(b: ^[dynamic]byte, first: ^bool, name: string) -> Error {
	if !first^ {
		put(b, ",") or_return
	}
	first^ = false
	put(b, `"`) or_return
	put(b, name) or_return
	return put(b, `":`)
}

@(private = "file")
put_string_member :: proc(b: ^[dynamic]byte, first: ^bool, name, value: string) -> Error {
	if value == "" {
		return nil
	}
	put_member_name(b, first, name) or_return
	return put_json_string(b, value)
}

@(private = "file")
put_time_member :: proc(b: ^[dynamic]byte, first: ^bool, name: string, value: Maybe(i64)) -> Error {
	v, ok := value.?
	if !ok {
		return nil
	}
	put_member_name(b, first, name) or_return
	digits: [32]byte
	return put(b, strconv.write_int(digits[:], v, 10))
}

// put_json_string writes `s` as a JSON string literal, escaping quotes, backslashes and control characters.
@(private = "file")
put_json_string :: proc(b: ^[dynamic]byte, s: string) -> Error {
	if !utf8.valid_string(s) {
		return .Invalid_Utf8
	}
	hex := "0123456789abcdef"
	put(b, `"`) or_return
	start := 0
	for i in 0 ..< len(s) {
		c := s[i]
		esc: string
		switch c {
		case '"':
			esc = `\"`
		case '\\':
			esc = `\\`
		case '\n':
			esc = `\n`
		case '\r':
			esc = `\r`
		case '\t':
			esc = `\t`
		case 0x00 ..< 0x20, 0x7f:
		case:
			continue
		}
		put(b, s[start:i]) or_return
		start = i + 1
		if esc != "" {
			put(b, esc) or_return
		} else {
			code := [6]byte{'\\', 'u', '0', '0', hex[c >> 4], hex[c & 0xf]}
			put(b, string(code[:])) or_return
		}
	}
	put(b, s[start:]) or_return
	return put(b, `"`)
}
