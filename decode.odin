package jwt

import "base:runtime"
import "core:encoding/json"
import "core:strings"

/*
decode verifies `token` with `key`, then parses it and validates its claims.

The steps run in this order, and the first failure is returned:

1. Size and structure: at most `validation.max_token_size` bytes, three
   segments, canonical base64url.
2. Header: a JSON object with a supported, non-`none` `alg` and no `crit`.
3. Algorithm: allowed by the key type and by `validation.algorithms`.
4. Signature: checked in constant time, before the payload is parsed.
5. Payload: a JSON object whose registered claims have the right types.
6. Claims: validated by validate_claims.

Inputs:
- token: the compact JWS string.
- key: the key to verify with. See `Key` for which algorithms each key type allows.
- validation: the rules for claims and algorithms. The zero value requires a
  valid `exp` and compares times against the system clock.
- allocator: allocates the returned token.

Returns:
- t: the decoded token on success; release it with `token_destroy(&t)`. On
  failure it's zero and owns nothing.
- err: a `Format_Error`, `Signature_Error`, `Claim_Error` or allocator error.
*/
decode :: proc(token: string, key: Key, validation := Validation{}, allocator := context.allocator) -> (t: Token, err: Error) {
	parts := split_token(token, validation.max_token_size) or_return
	t.allocator = allocator
	err = decode_parts(&t, parts, key, validation, verify = true)
	if err != nil {
		token_destroy(&t)
		return {}, err
	}
	return t, nil
}

/*
decode_unverified parses `token` without checking its signature or claims.

Use it only to read header members such as `kid` so you can pick a key, then
call decode with that key. Never trust the claims it returns. It still rejects
`alg: "none"`, unsupported algorithms and `crit` headers, because such a token
could never pass decode.

Inputs:
- token: the compact JWS string.
- max_token_size: the size limit in bytes; 0 means `DEFAULT_MAX_TOKEN_SIZE`.
- allocator: allocates the returned token.

Returns:
- t: the parsed token; release it with `token_destroy(&t)`. On failure it's zero.
- err: a `Format_Error`, `Signature_Error`, `Claim_Error.Invalid_Claim_Type` or allocator error.
*/
decode_unverified :: proc(token: string, max_token_size := 0, allocator := context.allocator) -> (t: Token, err: Error) {
	parts := split_token(token, max_token_size) or_return
	t.allocator = allocator
	err = decode_parts(&t, parts, nil, {}, verify = false)
	if err != nil {
		token_destroy(&t)
		return {}, err
	}
	return t, nil
}

/*
verify_signature checks the signature of a compact JWS without parsing the
payload or checking any claims.

It accepts payloads that aren't JSON, which makes it useful for plain JWS
messages. For JWTs, use decode, which also validates the claims.

Inputs:
- token: the compact JWS string.
- key: the key to verify with.
- algorithms: the allowed algorithms; an empty set allows every algorithm the key supports.
- max_token_size: the size limit in bytes; 0 means `DEFAULT_MAX_TOKEN_SIZE`.
- allocator: scratch memory for the header, freed before returning.

Returns:
- err: nil when the signature is valid, otherwise a `Format_Error`,
  `Signature_Error` or allocator error.
*/
verify_signature :: proc(token: string, key: Key, algorithms := Algorithms{}, max_token_size := 0, allocator := context.allocator) -> Error {
	parts := split_token(token, max_token_size) or_return
	header_object, header := parse_header(parts.header, allocator) or_return
	defer json.destroy_value(header_object, allocator)
	check_algorithm(header.alg, key, algorithms) or_return
	return verify_parts(parts, header.alg, key)
}

/*
claim returns the payload member called `name`, which may be a private claim.
The value borrows from the token.
*/
claim :: proc(t: ^Token, name: string) -> (value: json.Value, ok: bool) {
	return t.payload[name]
}

// claim_string returns the payload member `name` when it's a JSON string. The string borrows from the token.
claim_string :: proc(t: ^Token, name: string) -> (value: string, ok: bool) {
	v := claim(t, name) or_return
	return v.(json.String)
}

// claim_int returns the payload member `name` when it's a JSON integer.
claim_int :: proc(t: ^Token, name: string) -> (value: i64, ok: bool) {
	v := claim(t, name) or_return
	return v.(json.Integer)
}

// claim_bool returns the payload member `name` when it's a JSON boolean.
claim_bool :: proc(t: ^Token, name: string) -> (value: bool, ok: bool) {
	v := claim(t, name) or_return
	return v.(json.Boolean)
}

// Segments holds the three parts of a compact JWS and the signing input `header.payload`.
@(private = "file")
Segments :: struct {
	header, payload, signature: string,
	signing_input:              string,
}

// split_token checks the size and returns the three segments of a compact JWS.
@(private = "file")
split_token :: proc(token: string, max_token_size: int) -> (parts: Segments, err: Error) {
	limit := max_token_size if max_token_size > 0 else DEFAULT_MAX_TOKEN_SIZE
	if len(token) > limit {
		return {}, .Token_Too_Large
	}
	if strings.count(token, ".") != 2 {
		return {}, .Wrong_Segment_Count
	}
	first := strings.index_byte(token, '.')
	second := first + 1 + strings.index_byte(token[first + 1:], '.')
	parts = {
		header        = token[:first],
		payload       = token[first + 1:second],
		signature     = token[second + 1:],
		signing_input = token[:second],
	}
	if parts.header == "" {
		return {}, .Invalid_Base64
	}
	return parts, nil
}

/*
decode_parts fills `t` from the segments. On failure, `t` may hold partial
results, which the caller releases with token_destroy.
*/
@(private = "file")
decode_parts :: proc(t: ^Token, parts: Segments, key: Key, validation: Validation, verify: bool) -> Error {
	t.header_object, t.header = parse_header(parts.header, t.allocator) or_return
	if verify {
		check_algorithm(t.header.alg, key, validation.algorithms) or_return
		verify_parts(parts, t.header.alg, key) or_return
	}
	t.payload, t.claims = parse_payload(parts.payload, t.allocator) or_return
	if verify {
		validate_claims(t.claims, validation) or_return
	}
	return nil
}

// check_algorithm makes sure `alg` is allowed by both the key type and the caller's set.
@(private = "file")
check_algorithm :: proc(alg: Algorithm, key: Key, algorithms: Algorithms) -> Error {
	check_key(alg, key) or_return
	if algorithms != {} && alg not_in algorithms {
		return Signature_Error.Algorithm_Not_Allowed
	}
	return nil
}

// verify_parts decodes the signature segment and checks it over the signing input.
@(private = "file")
verify_parts :: proc(parts: Segments, alg: Algorithm, key: Key) -> Error {
	sig_text := parts.signature
	if sig_text == "" {
		return Signature_Error.Invalid_Signature
	}
	if len(sig_text) > base64url_encoded_len(MAX_SIGNATURE_SIZE) {
		return Signature_Error.Invalid_Signature
	}
	sig: [MAX_SIGNATURE_SIZE]byte
	sig_len := base64url_decoded_len(len(sig_text))
	if !decode_into(sig[:sig_len], sig_text) {
		return Format_Error.Invalid_Base64
	}
	return verify_bytes(alg, key, transmute([]byte)parts.signing_input, sig[:sig_len])
}

// parse_header decodes the JOSE header. On failure it frees everything and returns a nil object.
@(private = "file")
parse_header :: proc(segment: string, allocator: runtime.Allocator) -> (obj: json.Object, header: Header, err: Error) {
	raw := base64url_decode(segment, allocator) or_return
	defer delete(raw, allocator)

	is_object: bool
	obj, is_object = parse_json_object(raw, allocator) or_return
	if !is_object {
		return nil, {}, Format_Error.Header_Not_Object
	}
	header, err = header_from_object(obj)
	if err != nil {
		json.destroy_value(obj, allocator)
		return nil, {}, err
	}
	return obj, header, nil
}

@(private = "file")
header_from_object :: proc(obj: json.Object) -> (header: Header, err: Error) {
	alg_value, has_alg := obj["alg"]
	alg_name, alg_is_string := alg_value.(json.String)
	if !has_alg || !alg_is_string {
		return {}, Signature_Error.Missing_Algorithm
	}
	header.alg = algorithm_from_name(alg_name) or_return

	if "crit" in obj {
		return {}, Format_Error.Unsupported_Critical_Header
	}
	header.typ = optional_header_string(obj, "typ") or_return
	header.cty = optional_header_string(obj, "cty") or_return
	header.kid = optional_header_string(obj, "kid") or_return
	return header, nil
}

@(private = "file")
optional_header_string :: proc(obj: json.Object, name: string) -> (value: string, err: Error) {
	v, present := obj[name]
	if !present {
		return "", nil
	}
	s, is_string := v.(json.String)
	if !is_string {
		return "", Format_Error.Invalid_Header
	}
	return s, nil
}

@(private = "file")
parse_payload :: proc(segment: string, allocator: runtime.Allocator) -> (obj: json.Object, claims: Claims, err: Error) {
	raw := base64url_decode(segment, allocator) or_return
	defer delete(raw, allocator)

	is_object: bool
	obj, is_object = parse_json_object(raw, allocator) or_return
	if !is_object {
		json.destroy_value(obj, allocator)
		return nil, {}, Format_Error.Payload_Not_Object
	}
	claims, err = claims_from_object(obj, allocator)
	if err != nil {
		json.destroy_value(obj, allocator)
		return nil, {}, err
	}
	return obj, claims, nil
}

// claims_from_object reads the registered claims. Strings borrow from `obj`; `aud` is allocated.
@(private = "file")
claims_from_object :: proc(obj: json.Object, allocator: runtime.Allocator) -> (claims: Claims, err: Error) {
	claims.iss = optional_claim_string(obj, "iss") or_return
	claims.sub = optional_claim_string(obj, "sub") or_return
	claims.jti = optional_claim_string(obj, "jti") or_return
	claims.exp = optional_numeric_date(obj, "exp") or_return
	claims.nbf = optional_numeric_date(obj, "nbf") or_return
	claims.iat = optional_numeric_date(obj, "iat") or_return

	aud, has_aud := obj["aud"]
	if !has_aud {
		return claims, nil
	}
	#partial switch v in aud {
	case json.String:
		claims.aud = make([]string, 1, allocator) or_return
		claims.aud[0] = v
	case json.Array:
		for elem in v {
			if _, is_string := elem.(json.String); !is_string {
				return {}, Claim_Error.Invalid_Claim_Type
			}
		}
		claims.aud = make([]string, len(v), allocator) or_return
		for elem, i in v {
			claims.aud[i] = elem.(json.String)
		}
	case:
		return {}, Claim_Error.Invalid_Claim_Type
	}
	return claims, nil
}

@(private = "file")
optional_claim_string :: proc(obj: json.Object, name: string) -> (value: string, err: Error) {
	v, present := obj[name]
	if !present {
		return "", nil
	}
	s, is_string := v.(json.String)
	if !is_string {
		return "", Claim_Error.Invalid_Claim_Type
	}
	return s, nil
}

// optional_numeric_date reads a NumericDate claim. Fractional seconds are rounded down.
@(private = "file")
optional_numeric_date :: proc(obj: json.Object, name: string) -> (value: Maybe(i64), err: Error) {
	v, present := obj[name]
	if !present {
		return nil, nil
	}
	#partial switch n in v {
	case json.Integer:
		return n, nil
	case json.Float:
		// Rejects NaN and infinities, and keeps the conversion in range.
		if !(n > -9.0e18 && n < 9.0e18) {
			return nil, Claim_Error.Invalid_Claim_Type
		}
		i := i64(n)
		if f64(i) > n {
			i -= 1
		}
		return i, nil
	}
	return nil, Claim_Error.Invalid_Claim_Type
}
