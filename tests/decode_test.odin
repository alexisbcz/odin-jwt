package jwt_tests

import jwt ".."
import "core:crypto/ed25519"
import "core:crypto/hash"
import "core:mem"
import "core:strings"
import "core:testing"

// PAYLOAD is a minimal valid claims set for NOW.
@(private = "file")
PAYLOAD :: `{"sub":"alice","exp":1700000060}`

@(private = "file")
HS256_HEADER :: `{"alg":"HS256","typ":"JWT"}`

// expect_decode_error signs `header` and `payload` with SECRET and checks that decode fails with `want` without leaking.
@(private = "file")
expect_decode_error :: proc(t: ^testing.T, header, payload: string, want: jwt.Error, loc := #caller_location) {
	track: mem.Tracking_Allocator
	context.allocator = begin_tracking(&track)
	defer end_tracking(t, &track, loc)

	raw := sign_raw(header, payload)
	defer delete(raw)
	token, err := jwt.decode(raw, secret_key(), {now = NOW})
	defer jwt.token_destroy(&token)
	testing.expectf(t, err == want, "want %v, got %v", want, err, loc = loc)
	if err != nil {
		testing.expect(t, token.payload == nil && token.header_object == nil, "failed decode returned memory", loc = loc)
	}
}

@(test)
test_decode_accepts_crafted_valid_token :: proc(t: ^testing.T) {
	expect_decode_error(t, HS256_HEADER, PAYLOAD, nil)
}

@(test)
test_decode_rejects_wrong_segment_count :: proc(t: ^testing.T) {
	for token in ([]string{"", "abc", "a.b", "a.b.c.d", "a.b.c.d.e"}) {
		_, err := jwt.decode(token, secret_key(), {now = NOW})
		testing.expectf(t, err == jwt.Error(jwt.Format_Error.Wrong_Segment_Count), "%q: got %v", token, err)
	}
}

@(test)
test_decode_rejects_oversized_token :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	context.allocator = begin_tracking(&track)
	defer end_tracking(t, &track)

	big := strings.repeat("a", jwt.DEFAULT_MAX_TOKEN_SIZE + 1)
	defer delete(big)
	_, err := jwt.decode(big, secret_key(), {now = NOW})
	testing.expect_value(t, err, jwt.Error(jwt.Format_Error.Token_Too_Large))

	raw := sign_raw(HS256_HEADER, PAYLOAD)
	defer delete(raw)
	_, small := jwt.decode(raw, secret_key(), {now = NOW, max_token_size = 16})
	testing.expect_value(t, small, jwt.Error(jwt.Format_Error.Token_Too_Large))
}

@(test)
test_decode_rejects_empty_signature :: proc(t: ^testing.T) {
	raw := sign_raw(HS256_HEADER, PAYLOAD)
	defer delete(raw)
	stripped := raw[:strings.last_index_byte(raw, '.') + 1]
	_, err := jwt.decode(stripped, secret_key(), {now = NOW})
	testing.expect_value(t, err, jwt.Error(jwt.Signature_Error.Invalid_Signature))
}

@(test)
test_decode_rejects_truncated_signature :: proc(t: ^testing.T) {
	raw := sign_raw(HS256_HEADER, PAYLOAD)
	defer delete(raw)
	// 43 characters minus 3 is still a valid base64url length, but too short a tag.
	_, short := jwt.decode(raw[:len(raw) - 3], secret_key(), {now = NOW})
	testing.expect_value(t, short, jwt.Error(jwt.Signature_Error.Invalid_Signature))
	// Minus 4 leaves stray trailing bits, so the segment isn't canonical base64url.
	_, ragged := jwt.decode(raw[:len(raw) - 4], secret_key(), {now = NOW})
	testing.expect_value(t, ragged, jwt.Error(jwt.Format_Error.Invalid_Base64))
}

@(test)
test_decode_rejects_oversized_signature :: proc(t: ^testing.T) {
	raw := sign_raw(HS256_HEADER, PAYLOAD)
	defer delete(raw)
	padded := strings.concatenate({raw, strings.repeat("A", 100, context.temp_allocator)})
	defer delete(padded)
	_, err := jwt.decode(padded, secret_key(), {now = NOW})
	testing.expect_value(t, err, jwt.Error(jwt.Signature_Error.Invalid_Signature))
	free_all(context.temp_allocator)
}

@(test)
test_decode_rejects_invalid_base64_segments :: proc(t: ^testing.T) {
	raw := sign_raw(HS256_HEADER, PAYLOAD)
	defer delete(raw)
	parts := strings.split(raw, ".")
	defer delete(parts)

	bad_header := strings.join({"eyJ=", parts[1], parts[2]}, ".")
	defer delete(bad_header)
	_, herr := jwt.decode(bad_header, secret_key(), {now = NOW})
	testing.expect_value(t, herr, jwt.Error(jwt.Format_Error.Invalid_Base64))

	bad_sig := strings.join({parts[0], parts[1], "a+b/"}, ".")
	defer delete(bad_sig)
	_, serr := jwt.decode(bad_sig, secret_key(), {now = NOW})
	testing.expect_value(t, serr, jwt.Error(jwt.Format_Error.Invalid_Base64))

	empty_header := strings.join({"", parts[1], parts[2]}, ".")
	defer delete(empty_header)
	_, eerr := jwt.decode(empty_header, secret_key(), {now = NOW})
	testing.expect_value(t, eerr, jwt.Error(jwt.Format_Error.Invalid_Base64))
}

@(test)
test_decode_rejects_header_that_is_not_an_object :: proc(t: ^testing.T) {
	expect_decode_error(t, `["HS256"]`, PAYLOAD, jwt.Format_Error.Header_Not_Object)
	expect_decode_error(t, `{"alg":"HS256"`, PAYLOAD, jwt.Format_Error.Invalid_Json)
}

@(test)
test_decode_rejects_missing_or_non_string_alg :: proc(t: ^testing.T) {
	expect_decode_error(t, `{"typ":"JWT"}`, PAYLOAD, jwt.Signature_Error.Missing_Algorithm)
	expect_decode_error(t, `{"alg":256}`, PAYLOAD, jwt.Signature_Error.Missing_Algorithm)
	expect_decode_error(t, `{"alg":""}`, PAYLOAD, jwt.Signature_Error.Missing_Algorithm)
}

@(test)
test_decode_rejects_none_in_every_case :: proc(t: ^testing.T) {
	for header in ([]string{`{"alg":"none"}`, `{"alg":"None"}`, `{"alg":"NONE"}`, `{"alg":"nOnE"}`}) {
		expect_decode_error(t, header, PAYLOAD, jwt.Signature_Error.Algorithm_None)
	}
}

@(test)
test_decode_rejects_unsupported_algorithms :: proc(t: ^testing.T) {
	for header in ([]string{`{"alg":"RS256"}`, `{"alg":"hs256"}`, `{"alg":"HS256 "}`, `{"alg":"ES256"}`}) {
		expect_decode_error(t, header, PAYLOAD, jwt.Signature_Error.Unsupported_Algorithm)
	}
}

@(test)
test_decode_rejects_crit_header :: proc(t: ^testing.T) {
	expect_decode_error(t, `{"alg":"HS256","crit":["exp"],"exp":1}`, PAYLOAD, jwt.Format_Error.Unsupported_Critical_Header)
	expect_decode_error(t, `{"alg":"HS256","b64":false,"crit":["b64"]}`, PAYLOAD, jwt.Format_Error.Unsupported_Critical_Header)
}

@(test)
test_decode_rejects_header_members_of_wrong_type :: proc(t: ^testing.T) {
	expect_decode_error(t, `{"alg":"HS256","typ":1}`, PAYLOAD, jwt.Format_Error.Invalid_Header)
	expect_decode_error(t, `{"alg":"HS256","kid":null}`, PAYLOAD, jwt.Format_Error.Invalid_Header)
	expect_decode_error(t, `{"alg":"HS256","cty":["JWT"]}`, PAYLOAD, jwt.Format_Error.Invalid_Header)
}

@(test)
test_decode_rejects_duplicate_header_members :: proc(t: ^testing.T) {
	expect_decode_error(t, `{"alg":"HS256","alg":"none"}`, PAYLOAD, jwt.Format_Error.Invalid_Json)
}

@(test)
test_decode_rejects_payload_that_is_not_an_object :: proc(t: ^testing.T) {
	expect_decode_error(t, HS256_HEADER, `["alice"]`, jwt.Format_Error.Payload_Not_Object)
	expect_decode_error(t, HS256_HEADER, `Example of Ed25519 signing`, jwt.Format_Error.Invalid_Json)
	expect_decode_error(t, HS256_HEADER, `{"exp":1700000060} {}`, jwt.Format_Error.Invalid_Json)
	expect_decode_error(t, HS256_HEADER, `{exp:1700000060}`, jwt.Format_Error.Invalid_Json)
	expect_decode_error(t, HS256_HEADER, `{"exp":1700000060,"exp":1}`, jwt.Format_Error.Invalid_Json)
}

@(test)
test_decode_rejects_hmac_token_with_ed25519_key :: proc(t: ^testing.T) {
	priv: ed25519.Private_Key
	pub: ed25519.Public_Key
	load_rfc_8037_keys(t, &priv, &pub)

	raw := sign_raw(HS256_HEADER, PAYLOAD)
	defer delete(raw)
	_, err := jwt.decode(raw, &pub, {now = NOW})
	testing.expect_value(t, err, jwt.Error(jwt.Signature_Error.Key_Algorithm_Mismatch))
}

@(test)
test_decode_rejects_eddsa_token_with_hmac_key :: proc(t: ^testing.T) {
	// Algorithm confusion: an attacker HMAC-signs a token that claims EdDSA,
	// hoping the verifier treats its secret as an Ed25519 key or the reverse.
	expect_decode_error(t, `{"alg":"EdDSA"}`, PAYLOAD, jwt.Signature_Error.Key_Algorithm_Mismatch)

	priv: ed25519.Private_Key
	pub: ed25519.Public_Key
	load_rfc_8037_keys(t, &priv, &pub)
	_, err := jwt.decode(RFC_8037_TOKEN, secret_key(), {now = NOW})
	testing.expect_value(t, err, jwt.Error(jwt.Signature_Error.Key_Algorithm_Mismatch))
}

@(test)
test_decode_enforces_algorithm_allow_list :: proc(t: ^testing.T) {
	raw := sign_raw(`{"alg":"HS512"}`, PAYLOAD, .SHA512)
	defer delete(raw)
	_, err := jwt.decode(raw, secret_key(), {now = NOW, algorithms = {.HS256}})
	testing.expect_value(t, err, jwt.Error(jwt.Signature_Error.Algorithm_Not_Allowed))

	ok, allowed := jwt.decode(raw, secret_key(), {now = NOW, algorithms = {.HS256, .HS512}})
	defer jwt.token_destroy(&ok)
	testing.expect_value(t, allowed, nil)
}

@(test)
test_decode_rejects_wrong_secret :: proc(t: ^testing.T) {
	raw := sign_raw(HS256_HEADER, PAYLOAD)
	defer delete(raw)
	other := jwt.Hmac_Key(transmute([]byte)string("ffffffffffffffffffffffffffffffff"))
	_, err := jwt.decode(raw, other, {now = NOW})
	testing.expect_value(t, err, jwt.Error(jwt.Signature_Error.Invalid_Signature))
}

@(test)
test_decode_rejects_signature_length_of_other_algorithm :: proc(t: ^testing.T) {
	// A header that says HS512 with a 32-byte HS256 tag must fail before any comparison.
	raw := sign_raw(`{"alg":"HS512"}`, PAYLOAD, hash.Algorithm.SHA256)
	defer delete(raw)
	_, err := jwt.decode(raw, secret_key(), {now = NOW})
	testing.expect_value(t, err, jwt.Error(jwt.Signature_Error.Invalid_Signature))
}

@(test)
test_decode_rejects_short_hmac_key :: proc(t: ^testing.T) {
	raw := sign_raw(HS256_HEADER, PAYLOAD, key = "short")
	defer delete(raw)
	_, err := jwt.decode(raw, jwt.Hmac_Key(transmute([]byte)string("short")), {now = NOW})
	testing.expect_value(t, err, jwt.Error(jwt.Signature_Error.Key_Too_Short))
}

@(test)
test_decode_checks_signature_before_payload :: proc(t: ^testing.T) {
	// The payload is garbage, but the bad signature must be reported first.
	raw := sign_raw(HS256_HEADER, `not json`, key = "ffffffffffffffffffffffffffffffff")
	defer delete(raw)
	_, err := jwt.decode(raw, secret_key(), {now = NOW})
	testing.expect_value(t, err, jwt.Error(jwt.Signature_Error.Invalid_Signature))
}

@(test)
test_decode_unverified_reads_header_without_key :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	context.allocator = begin_tracking(&track)
	defer end_tracking(t, &track)

	raw := sign_raw(`{"alg":"HS256","kid":"k1","x5u":"ignored"}`, PAYLOAD, key = "unknown-to-the-verifier-unknown!")
	defer delete(raw)

	token, err := jwt.decode_unverified(raw)
	defer jwt.token_destroy(&token)
	testing.expect_value(t, err, nil)
	testing.expect_value(t, token.header.kid, "k1")
	testing.expect_value(t, token.claims.sub, "alice")
	testing.expect(t, "x5u" in token.header_object)

	// The real decode still refuses it with our key.
	_, verr := jwt.decode(raw, secret_key(), {now = NOW})
	testing.expect_value(t, verr, jwt.Error(jwt.Signature_Error.Invalid_Signature))
}

@(test)
test_decode_unverified_honours_size_limit :: proc(t: ^testing.T) {
	raw := sign_raw(HS256_HEADER, PAYLOAD)
	defer delete(raw)
	_, err := jwt.decode_unverified(raw, max_token_size = 8)
	testing.expect_value(t, err, jwt.Error(jwt.Format_Error.Token_Too_Large))
}

@(test)
test_verify_signature_accepts_non_json_payload :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	context.allocator = begin_tracking(&track)
	defer end_tracking(t, &track)

	raw := sign_raw(HS256_HEADER, `plain text, not JSON`)
	defer delete(raw)
	testing.expect_value(t, jwt.verify_signature(raw, secret_key()), nil)
	testing.expect_value(t, jwt.verify_signature(raw, secret_key(), {.HS512}), jwt.Error(jwt.Signature_Error.Algorithm_Not_Allowed))
}

@(test)
test_decode_rejects_lenient_json :: proc(t: ^testing.T) {
	expect_decode_error(t, HS256_HEADER, `{"exp":1700000060,}`, jwt.Format_Error.Invalid_Json)
	expect_decode_error(t, HS256_HEADER, `{"exp":1700000060 /* c */}`, jwt.Format_Error.Invalid_Json)
	expect_decode_error(t, HS256_HEADER, `{"exp":01700000060}`, jwt.Format_Error.Invalid_Json)
	expect_decode_error(t, HS256_HEADER, `{"exp":1700000060,"s":"tab	here"}`, jwt.Format_Error.Invalid_Json)
	expect_decode_error(t, HS256_HEADER, `{"exp":1700000060,"s":"\x41"}`, jwt.Format_Error.Invalid_Json)
	expect_decode_error(t, HS256_HEADER, "{\"exp\":1700000060,\"s\":\"\xff\"}", jwt.Format_Error.Invalid_Json)
	expect_decode_error(t, `{"alg":"HS256",}`, PAYLOAD, jwt.Format_Error.Invalid_Json)
}

@(test)
test_decode_accepts_json_whitespace_and_escapes :: proc(t: ^testing.T) {
	expect_decode_error(t, " {\"alg\" : \"HS256\"}\r\n", "{ \"exp\":1700000060, \"s\":\"\\u00e9\\n\\/\" , \"n\":[1.5e3,-0,true,null] }", nil)
}

@(test)
test_decode_rejects_deep_nesting :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	context.allocator = begin_tracking(&track)
	defer end_tracking(t, &track)

	depth := jwt.MAX_JSON_DEPTH
	open := strings.repeat("[", depth)
	defer delete(open)
	close := strings.repeat("]", depth)
	defer delete(close)

	// The payload object itself is one level, so `depth` arrays inside it go one too deep.
	too_deep := strings.concatenate({`{"exp":1700000060,"x":`, open, close, `}`})
	defer delete(too_deep)
	expect_decode_error(t, HS256_HEADER, too_deep, jwt.Format_Error.Invalid_Json)

	just_fits := strings.concatenate({`{"exp":1700000060,"x":`, open[1:], close[1:], `}`})
	defer delete(just_fits)
	expect_decode_error(t, HS256_HEADER, just_fits, nil)
}

@(test)
test_token_destroy_on_zero_value_is_safe :: proc(t: ^testing.T) {
	token: jwt.Token
	jwt.token_destroy(&token)
	jwt.token_destroy(&token)
	testing.expect(t, token.payload == nil)
}

@(test)
test_decode_works_with_arena_allocator :: proc(t: ^testing.T) {
	buf: [8 * 1024]byte
	arena: mem.Arena
	mem.arena_init(&arena, buf[:])
	allocator := mem.arena_allocator(&arena)

	raw := sign_raw(HS256_HEADER, `{"sub":"alice","aud":["a","b"],"exp":1700000060}`)
	defer delete(raw)
	token, err := jwt.decode(raw, secret_key(), {now = NOW, audience = "b"}, allocator)
	testing.expect_value(t, err, nil)
	testing.expect_value(t, token.claims.sub, "alice")
	testing.expect(t, arena.offset > 0, "the token must allocate from the given allocator")
}
