package jwt_tests

import jwt ".."
import "core:crypto/ed25519"
import "core:encoding/json"
import "core:mem"
import "core:testing"

@(private = "file")
JOHN :: `{"sub":"1234567890","name":"John Doe","iat":1516239022}`

@(private = "file")
expect_known_answer :: proc(t: ^testing.T, alg: jwt.Algorithm, expected: string, loc := #caller_location) {
	track: mem.Tracking_Allocator
	context.allocator = begin_tracking(&track)
	defer end_tracking(t, &track, loc)

	key := load_rfc_7515_key(t)
	defer delete(key)

	token, err := jwt.encode(transmute([]byte)string(JOHN), alg, jwt.Hmac_Key(key))
	defer delete(token)
	testing.expect_value(t, err, nil, loc = loc)
	testing.expect_value(t, token, expected, loc = loc)
}

@(test)
test_encode_hs256_known_answer :: proc(t: ^testing.T) {
	expect_known_answer(t, .HS256, "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SVT7VUK8eOve-SCacPaU_bkzT3SFr9wk5EQciofG4Qo")
}

@(test)
test_encode_hs384_known_answer :: proc(t: ^testing.T) {
	expect_known_answer(t, .HS384, "eyJhbGciOiJIUzM4NCIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.MSnfJgb61edr7STbvEqi4Mj3Vvmb8Kh3lsnlXacv0cDAGYhBOpNmOrhWwQgTJCKj")
}

@(test)
test_encode_hs512_known_answer :: proc(t: ^testing.T) {
	expect_known_answer(t, .HS512, "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.39Xvky4dIVLaVaOW5BgbO7smTZUyvIcRtBE3i2hVW3GbjSeUFmpwRbMy94CfvgHC3KHT6V4-pnkNTotCWer-cw")
}

@(test)
test_encode_writes_kid_header :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	context.allocator = begin_tracking(&track)
	defer end_tracking(t, &track)

	encoded, err := jwt.encode_claims({sub = "alice", exp = NOW + 60}, .HS256, secret_key(), kid = "key-2026")
	defer delete(encoded)
	testing.expect_value(t, err, nil)

	token, derr := jwt.decode_unverified(encoded)
	defer jwt.token_destroy(&token)
	testing.expect_value(t, derr, nil)
	testing.expect_value(t, token.header.kid, "key-2026")
	testing.expect_value(t, token.header.typ, "JWT")
	testing.expect_value(t, token.header.alg, jwt.Algorithm.HS256)
}

@(test)
test_encode_escapes_kid :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	context.allocator = begin_tracking(&track)
	defer end_tracking(t, &track)

	kid := "a\"b\\c\nd"
	encoded, err := jwt.encode_claims({exp = NOW + 60}, .HS256, secret_key(), kid = kid)
	defer delete(encoded)
	testing.expect_value(t, err, nil)

	token, derr := jwt.decode(encoded, secret_key(), {now = NOW})
	defer jwt.token_destroy(&token)
	testing.expect_value(t, derr, nil)
	testing.expect_value(t, token.header.kid, kid)
}

@(test)
test_encode_rejects_non_object_payload :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	context.allocator = begin_tracking(&track)
	defer end_tracking(t, &track)

	for payload in ([]string{`[1,2]`, `"text"`, `42`, `null`}) {
		token, err := jwt.encode(transmute([]byte)payload, .HS256, secret_key())
		testing.expectf(t, err == jwt.Error(jwt.Format_Error.Payload_Not_Object), "%s: got %v", payload, err)
		testing.expect_value(t, token, "")
	}
}

@(test)
test_encode_rejects_invalid_json_payload :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	context.allocator = begin_tracking(&track)
	defer end_tracking(t, &track)

	for payload in ([]string{``, `{`, `{"a":}`, `{"a":1,}`, `{a:1}`, `{"a":1}{}`, `{"a":1} x`, `{'a':1}`}) {
		_, err := jwt.encode(transmute([]byte)payload, .HS256, secret_key())
		testing.expectf(t, err == jwt.Error(jwt.Format_Error.Invalid_Json), "%q: got %v", payload, err)
	}
}

@(test)
test_encode_rejects_duplicate_keys :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	context.allocator = begin_tracking(&track)
	defer end_tracking(t, &track)

	_, err := jwt.encode(transmute([]byte)string(`{"sub":"alice","sub":"admin"}`), .HS256, secret_key())
	testing.expect_value(t, err, jwt.Error(jwt.Format_Error.Invalid_Json))
}

@(test)
test_encode_rejects_short_hmac_keys :: proc(t: ^testing.T) {
	payload := transmute([]byte)string(`{}`)
	_, hs256 := jwt.encode(payload, .HS256, jwt.Hmac_Key(transmute([]byte)string(SECRET[:31])))
	testing.expect_value(t, hs256, jwt.Error(jwt.Signature_Error.Key_Too_Short))
	_, hs384 := jwt.encode(payload, .HS384, jwt.Hmac_Key(transmute([]byte)string(SECRET[:47])))
	testing.expect_value(t, hs384, jwt.Error(jwt.Signature_Error.Key_Too_Short))
	_, hs512 := jwt.encode(payload, .HS512, jwt.Hmac_Key(transmute([]byte)string(SECRET[:63])))
	testing.expect_value(t, hs512, jwt.Error(jwt.Signature_Error.Key_Too_Short))

	token, exact := jwt.encode(payload, .HS256, jwt.Hmac_Key(transmute([]byte)string(SECRET[:32])))
	defer delete(token)
	testing.expect_value(t, exact, nil)
}

@(test)
test_encode_rejects_key_algorithm_mismatch :: proc(t: ^testing.T) {
	priv: ed25519.Private_Key
	pub: ed25519.Public_Key
	load_rfc_8037_keys(t, &priv, &pub)
	payload := transmute([]byte)string(`{}`)

	_, hmac_with_ed := jwt.encode(payload, .HS256, &priv)
	testing.expect_value(t, hmac_with_ed, jwt.Error(jwt.Signature_Error.Key_Algorithm_Mismatch))
	_, ed_with_hmac := jwt.encode(payload, .EdDSA, secret_key())
	testing.expect_value(t, ed_with_hmac, jwt.Error(jwt.Signature_Error.Key_Algorithm_Mismatch))
}

@(test)
test_encode_rejects_public_key :: proc(t: ^testing.T) {
	priv: ed25519.Private_Key
	pub: ed25519.Public_Key
	load_rfc_8037_keys(t, &priv, &pub)

	_, err := jwt.encode(transmute([]byte)string(`{}`), .EdDSA, &pub)
	testing.expect_value(t, err, jwt.Error(jwt.Signature_Error.Key_Cannot_Sign))
}

@(test)
test_encode_rejects_unknown_algorithm :: proc(t: ^testing.T) {
	_, err := jwt.encode(transmute([]byte)string(`{}`), .Unknown, secret_key())
	testing.expect_value(t, err, jwt.Error(jwt.Signature_Error.Unsupported_Algorithm))
}

@(test)
test_encode_rejects_missing_or_uninitialized_keys :: proc(t: ^testing.T) {
	payload := transmute([]byte)string(`{}`)
	_, none := jwt.encode(payload, .HS256, nil)
	testing.expect_value(t, none, jwt.Error(jwt.Signature_Error.Invalid_Key))

	nil_priv: ^ed25519.Private_Key
	_, nil_ptr := jwt.encode(payload, .EdDSA, nil_priv)
	testing.expect_value(t, nil_ptr, jwt.Error(jwt.Signature_Error.Invalid_Key))

	blank: ed25519.Private_Key
	_, uninit := jwt.encode(payload, .EdDSA, &blank)
	testing.expect_value(t, uninit, jwt.Error(jwt.Signature_Error.Invalid_Key))
}

@(test)
test_encode_claims_writes_registered_claims_in_order :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	context.allocator = begin_tracking(&track)
	defer end_tracking(t, &track)

	claims := jwt.Claims {
		iss = "https://issuer.example",
		sub = "alice",
		aud = {"api"},
		exp = 1700000060,
		nbf = 1700000000,
		iat = 1699999999,
		jti = "id-1",
	}
	token, err := jwt.encode_claims(claims, .HS256, secret_key())
	defer delete(token)
	testing.expect_value(t, err, nil)

	payload := decode_payload(token)
	defer delete(payload)
	testing.expect_value(t, payload, `{"iss":"https://issuer.example","sub":"alice","aud":"api","exp":1700000060,"nbf":1700000000,"iat":1699999999,"jti":"id-1"}`)
}

@(test)
test_encode_claims_omits_empty_claims :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	context.allocator = begin_tracking(&track)
	defer end_tracking(t, &track)

	token, err := jwt.encode_claims({}, .HS256, secret_key())
	defer delete(token)
	testing.expect_value(t, err, nil)
	payload := decode_payload(token)
	defer delete(payload)
	testing.expect_value(t, payload, `{}`)

	negative, nerr := jwt.encode_claims({exp = -5}, .HS256, secret_key())
	defer delete(negative)
	testing.expect_value(t, nerr, nil)
	negative_payload := decode_payload(negative)
	defer delete(negative_payload)
	testing.expect_value(t, negative_payload, `{"exp":-5}`)
}

@(test)
test_encode_claims_writes_audience_array :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	context.allocator = begin_tracking(&track)
	defer end_tracking(t, &track)

	token, err := jwt.encode_claims({aud = {"web", "mobile"}, exp = NOW + 60}, .HS256, secret_key())
	defer delete(token)
	testing.expect_value(t, err, nil)
	payload := decode_payload(token)
	defer delete(payload)
	testing.expect_value(t, payload, `{"aud":["web","mobile"],"exp":1700000060}`)

	decoded, derr := jwt.decode(token, secret_key(), {now = NOW, audience = "mobile"})
	defer jwt.token_destroy(&decoded)
	testing.expect_value(t, derr, nil)
	testing.expect_value(t, len(decoded.claims.aud), 2)
}

@(test)
test_encode_claims_escapes_strings :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	context.allocator = begin_tracking(&track)
	defer end_tracking(t, &track)

	sub := "quote\" slash\\ tab\t nl\n ctl\x01 é"
	token, err := jwt.encode_claims({sub = sub, exp = NOW + 60}, .HS256, secret_key())
	defer delete(token)
	testing.expect_value(t, err, nil)

	payload := decode_payload(token)
	defer delete(payload)
	testing.expect_value(t, payload, `{"sub":"quote\" slash\\ tab\t nl\n ctl\u0001 é","exp":1700000060}`)

	decoded, derr := jwt.decode(token, secret_key(), {now = NOW})
	defer jwt.token_destroy(&decoded)
	testing.expect_value(t, derr, nil)
	testing.expect_value(t, decoded.claims.sub, sub)
}

@(test)
test_encode_claims_rejects_invalid_utf8 :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	context.allocator = begin_tracking(&track)
	defer end_tracking(t, &track)

	_, err := jwt.encode_claims({sub = "\xff\xfe", exp = NOW}, .HS256, secret_key())
	testing.expect_value(t, err, jwt.Error(jwt.Format_Error.Invalid_Utf8))
	_, kid := jwt.encode_claims({exp = NOW}, .HS256, secret_key(), kid = "\xc3")
	testing.expect_value(t, kid, jwt.Error(jwt.Format_Error.Invalid_Utf8))
}

@(test)
test_encode_accepts_marshalled_struct :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	context.allocator = begin_tracking(&track)
	defer end_tracking(t, &track)

	Session :: struct {
		sub:   string,
		exp:   i64,
		role:  string,
		admin: bool,
	}
	payload, merr := json.marshal(Session{sub = "alice", exp = NOW + 60, role = "editor", admin = true})
	defer delete(payload)
	testing.expect_value(t, merr, nil)

	token, err := jwt.encode(payload, .HS384, secret_key())
	defer delete(token)
	testing.expect_value(t, err, nil)

	decoded, derr := jwt.decode(token, secret_key(), {now = NOW})
	defer jwt.token_destroy(&decoded)
	testing.expect_value(t, derr, nil)
	role, has_role := jwt.claim_string(&decoded, "role")
	testing.expect(t, has_role)
	testing.expect_value(t, role, "editor")
	admin, has_admin := jwt.claim_bool(&decoded, "admin")
	testing.expect(t, has_admin && admin)
	exp, has_exp := jwt.claim_int(&decoded, "exp")
	testing.expect(t, has_exp)
	testing.expect_value(t, exp, NOW + 60)
}

@(test)
test_eddsa_roundtrip :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	context.allocator = begin_tracking(&track)
	defer end_tracking(t, &track)

	priv: ed25519.Private_Key
	pub: ed25519.Public_Key
	load_rfc_8037_keys(t, &priv, &pub)

	token, err := jwt.encode_claims({sub = "alice", exp = NOW + 60}, .EdDSA, &priv, kid = "ed-1")
	defer delete(token)
	testing.expect_value(t, err, nil)

	decoded, derr := jwt.decode(token, &pub, {now = NOW, subject = "alice"})
	defer jwt.token_destroy(&decoded)
	testing.expect_value(t, derr, nil)
	testing.expect_value(t, decoded.header.alg, jwt.Algorithm.EdDSA)
	testing.expect_value(t, decoded.header.kid, "ed-1")

	// Ed25519 signatures are deterministic, so signing twice gives the same token.
	again, aerr := jwt.encode_claims({sub = "alice", exp = NOW + 60}, .EdDSA, &priv, kid = "ed-1")
	defer delete(again)
	testing.expect_value(t, aerr, nil)
	testing.expect_value(t, again, token)
}

@(test)
test_hmac_roundtrip_every_algorithm :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	context.allocator = begin_tracking(&track)
	defer end_tracking(t, &track)

	for alg in jwt.HMAC_ALGORITHMS {
		token, err := jwt.encode_claims({iss = "me", exp = NOW + 1}, alg, secret_key())
		testing.expect_value(t, err, nil)
		decoded, derr := jwt.decode(token, secret_key(), {now = NOW, issuer = "me", algorithms = {alg}})
		testing.expectf(t, derr == nil, "%v: %v", alg, derr)
		testing.expect_value(t, decoded.header.alg, alg)
		jwt.token_destroy(&decoded)
		delete(token)
	}
}
