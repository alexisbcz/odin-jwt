package jwt_tests

import jwt ".."
import "core:crypto/ed25519"
import "core:mem"
import "core:strings"
import "core:testing"

@(test)
test_rfc7515_a1_hs256_token_decodes :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	context.allocator = begin_tracking(&track)
	defer end_tracking(t, &track)

	key := load_rfc_7515_key(t)
	defer delete(key)

	token, err := jwt.decode(RFC_7515_TOKEN, jwt.Hmac_Key(key), {now = RFC_7515_EXP - 10})
	defer jwt.token_destroy(&token)
	testing.expect_value(t, err, nil)
	testing.expect_value(t, token.header.alg, jwt.Algorithm.HS256)
	testing.expect_value(t, token.header.typ, "JWT")
	testing.expect_value(t, token.claims.iss, "joe")
	testing.expect_value(t, token.claims.exp.?, RFC_7515_EXP)
}

@(test)
test_rfc7515_a1_private_claim_is_readable :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	context.allocator = begin_tracking(&track)
	defer end_tracking(t, &track)

	key := load_rfc_7515_key(t)
	defer delete(key)

	token, err := jwt.decode(RFC_7515_TOKEN, jwt.Hmac_Key(key), {now = RFC_7515_EXP - 10})
	defer jwt.token_destroy(&token)
	testing.expect_value(t, err, nil)
	is_root, ok := jwt.claim_bool(&token, "http://example.com/is_root")
	testing.expect(t, ok)
	testing.expect(t, is_root)
	_, missing := jwt.claim_bool(&token, "is_admin")
	testing.expect(t, !missing)
	_, wrong_type := jwt.claim_int(&token, "iss")
	testing.expect(t, !wrong_type)
}

@(test)
test_rfc7515_a1_token_expires_at_exp :: proc(t: ^testing.T) {
	key := load_rfc_7515_key(t)
	defer delete(key)

	token, err := jwt.decode(RFC_7515_TOKEN, jwt.Hmac_Key(key), {now = RFC_7515_EXP})
	testing.expect_value(t, err, jwt.Error(jwt.Claim_Error.Expired))
	testing.expect(t, token.payload == nil, "a failed decode must not hand back memory")
}

@(test)
test_rfc7515_a1_tampered_payload_is_rejected :: proc(t: ^testing.T) {
	key := load_rfc_7515_key(t)
	defer delete(key)

	// Replace the payload with {"iss":"joe","exp":9999999999} under the original signature.
	parts := strings.split(RFC_7515_TOKEN, ".")
	defer delete(parts)
	forged_payload, _ := jwt.base64url_encode(transmute([]byte)string(`{"iss":"joe","exp":9999999999}`))
	defer delete(forged_payload)
	forged := strings.join({parts[0], forged_payload, parts[2]}, ".")
	defer delete(forged)

	_, err := jwt.decode(forged, jwt.Hmac_Key(key), {now = RFC_7515_EXP - 10})
	testing.expect_value(t, err, jwt.Error(jwt.Signature_Error.Invalid_Signature))
}

@(test)
test_rfc7515_a5_unsecured_token_is_rejected :: proc(t: ^testing.T) {
	// RFC 7515 appendix A.5: {"alg":"none"} with an empty signature.
	UNSECURED :: "eyJhbGciOiJub25lIn0.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ."
	_, err := jwt.decode(UNSECURED, secret_key(), {now = RFC_7515_EXP - 10})
	testing.expect_value(t, err, jwt.Error(jwt.Signature_Error.Algorithm_None))

	_, unverified := jwt.decode_unverified(UNSECURED)
	testing.expect_value(t, unverified, jwt.Error(jwt.Signature_Error.Algorithm_None))
}

@(test)
test_rfc8037_a4_eddsa_signature_verifies :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	context.allocator = begin_tracking(&track)
	defer end_tracking(t, &track)

	priv: ed25519.Private_Key
	pub: ed25519.Public_Key
	load_rfc_8037_keys(t, &priv, &pub)

	testing.expect_value(t, jwt.verify_signature(RFC_8037_TOKEN, &pub), nil)
	// A private key verifies through its public half.
	testing.expect_value(t, jwt.verify_signature(RFC_8037_TOKEN, &priv), nil)
}

@(test)
test_rfc8037_a4_public_key_matches_seed :: proc(t: ^testing.T) {
	priv: ed25519.Private_Key
	pub: ed25519.Public_Key
	load_rfc_8037_keys(t, &priv, &pub)

	derived: ed25519.Public_Key
	ed25519.public_key_set_priv(&derived, &priv)
	testing.expect(t, ed25519.public_key_equal(&derived, &pub))
}

@(test)
test_rfc8037_a4_tampered_signature_is_rejected :: proc(t: ^testing.T) {
	priv: ed25519.Private_Key
	pub: ed25519.Public_Key
	load_rfc_8037_keys(t, &priv, &pub)

	tampered := strings.clone(RFC_8037_TOKEN)
	defer delete(tampered)
	bytes := transmute([]byte)tampered
	// Flip a character in the middle of the signature segment.
	i := len(bytes) - 20
	bytes[i] = 'A' if bytes[i] != 'A' else 'B'

	testing.expect_value(t, jwt.verify_signature(tampered, &pub), jwt.Error(jwt.Signature_Error.Invalid_Signature))
}
