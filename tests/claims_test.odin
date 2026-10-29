package jwt_tests

import jwt ".."
import "core:mem"
import "core:testing"

@(test)
test_algorithm_names_roundtrip :: proc(t: ^testing.T) {
	for alg in jwt.Algorithm {
		if alg == .Unknown {
			testing.expect_value(t, jwt.algorithm_name(alg), "")
			continue
		}
		parsed, err := jwt.algorithm_from_name(jwt.algorithm_name(alg))
		testing.expect_value(t, err, jwt.Signature_Error.None)
		testing.expect_value(t, parsed, alg)
	}
}

@(test)
test_algorithm_from_name_rejects_none_and_unknown :: proc(t: ^testing.T) {
	_, none := jwt.algorithm_from_name("nOnE")
	testing.expect_value(t, none, jwt.Signature_Error.Algorithm_None)
	_, lower := jwt.algorithm_from_name("hs256")
	testing.expect_value(t, lower, jwt.Signature_Error.Unsupported_Algorithm)
	_, rsa := jwt.algorithm_from_name("RS256")
	testing.expect_value(t, rsa, jwt.Signature_Error.Unsupported_Algorithm)
	_, empty := jwt.algorithm_from_name("")
	testing.expect_value(t, empty, jwt.Signature_Error.Missing_Algorithm)
}

@(test)
test_key_algorithms_follow_key_type :: proc(t: ^testing.T) {
	testing.expect_value(t, jwt.key_algorithms(secret_key()), jwt.HMAC_ALGORITHMS)
	testing.expect_value(t, jwt.key_algorithms(nil), jwt.Algorithms{})
}

@(test)
test_validate_requires_exp_by_default :: proc(t: ^testing.T) {
	testing.expect_value(t, jwt.validate_claims({sub = "alice"}, {now = NOW}), jwt.Claim_Error.Missing_Claim)
	testing.expect_value(t, jwt.validate_claims({sub = "alice"}, {now = NOW, allow_missing_exp = true}), jwt.Claim_Error.None)
}

@(test)
test_validate_exp_boundary :: proc(t: ^testing.T) {
	testing.expect_value(t, jwt.validate_claims({exp = NOW + 1}, {now = NOW}), jwt.Claim_Error.None)
	testing.expect_value(t, jwt.validate_claims({exp = NOW}, {now = NOW}), jwt.Claim_Error.Expired)
	testing.expect_value(t, jwt.validate_claims({exp = NOW - 1}, {now = NOW}), jwt.Claim_Error.Expired)
}

@(test)
test_validate_exp_with_leeway :: proc(t: ^testing.T) {
	testing.expect_value(t, jwt.validate_claims({exp = NOW - 30}, {now = NOW, leeway = 31}), jwt.Claim_Error.None)
	testing.expect_value(t, jwt.validate_claims({exp = NOW - 30}, {now = NOW, leeway = 30}), jwt.Claim_Error.Expired)
}

@(test)
test_validate_nbf :: proc(t: ^testing.T) {
	base := jwt.Validation{now = NOW, allow_missing_exp = true}
	testing.expect_value(t, jwt.validate_claims({nbf = NOW}, base), jwt.Claim_Error.None)
	testing.expect_value(t, jwt.validate_claims({nbf = NOW + 1}, base), jwt.Claim_Error.Not_Yet_Valid)

	lenient := base
	lenient.leeway = 5
	testing.expect_value(t, jwt.validate_claims({nbf = NOW + 5}, lenient), jwt.Claim_Error.None)
	testing.expect_value(t, jwt.validate_claims({nbf = NOW + 6}, lenient), jwt.Claim_Error.Not_Yet_Valid)
}

@(test)
test_validate_rejects_iat_in_the_future :: proc(t: ^testing.T) {
	base := jwt.Validation{now = NOW, allow_missing_exp = true}
	testing.expect_value(t, jwt.validate_claims({iat = NOW}, base), jwt.Claim_Error.None)
	testing.expect_value(t, jwt.validate_claims({iat = NOW + 60}, base), jwt.Claim_Error.Issued_In_Future)

	lenient := base
	lenient.leeway = 60
	testing.expect_value(t, jwt.validate_claims({iat = NOW + 60}, lenient), jwt.Claim_Error.None)
}

@(test)
test_validate_issuer :: proc(t: ^testing.T) {
	v := jwt.Validation{now = NOW, allow_missing_exp = true, issuer = "https://auth.example"}
	testing.expect_value(t, jwt.validate_claims({iss = "https://auth.example"}, v), jwt.Claim_Error.None)
	testing.expect_value(t, jwt.validate_claims({iss = "https://evil.example"}, v), jwt.Claim_Error.Invalid_Issuer)
	testing.expect_value(t, jwt.validate_claims({}, v), jwt.Claim_Error.Invalid_Issuer)
}

@(test)
test_validate_subject :: proc(t: ^testing.T) {
	v := jwt.Validation{now = NOW, allow_missing_exp = true, subject = "alice"}
	testing.expect_value(t, jwt.validate_claims({sub = "alice"}, v), jwt.Claim_Error.None)
	testing.expect_value(t, jwt.validate_claims({sub = "bob"}, v), jwt.Claim_Error.Invalid_Subject)
}

@(test)
test_validate_audience :: proc(t: ^testing.T) {
	v := jwt.Validation{now = NOW, allow_missing_exp = true, audience = "api"}
	testing.expect_value(t, jwt.validate_claims({aud = {"api"}}, v), jwt.Claim_Error.None)
	testing.expect_value(t, jwt.validate_claims({aud = {"web", "api"}}, v), jwt.Claim_Error.None)
	testing.expect_value(t, jwt.validate_claims({aud = {"web"}}, v), jwt.Claim_Error.Invalid_Audience)
	testing.expect_value(t, jwt.validate_claims({aud = {"API"}}, v), jwt.Claim_Error.Invalid_Audience)
	testing.expect_value(t, jwt.validate_claims({}, v), jwt.Claim_Error.Invalid_Audience)
}

@(test)
test_validate_rejects_unexpected_audience :: proc(t: ^testing.T) {
	// RFC 7519 section 4.1.3: a recipient that isn't named in a present aud must reject the token.
	v := jwt.Validation{now = NOW, allow_missing_exp = true}
	testing.expect_value(t, jwt.validate_claims({aud = {"api"}}, v), jwt.Claim_Error.Invalid_Audience)
}

@(test)
test_validate_required_claims :: proc(t: ^testing.T) {
	v := jwt.Validation{now = NOW, required = {.Iat, .Jti}}
	testing.expect_value(t, jwt.validate_claims({exp = NOW + 1, iat = NOW}, v), jwt.Claim_Error.Missing_Claim)
	testing.expect_value(t, jwt.validate_claims({exp = NOW + 1, iat = NOW, jti = "x"}, v), jwt.Claim_Error.None)
}

@(test)
test_validate_rejects_negative_leeway :: proc(t: ^testing.T) {
	testing.expect_value(t, jwt.validate_claims({exp = NOW + 100}, {now = NOW, leeway = -1}), jwt.Claim_Error.Invalid_Leeway)
}

@(test)
test_validate_saturates_extreme_values :: proc(t: ^testing.T) {
	testing.expect_value(t, jwt.validate_claims({exp = max(i64)}, {now = NOW}), jwt.Claim_Error.None)
	testing.expect_value(t, jwt.validate_claims({exp = min(i64)}, {now = NOW, leeway = max(i64)}), jwt.Claim_Error.Expired)
	// now - leeway would wrap around to a small positive number and wrongly expire the token.
	testing.expect_value(t, jwt.validate_claims({exp = min(i64) + 1}, {now = min(i64) + 1, leeway = max(i64)}), jwt.Claim_Error.None)
	testing.expect_value(t, jwt.validate_claims({exp = NOW + 1, nbf = max(i64)}, {now = NOW, leeway = max(i64)}), jwt.Claim_Error.None)
	testing.expect_value(t, jwt.validate_claims({exp = max(i64), nbf = max(i64)}, {now = max(i64) - 1}), jwt.Claim_Error.Not_Yet_Valid)
}

@(test)
test_validate_uses_system_clock_by_default :: proc(t: ^testing.T) {
	testing.expect_value(t, jwt.validate_claims({exp = 1}, {}), jwt.Claim_Error.Expired)
	testing.expect_value(t, jwt.validate_claims({exp = 99_999_999_999}, {}), jwt.Claim_Error.None)
}

@(private = "file")
expect_claim_type_error :: proc(t: ^testing.T, payload: string, loc := #caller_location) {
	track: mem.Tracking_Allocator
	context.allocator = begin_tracking(&track)
	defer end_tracking(t, &track, loc)

	raw := sign_raw(`{"alg":"HS256"}`, payload)
	defer delete(raw)
	_, err := jwt.decode(raw, secret_key(), {now = NOW})
	testing.expectf(t, err == jwt.Error(jwt.Claim_Error.Invalid_Claim_Type), "%s: got %v", payload, err, loc = loc)
}

@(test)
test_decode_rejects_badly_typed_time_claims :: proc(t: ^testing.T) {
	expect_claim_type_error(t, `{"exp":"1700000060"}`)
	expect_claim_type_error(t, `{"exp":null}`)
	expect_claim_type_error(t, `{"exp":1700000060,"nbf":true}`)
	expect_claim_type_error(t, `{"exp":1700000060,"iat":[1]}`)
	expect_claim_type_error(t, `{"exp":1e300}`)
	expect_claim_type_error(t, `{"exp":-1e300}`)
}

@(test)
test_decode_rejects_badly_typed_string_claims :: proc(t: ^testing.T) {
	expect_claim_type_error(t, `{"exp":1700000060,"iss":null}`)
	expect_claim_type_error(t, `{"exp":1700000060,"sub":42}`)
	expect_claim_type_error(t, `{"exp":1700000060,"jti":{}}`)
}

@(test)
test_decode_rejects_badly_typed_audience :: proc(t: ^testing.T) {
	expect_claim_type_error(t, `{"exp":1700000060,"aud":1}`)
	expect_claim_type_error(t, `{"exp":1700000060,"aud":["api",1]}`)
	expect_claim_type_error(t, `{"exp":1700000060,"aud":{"api":true}}`)
}

@(test)
test_decode_rounds_fractional_numeric_dates_down :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	context.allocator = begin_tracking(&track)
	defer end_tracking(t, &track)

	raw := sign_raw(`{"alg":"HS256"}`, `{"exp":1700000060.9,"nbf":-0.5}`)
	defer delete(raw)
	token, err := jwt.decode(raw, secret_key(), {now = NOW})
	defer jwt.token_destroy(&token)
	testing.expect_value(t, err, nil)
	testing.expect_value(t, token.claims.exp.?, 1700000060)
	testing.expect_value(t, token.claims.nbf.?, -1)
}

@(test)
test_decode_reports_claim_errors_after_signature :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	context.allocator = begin_tracking(&track)
	defer end_tracking(t, &track)

	raw := sign_raw(`{"alg":"HS256"}`, `{"iss":"someone","exp":1700000060}`)
	defer delete(raw)
	token, err := jwt.decode(raw, secret_key(), {now = NOW, issuer = "me"})
	testing.expect_value(t, err, jwt.Error(jwt.Claim_Error.Invalid_Issuer))
	testing.expect(t, token.payload == nil)
}

@(test)
test_decode_rejects_integers_beyond_i64 :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	context.allocator = begin_tracking(&track)
	defer end_tracking(t, &track)

	// core:encoding/json would silently wrap these, so they never reach it.
	for payload in ([]string{`{"exp":99999999999999999999}`, `{"exp":1700000060,"n":-9223372036854775809}`}) {
		raw := sign_raw(`{"alg":"HS256"}`, payload)
		_, err := jwt.decode(raw, secret_key(), {now = NOW})
		testing.expectf(t, err == jwt.Error(jwt.Format_Error.Invalid_Json), "%s: got %v", payload, err)
		delete(raw)
	}

	raw := sign_raw(`{"alg":"HS256"}`, `{"exp":9223372036854775807,"n":-9223372036854775808}`)
	defer delete(raw)
	token, err := jwt.decode(raw, secret_key(), {now = NOW})
	defer jwt.token_destroy(&token)
	testing.expect_value(t, err, nil)
	n, ok := jwt.claim_int(&token, "n")
	testing.expect(t, ok)
	testing.expect_value(t, n, min(i64))
}
