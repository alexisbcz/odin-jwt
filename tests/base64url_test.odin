package jwt_tests

import jwt ".."
import "core:mem"
import "core:testing"

@(test)
test_base64url_encode_rfc4648_vectors :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	context.allocator = begin_tracking(&track)
	defer end_tracking(t, &track)

	// RFC 4648 section 10, without padding.
	cases := [][2]string{{"", ""}, {"f", "Zg"}, {"fo", "Zm8"}, {"foo", "Zm9v"}, {"foob", "Zm9vYg"}, {"fooba", "Zm9vYmE"}, {"foobar", "Zm9vYmFy"}}
	for c in cases {
		encoded, err := jwt.base64url_encode(transmute([]byte)c[0])
		testing.expect_value(t, err, nil)
		testing.expect_value(t, encoded, c[1])
		delete(encoded)
	}
}

@(test)
test_base64url_encode_uses_url_safe_alphabet :: proc(t: ^testing.T) {
	data := []byte{0xfb, 0xff, 0xbf}
	encoded, err := jwt.base64url_encode(data)
	defer delete(encoded)
	testing.expect_value(t, err, nil)
	testing.expect_value(t, encoded, "-_-_")
}

@(test)
test_base64url_roundtrips_every_length :: proc(t: ^testing.T) {
	track: mem.Tracking_Allocator
	context.allocator = begin_tracking(&track)
	defer end_tracking(t, &track)

	data: [40]byte
	for i in 0 ..< len(data) {
		data[i] = byte(i * 37 + 11)
	}
	for n in 0 ..= len(data) {
		encoded, err := jwt.base64url_encode(data[:n])
		testing.expect_value(t, err, nil)
		testing.expect_value(t, len(encoded), jwt.base64url_encoded_len(n))
		decoded, derr := jwt.base64url_decode(encoded)
		testing.expect_value(t, derr, nil)
		testing.expect(t, string(decoded) == string(data[:n]), "roundtrip mismatch")
		delete(encoded)
		delete(decoded)
	}
}

@(test)
test_base64url_decode_rejects_padding :: proc(t: ^testing.T) {
	decoded, err := jwt.base64url_decode("Zg==")
	testing.expect_value(t, err, jwt.Error(jwt.Format_Error.Invalid_Base64))
	testing.expect(t, decoded == nil)
}

@(test)
test_base64url_decode_rejects_standard_alphabet :: proc(t: ^testing.T) {
	_, plus := jwt.base64url_decode("+/+/")
	testing.expect_value(t, plus, jwt.Error(jwt.Format_Error.Invalid_Base64))
	_, slash := jwt.base64url_decode("ab/c")
	testing.expect_value(t, slash, jwt.Error(jwt.Format_Error.Invalid_Base64))
}

@(test)
test_base64url_decode_rejects_impossible_length :: proc(t: ^testing.T) {
	_, one := jwt.base64url_decode("A")
	testing.expect_value(t, one, jwt.Error(jwt.Format_Error.Invalid_Base64))
	_, five := jwt.base64url_decode("Zm9vY")
	testing.expect_value(t, five, jwt.Error(jwt.Format_Error.Invalid_Base64))
}

@(test)
test_base64url_decode_rejects_nonzero_trailing_bits :: proc(t: ^testing.T) {
	// "Zg" is the canonical encoding of "f"; "Zh" carries a stray low bit.
	_, two := jwt.base64url_decode("Zh")
	testing.expect_value(t, two, jwt.Error(jwt.Format_Error.Invalid_Base64))
	// "Zm8" is the canonical encoding of "fo"; "Zm9" carries stray low bits.
	_, three := jwt.base64url_decode("Zm9")
	testing.expect_value(t, three, jwt.Error(jwt.Format_Error.Invalid_Base64))
}

@(test)
test_base64url_decode_rejects_whitespace_and_dots :: proc(t: ^testing.T) {
	for input in ([]string{"Zm9v Yg", "Zm9v\nYg", "Zm.v", "Zm9v\x00"}) {
		_, err := jwt.base64url_decode(input)
		testing.expectf(t, err == jwt.Error(jwt.Format_Error.Invalid_Base64), "%q: got %v", input, err)
	}
}
