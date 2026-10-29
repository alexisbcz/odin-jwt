// Package jwt_tests holds the unit tests for jwt. Run them with `odin test tests`.
package jwt_tests

import jwt ".."
import "base:runtime"
import "core:crypto/ed25519"
import "core:crypto/hash"
import "core:crypto/hmac"
import "core:mem"
import "core:strings"
import "core:testing"

// RFC_7515_KEY is the HMAC key from RFC 7515 appendix A.1, base64url encoded.
RFC_7515_KEY :: "AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"

// RFC_7515_TOKEN is the HS256 JWS from RFC 7515 appendix A.1, also used in RFC 7519 section 3.1.
RFC_7515_TOKEN :: "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ.dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"

// RFC_7515_EXP is the `exp` claim of RFC_7515_TOKEN.
RFC_7515_EXP :: 1300819380

// RFC_8037_SEED is the Ed25519 private key `d` from RFC 8037 appendix A.1, base64url encoded.
RFC_8037_SEED :: "nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A"

// RFC_8037_PUBLIC is the Ed25519 public key `x` from RFC 8037 appendix A.1, base64url encoded.
RFC_8037_PUBLIC :: "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"

// RFC_8037_TOKEN is the EdDSA JWS from RFC 8037 appendix A.4. Its payload isn't JSON.
RFC_8037_TOKEN :: "eyJhbGciOiJFZERTQSJ9.RXhhbXBsZSBvZiBFZDI1NTE5IHNpZ25pbmc.hgyY0il_MGCjP0JzlnLWG1PPOt7-09PGcvMg3AIbQR6dWbhijcNR4ki4iylGjg5BhVsPt9g7sVvpAr_MuM0KAg"

// SECRET is a 64-byte HMAC key, long enough for every HMAC algorithm.
SECRET :: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// NOW is a fixed clock used by most tests.
NOW :: i64(1_700_000_000)

// secret_key returns SECRET as an Hmac_Key. It doesn't allocate.
secret_key :: proc() -> jwt.Hmac_Key {
	return jwt.Hmac_Key(transmute([]byte)string(SECRET))
}

/*
begin_tracking installs a tracking allocator as context.allocator for the
calling test and returns it. Pair it with `defer end_tracking(t, &track)`.
*/
begin_tracking :: proc(track: ^mem.Tracking_Allocator) -> runtime.Allocator {
	mem.tracking_allocator_init(track, context.allocator)
	return mem.tracking_allocator(track)
}

// end_tracking fails the test if anything leaked or was freed twice, then destroys the tracker.
end_tracking :: proc(t: ^testing.T, track: ^mem.Tracking_Allocator, loc := #caller_location) {
	for _, entry in track.allocation_map {
		testing.expectf(t, false, "leaked %v bytes allocated at %v", entry.size, entry.location, loc = loc)
	}
	for entry in track.bad_free_array {
		testing.expectf(t, false, "bad free at %v", entry.location, loc = loc)
	}
	mem.tracking_allocator_destroy(track)
}

// load_rfc_7515_key decodes the RFC 7515 HMAC key; free it with delete.
load_rfc_7515_key :: proc(t: ^testing.T) -> []byte {
	key, err := jwt.base64url_decode(RFC_7515_KEY)
	testing.expect_value(t, err, nil)
	return key
}

// load_rfc_8037_keys initializes the RFC 8037 Ed25519 key pair.
load_rfc_8037_keys :: proc(t: ^testing.T, priv: ^ed25519.Private_Key, pub: ^ed25519.Public_Key) {
	seed, err := jwt.base64url_decode(RFC_8037_SEED)
	testing.expect_value(t, err, nil)
	defer delete(seed)
	public_bytes, perr := jwt.base64url_decode(RFC_8037_PUBLIC)
	testing.expect_value(t, perr, nil)
	defer delete(public_bytes)
	testing.expect(t, ed25519.private_key_set_bytes(priv, seed))
	testing.expect(t, ed25519.public_key_set_bytes(pub, public_bytes))
}

/*
sign_raw builds an HMAC-signed token from arbitrary header and payload text,
bypassing jwt.encode so tests can craft tokens the library would never
produce. Free the result with delete.
*/
sign_raw :: proc(header, payload: string, algorithm := hash.Algorithm.SHA256, key := SECRET) -> string {
	h, _ := jwt.base64url_encode(transmute([]byte)header)
	defer delete(h)
	p, _ := jwt.base64url_encode(transmute([]byte)payload)
	defer delete(p)
	signing_input := strings.concatenate({h, ".", p})
	defer delete(signing_input)

	tag: [64]byte
	size := hash.DIGEST_SIZES[algorithm]
	hmac.sum(algorithm, tag[:size], transmute([]byte)signing_input, transmute([]byte)string(key))
	s, _ := jwt.base64url_encode(tag[:size])
	defer delete(s)
	return strings.concatenate({signing_input, ".", s})
}

// decode_payload returns the decoded payload segment of `token` as a string; free it with delete.
decode_payload :: proc(token: string) -> string {
	parts := strings.split(token, ".")
	defer delete(parts)
	raw, _ := jwt.base64url_decode(parts[1])
	return string(raw)
}

/*
Failing_Allocator passes requests to `backing` until `remaining` allocations
have succeeded, then fails every later allocation or resize with
`.Out_Of_Memory`. Frees always reach `backing`.
*/
Failing_Allocator :: struct {
	backing:   runtime.Allocator,
	remaining: int,
}

// failing_allocator returns an allocator that draws from `f`.
failing_allocator :: proc(f: ^Failing_Allocator) -> runtime.Allocator {
	return {procedure = failing_allocator_proc, data = f}
}

@(private = "file")
failing_allocator_proc :: proc(
	data: rawptr,
	mode: runtime.Allocator_Mode,
	size, alignment: int,
	old_memory: rawptr,
	old_size: int,
	loc := #caller_location,
) -> (
	[]byte,
	runtime.Allocator_Error,
) {
	f := (^Failing_Allocator)(data)
	#partial switch mode {
	case .Alloc, .Alloc_Non_Zeroed, .Resize, .Resize_Non_Zeroed:
		if f.remaining <= 0 {
			return nil, .Out_Of_Memory
		}
		f.remaining -= 1
	}
	return f.backing.procedure(f.backing.data, mode, size, alignment, old_memory, old_size, loc)
}
