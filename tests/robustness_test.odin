package jwt_tests

import jwt ".."
import "base:runtime"
import "core:encoding/json"
import "core:mem"
import "core:strings"
import "core:testing"

@(private = "file")
ROBUST_HEADER :: `{"alg":"HS256","kid":"key-1"}`

// ROBUST_PAYLOAD has nested arrays and objects so that every parser path allocates.
@(private = "file")
ROBUST_PAYLOAD :: `{"iss":"auth","sub":"alice","aud":["a","b","c"],"exp":1700000060,"roles":["x","y"],"o":{"k":["v"]}}`

@(test)
test_decode_survives_allocation_failure_at_every_step :: proc(t: ^testing.T) {
	raw := sign_raw(ROBUST_HEADER, ROBUST_PAYLOAD)
	defer delete(raw)

	succeeded := false
	for budget in 0 ..< 500 {
		track: mem.Tracking_Allocator
		failing := Failing_Allocator{backing = begin_tracking(&track), remaining = budget}
		token, err := jwt.decode(raw, secret_key(), {now = NOW, audience = "c"}, failing_allocator(&failing))
		if err == nil {
			// A success must never hide members dropped by a failed allocation.
			testing.expect_value(t, len(token.claims.aud), 3)
			roles, has_roles := jwt.claim(&token, "roles")
			testing.expect(t, has_roles)
			if arr, ok := roles.(json.Array); ok {
				testing.expect_value(t, len(arr), 2)
			} else {
				testing.expect(t, false, "roles must be an array")
			}
			succeeded = true
		} else {
			testing.expectf(t, err == runtime.Allocator_Error.Out_Of_Memory, "budget %v: want Out_Of_Memory, got %v", budget, err)
			testing.expect(t, token.payload == nil && token.header_object == nil, "failed decode returned memory")
		}
		jwt.token_destroy(&token)
		end_tracking(t, &track)
		if succeeded {
			break
		}
	}
	testing.expect(t, succeeded, "decode never succeeded within the allocation budget")
}

@(test)
test_encode_survives_allocation_failure_at_every_step :: proc(t: ^testing.T) {
	claims := jwt.Claims{iss = "auth", sub = "alice", aud = {"a", "b"}, exp = NOW + 60}
	succeeded := false
	for budget in 0 ..< 500 {
		track: mem.Tracking_Allocator
		failing := Failing_Allocator{backing = begin_tracking(&track), remaining = budget}
		allocator := failing_allocator(&failing)
		token, err := jwt.encode_claims(claims, .HS256, secret_key(), kid = "key-1", allocator = allocator)
		if err == nil {
			delete(token, allocator)
			succeeded = true
		} else {
			testing.expectf(t, err == runtime.Allocator_Error.Out_Of_Memory, "budget %v: want Out_Of_Memory, got %v", budget, err)
		}
		end_tracking(t, &track)
		if succeeded {
			break
		}
	}
	testing.expect(t, succeeded, "encode never succeeded within the allocation budget")
}

// expect_kid_result signs a token whose header has `kid` set to the raw JSON text `kid_json`.
@(private = "file")
expect_kid_result :: proc(t: ^testing.T, kid_json: string, want: jwt.Error, loc := #caller_location) {
	track: mem.Tracking_Allocator
	context.allocator = begin_tracking(&track)
	defer end_tracking(t, &track, loc)

	header := strings.concatenate({`{"alg":"HS256","kid":`, kid_json, `}`})
	defer delete(header)
	raw := sign_raw(header, `{"exp":1700000060}`)
	defer delete(raw)
	token, err := jwt.decode(raw, secret_key(), {now = NOW})
	defer jwt.token_destroy(&token)
	testing.expectf(t, err == want, "kid %s: want %v, got %v", kid_json, want, err, loc = loc)
}

@(test)
test_decode_rejects_lone_surrogate_escapes :: proc(t: ^testing.T) {
	// A lone surrogate has no Unicode value. Accepting it would let two different
	// headers decode to the same kid, because the parser substitutes U+FFFD.
	expect_kid_result(t, `"\ud800"`, jwt.Format_Error.Invalid_Json)
	expect_kid_result(t, `"\uDBFF"`, jwt.Format_Error.Invalid_Json)
	expect_kid_result(t, `"\udc00"`, jwt.Format_Error.Invalid_Json)
	expect_kid_result(t, `"\ud800x"`, jwt.Format_Error.Invalid_Json)
	expect_kid_result(t, `"\ud800A"`, jwt.Format_Error.Invalid_Json)
	expect_kid_result(t, `"\ud800\ud800"`, jwt.Format_Error.Invalid_Json)
	expect_kid_result(t, `"\udc00\ud800"`, jwt.Format_Error.Invalid_Json)
	expect_kid_result(t, `"\ud800\n"`, jwt.Format_Error.Invalid_Json)
}

@(test)
test_decode_accepts_surrogate_pairs :: proc(t: ^testing.T) {
	expect_kid_result(t, `"😀"`, nil)
	expect_kid_result(t, `"😀 ok"`, nil)
	expect_kid_result(t, `"￿"`, nil)
}

