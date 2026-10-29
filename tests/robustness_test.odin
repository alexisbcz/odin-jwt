package jwt_tests

import jwt ".."
import "base:runtime"
import "core:encoding/json"
import "core:mem"
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
