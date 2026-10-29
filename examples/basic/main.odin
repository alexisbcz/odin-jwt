// Example basic issues and verifies an HS256 token. Run it with `odin run examples/basic`.
package main

import jwt "../.."
import "core:encoding/json"
import "core:fmt"
import "core:os"
import "core:time"

// Session is the claims set this service puts in its tokens: registered claims plus private ones.
Session :: struct {
	iss:  string,
	sub:  string,
	aud:  string,
	exp:  i64,
	iat:  i64,
	role: string,
}

main :: proc() {
	// In production, load at least 32 random bytes from a secret store.
	key := jwt.Hmac_Key(transmute([]byte)string("replace-me-with-32-random-bytes!!"))
	now := time.to_unix_seconds(time.now())

	// Issue a token. Marshal any struct to add private claims such as `role`.
	payload, merr := json.marshal(Session {
		iss = "https://auth.example.com",
		sub = "alice",
		aud = "api",
		exp = now + 15 * 60,
		iat = now,
		role = "editor",
	})
	if merr != nil {
		fmt.eprintln("marshal failed:", merr)
		os.exit(1)
	}
	defer delete(payload)

	token, err := jwt.encode(payload, .HS256, key)
	if err != nil {
		fmt.eprintln("encode failed:", err)
		os.exit(1)
	}
	defer delete(token)
	fmt.println("token:", token)

	// Verify it. The rules say who must have issued it and who it is for.
	rules := jwt.Validation {
		issuer     = "https://auth.example.com",
		audience   = "api",
		leeway     = 30,
		algorithms = {.HS256},
	}
	decoded, derr := jwt.decode(token, key, rules)
	if derr != nil {
		fmt.eprintln("decode failed:", derr)
		os.exit(1)
	}
	defer jwt.token_destroy(&decoded)

	role, _ := jwt.claim_string(&decoded, "role")
	fmt.printfln("verified: sub=%s role=%s expires in %vs", decoded.claims.sub, role, decoded.claims.exp.? - now)

	// Failures come back as error values that print well.
	expired, _ := jwt.encode_claims({sub = "bob", exp = now - 3600}, .HS256, key)
	defer delete(expired)
	_, expired_err := jwt.decode(expired, key)
	fmt.println("expired token:", expired_err)

	unsecured := "eyJhbGciOiJub25lIn0.eyJzdWIiOiJtYWxsb3J5In0."
	_, none_err := jwt.decode(unsecured, key)
	fmt.println("alg=none token:", none_err)
}
