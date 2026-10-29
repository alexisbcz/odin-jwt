// Example eddsa signs with an Ed25519 private key and verifies with the public key. Run it with `odin run examples/eddsa`.
package main

import jwt "../.."
import "core:crypto/ed25519"
import "core:fmt"
import "core:os"
import "core:time"

main :: proc() {
	// The issuer keeps the private key; verifiers only need the public key.
	priv: ed25519.Private_Key
	if !ed25519.private_key_generate(&priv) {
		fmt.eprintln("no entropy source")
		os.exit(1)
	}
	defer ed25519.private_key_clear(&priv)

	pub: ed25519.Public_Key
	ed25519.public_key_set_priv(&pub, &priv)

	now := time.to_unix_seconds(time.now())
	token, err := jwt.encode_claims({sub = "device-42", aud = {"telemetry"}, exp = now + 3600, iat = now}, .EdDSA, &priv, kid = "2026-10")
	if err != nil {
		fmt.eprintln("encode failed:", err)
		os.exit(1)
	}
	defer delete(token)
	fmt.println("token:", token)

	// Read the key id first when you rotate keys, then verify with the matching key.
	peek, perr := jwt.decode_unverified(token)
	if perr != nil {
		fmt.eprintln("malformed token:", perr)
		os.exit(1)
	}
	fmt.println("signed with key:", peek.header.kid)
	jwt.token_destroy(&peek)

	decoded, derr := jwt.decode(token, &pub, {audience = "telemetry"})
	if derr != nil {
		fmt.eprintln("decode failed:", derr)
		os.exit(1)
	}
	defer jwt.token_destroy(&decoded)
	fmt.println("verified subject:", decoded.claims.sub)

	// An HMAC key never verifies an EdDSA token, which blocks algorithm confusion.
	_, confused := jwt.decode(token, jwt.Hmac_Key(transmute([]byte)string("an-hmac-secret-of-32-bytes-long!")))
	fmt.println("with an HMAC key:", confused)
}
