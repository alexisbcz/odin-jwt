package jwt

import "core:time"

// Registered_Claim names one registered claim of RFC 7519 section 4.1.
Registered_Claim :: enum u8 {
	Iss,
	Sub,
	Aud,
	Exp,
	Nbf,
	Iat,
	Jti,
}

// Registered_Claims is a set of registered claims, used by `Validation.required`.
Registered_Claims :: bit_set[Registered_Claim]

/*
Validation holds the rules that decode and validate_claims apply.

The zero value is a safe default: it requires a valid `exp`, uses the system
clock, allows no leeway, rejects any token that carries `aud`, and accepts
every algorithm the key supports.
*/
Validation :: struct {
	// now is the current time in Unix seconds. nil means the system clock.
	now:               Maybe(i64),
	// leeway is the clock skew, in seconds, allowed when checking exp, nbf and iat. Must not be negative.
	leeway:            i64,
	// issuer, when not empty, must equal the `iss` claim.
	issuer:            string,
	// audience, when not empty, must appear in the `aud` claim. When empty, a token with `aud` is rejected.
	audience:          string,
	// subject, when not empty, must equal the `sub` claim.
	subject:           string,
	// required lists claims that must be present, in addition to `exp`.
	required:          Registered_Claims,
	// allow_missing_exp accepts tokens without `exp`. A present `exp` is always checked.
	allow_missing_exp: bool,
	// algorithms restricts the accepted algorithms. An empty set allows every algorithm the key supports.
	algorithms:        Algorithms,
	// max_token_size is the size limit in bytes. 0 means `DEFAULT_MAX_TOKEN_SIZE`.
	max_token_size:    int,
}

/*
validate_claims checks registered claims against `validation`.

decode calls it for you. Call it yourself after decode_unverified once you
have verified the token some other way.

The checks follow RFC 7519 section 4.1 and run in this order: required
claims, `exp`, `nbf`, `iat`, `iss`, `sub`, then `aud`.

- A token is expired when `now - leeway >= exp`.
- A token isn't valid yet when `now + leeway < nbf`.
- A token was issued in the future when `now + leeway < iat`.

Returns:
- err: nil when every check passes, otherwise the first failing `Claim_Error`.
*/
validate_claims :: proc(claims: Claims, validation: Validation) -> Claim_Error {
	if validation.leeway < 0 {
		return .Invalid_Leeway
	}

	required := validation.required
	if !validation.allow_missing_exp {
		required += {.Exp}
	}
	present: Registered_Claims
	if claims.iss != "" {
		present += {.Iss}
	}
	if claims.sub != "" {
		present += {.Sub}
	}
	if len(claims.aud) > 0 {
		present += {.Aud}
	}
	if claims.exp != nil {
		present += {.Exp}
	}
	if claims.nbf != nil {
		present += {.Nbf}
	}
	if claims.iat != nil {
		present += {.Iat}
	}
	if claims.jti != "" {
		present += {.Jti}
	}
	if required - present != {} {
		return .Missing_Claim
	}

	now, has_now := validation.now.?
	if !has_now {
		now = time.to_unix_seconds(time.now())
	}
	leeway := validation.leeway

	if exp, ok := claims.exp.?; ok && saturating_sub(now, leeway) >= exp {
		return .Expired
	}
	if nbf, ok := claims.nbf.?; ok && saturating_add(now, leeway) < nbf {
		return .Not_Yet_Valid
	}
	if iat, ok := claims.iat.?; ok && saturating_add(now, leeway) < iat {
		return .Issued_In_Future
	}
	if validation.issuer != "" && claims.iss != validation.issuer {
		return .Invalid_Issuer
	}
	if validation.subject != "" && claims.sub != validation.subject {
		return .Invalid_Subject
	}
	if validation.audience == "" {
		if len(claims.aud) > 0 {
			return .Invalid_Audience
		}
	} else {
		found := false
		for aud in claims.aud {
			if aud == validation.audience {
				found = true
				break
			}
		}
		if !found {
			return .Invalid_Audience
		}
	}
	return .None
}

@(private = "file")
saturating_add :: proc(a, b: i64) -> i64 {
	if b > 0 && a > max(i64) - b {
		return max(i64)
	}
	return a + b
}

@(private = "file")
saturating_sub :: proc(a, b: i64) -> i64 {
	if b > 0 && a < min(i64) + b {
		return min(i64)
	}
	return a - b
}
