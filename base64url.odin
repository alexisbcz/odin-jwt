package jwt

import "base:runtime"

@(private = "file")
ENCODE_TABLE :: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"

// decode_char maps one base64url character to its 6-bit value, or 0xff when it isn't in the alphabet.
@(private = "file")
decode_char :: #force_inline proc "contextless" (c: byte) -> byte {
	switch c {
	case 'A' ..= 'Z':
		return c - 'A'
	case 'a' ..= 'z':
		return c - 'a' + 26
	case '0' ..= '9':
		return c - '0' + 52
	case '-':
		return 62
	case '_':
		return 63
	}
	return 0xff
}

// base64url_encoded_len returns the length of the unpadded base64url encoding of `n` bytes.
base64url_encoded_len :: proc(n: int) -> int {
	return (n * 8 + 5) / 6
}

/*
base64url_decoded_len returns how many bytes an unpadded base64url string of
`n` characters decodes to. A length of the form `4k + 1` is never valid, and
the result for it is meaningless.
*/
base64url_decoded_len :: proc(n: int) -> int {
	return n * 6 / 8
}

/*
base64url_encode encodes `data` as unpadded base64url (RFC 4648 section 5),
the encoding that JWS uses for every segment.

Returns:
- encoded: a new string owned by the caller; free it with `delete(encoded, allocator)`.
- err: an allocator error.
*/
base64url_encode :: proc(data: []byte, allocator := context.allocator) -> (encoded: string, err: runtime.Allocator_Error) {
	buf := make([]byte, base64url_encoded_len(len(data)), allocator) or_return
	encode_into(buf, data)
	return string(buf), nil
}

/*
base64url_decode decodes unpadded base64url text.

It is strict: padding, whitespace, characters outside the URL-safe alphabet,
impossible lengths and non-zero trailing bits all fail, so every byte string
has exactly one accepted encoding.

Returns:
- decoded: new bytes owned by the caller; free them with `delete(decoded, allocator)`.
- err: `Format_Error.Invalid_Base64` or an allocator error.
*/
base64url_decode :: proc(s: string, allocator := context.allocator) -> (decoded: []byte, err: Error) {
	if len(s) % 4 == 1 {
		return nil, .Invalid_Base64
	}
	buf := make([]byte, base64url_decoded_len(len(s)), allocator) or_return
	if !decode_into(buf, s) {
		delete(buf, allocator)
		return nil, .Invalid_Base64
	}
	return buf, nil
}

// encode_into writes the encoding of `data` to `dst`, which must hold exactly base64url_encoded_len(len(data)) bytes.
@(private)
encode_into :: proc(dst, data: []byte) {
	assert(len(dst) == base64url_encoded_len(len(data)))
	table := ENCODE_TABLE
	di := 0
	i := 0
	for ; i + 3 <= len(data); i += 3 {
		v := u32(data[i]) << 16 | u32(data[i + 1]) << 8 | u32(data[i + 2])
		dst[di + 0] = table[v >> 18 & 0x3f]
		dst[di + 1] = table[v >> 12 & 0x3f]
		dst[di + 2] = table[v >> 6 & 0x3f]
		dst[di + 3] = table[v & 0x3f]
		di += 4
	}
	switch len(data) - i {
	case 1:
		v := u32(data[i]) << 16
		dst[di + 0] = table[v >> 18 & 0x3f]
		dst[di + 1] = table[v >> 12 & 0x3f]
	case 2:
		v := u32(data[i]) << 16 | u32(data[i + 1]) << 8
		dst[di + 0] = table[v >> 18 & 0x3f]
		dst[di + 1] = table[v >> 12 & 0x3f]
		dst[di + 2] = table[v >> 6 & 0x3f]
	}
}

/*
decode_into decodes `s` into `dst`, which must hold exactly
base64url_decoded_len(len(s)) bytes. It returns false on any invalid input,
including a length of the form `4k + 1` and non-zero trailing bits.
*/
@(private)
decode_into :: proc(dst: []byte, s: string) -> bool {
	if len(s) % 4 == 1 || len(dst) != base64url_decoded_len(len(s)) {
		return false
	}
	di := 0
	i := 0
	for ; i + 4 <= len(s); i += 4 {
		a, b, c, d := decode_char(s[i]), decode_char(s[i + 1]), decode_char(s[i + 2]), decode_char(s[i + 3])
		if (a | b | c | d) & 0xc0 != 0 {
			return false
		}
		v := u32(a) << 18 | u32(b) << 12 | u32(c) << 6 | u32(d)
		dst[di + 0] = byte(v >> 16)
		dst[di + 1] = byte(v >> 8)
		dst[di + 2] = byte(v)
		di += 3
	}
	switch len(s) - i {
	case 2:
		a, b := decode_char(s[i]), decode_char(s[i + 1])
		if (a | b) & 0xc0 != 0 || b & 0x0f != 0 {
			return false
		}
		dst[di] = a << 2 | b >> 4
	case 3:
		a, b, c := decode_char(s[i]), decode_char(s[i + 1]), decode_char(s[i + 2])
		if (a | b | c) & 0xc0 != 0 || c & 0x03 != 0 {
			return false
		}
		dst[di + 0] = a << 2 | b >> 4
		dst[di + 1] = b << 4 | c >> 2
	}
	return true
}
