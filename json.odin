package jwt

import "base:runtime"
import "core:encoding/json"
import "core:unicode/utf8"

// MAX_JSON_DEPTH is the deepest nesting of arrays and objects that a header or payload may use.
MAX_JSON_DEPTH :: 32

/*
validate_json reports whether `data` is exactly one RFC 8259 JSON value with
optional surrounding whitespace.

It runs before `core:encoding/json` sees untrusted input, so the parser only
ever handles well-formed text. It rejects what that parser would let through
or mishandle: trailing commas, comments, single quotes, unquoted keys, bare
control characters, invalid escapes, invalid UTF-8, malformed numbers,
integers outside the i64 range, which the parser would silently wrap, and
nesting deeper than MAX_JSON_DEPTH. It doesn't allocate.
*/
@(private)
validate_json :: proc(data: []byte) -> bool {
	if !utf8.valid_string(string(data)) {
		return false
	}
	v := Json_Validator{data = data}
	skip_ws(&v)
	if !validate_value(&v, 0) {
		return false
	}
	skip_ws(&v)
	return v.pos == len(v.data)
}

@(private = "file")
Json_Validator :: struct {
	data: []byte,
	pos:  int,
}

@(private = "file")
peek :: proc(v: ^Json_Validator) -> byte {
	return v.data[v.pos] if v.pos < len(v.data) else 0
}

@(private = "file")
skip_ws :: proc(v: ^Json_Validator) {
	for v.pos < len(v.data) {
		switch v.data[v.pos] {
		case ' ', '\t', '\n', '\r':
			v.pos += 1
		case:
			return
		}
	}
}

@(private = "file")
expect_literal :: proc(v: ^Json_Validator, lit: string) -> bool {
	if len(v.data) - v.pos < len(lit) || string(v.data[v.pos:][:len(lit)]) != lit {
		return false
	}
	v.pos += len(lit)
	return true
}

@(private = "file")
validate_value :: proc(v: ^Json_Validator, depth: int) -> bool {
	switch peek(v) {
	case '{':
		return validate_object(v, depth + 1)
	case '[':
		return validate_array(v, depth + 1)
	case '"':
		return validate_string(v)
	case 't':
		return expect_literal(v, "true")
	case 'f':
		return expect_literal(v, "false")
	case 'n':
		return expect_literal(v, "null")
	case '-', '0' ..= '9':
		return validate_number(v)
	}
	return false
}

@(private = "file")
validate_object :: proc(v: ^Json_Validator, depth: int) -> bool {
	if depth > MAX_JSON_DEPTH {
		return false
	}
	v.pos += 1 // '{'
	skip_ws(v)
	if peek(v) == '}' {
		v.pos += 1
		return true
	}
	for {
		skip_ws(v)
		if peek(v) != '"' || !validate_string(v) {
			return false
		}
		skip_ws(v)
		if peek(v) != ':' {
			return false
		}
		v.pos += 1
		skip_ws(v)
		if !validate_value(v, depth) {
			return false
		}
		skip_ws(v)
		switch peek(v) {
		case ',':
			v.pos += 1
		case '}':
			v.pos += 1
			return true
		case:
			return false
		}
	}
}

@(private = "file")
validate_array :: proc(v: ^Json_Validator, depth: int) -> bool {
	if depth > MAX_JSON_DEPTH {
		return false
	}
	v.pos += 1 // '['
	skip_ws(v)
	if peek(v) == ']' {
		v.pos += 1
		return true
	}
	for {
		skip_ws(v)
		if !validate_value(v, depth) {
			return false
		}
		skip_ws(v)
		switch peek(v) {
		case ',':
			v.pos += 1
		case ']':
			v.pos += 1
			return true
		case:
			return false
		}
	}
}

@(private = "file")
is_hex :: proc(c: byte) -> bool {
	switch c {
	case '0' ..= '9', 'a' ..= 'f', 'A' ..= 'F':
		return true
	}
	return false
}

@(private = "file")
validate_string :: proc(v: ^Json_Validator) -> bool {
	v.pos += 1 // opening quote
	for v.pos < len(v.data) {
		c := v.data[v.pos]
		switch c {
		case '"':
			v.pos += 1
			return true
		case '\\':
			v.pos += 1
			switch peek(v) {
			case '"', '\\', '/', 'b', 'f', 'n', 'r', 't':
				v.pos += 1
			case 'u':
				if len(v.data) - v.pos < 5 {
					return false
				}
				for i in 1 ..= 4 {
					if !is_hex(v.data[v.pos + i]) {
						return false
					}
				}
				v.pos += 5
			case:
				return false
			}
		case 0x00 ..< 0x20:
			return false
		case:
			v.pos += 1
		}
	}
	return false
}

@(private = "file")
validate_digits :: proc(v: ^Json_Validator) -> bool {
	start := v.pos
	for v.pos < len(v.data) && '0' <= v.data[v.pos] && v.data[v.pos] <= '9' {
		v.pos += 1
	}
	return v.pos > start
}

@(private = "file")
validate_number :: proc(v: ^Json_Validator) -> bool {
	start := v.pos
	is_integer := true
	if peek(v) == '-' {
		v.pos += 1
	}
	switch peek(v) {
	case '0':
		v.pos += 1
	case '1' ..= '9':
		validate_digits(v)
	case:
		return false
	}
	if peek(v) == '.' {
		is_integer = false
		v.pos += 1
		if !validate_digits(v) {
			return false
		}
	}
	if c := peek(v); c == 'e' || c == 'E' {
		is_integer = false
		v.pos += 1
		if c2 := peek(v); c2 == '+' || c2 == '-' {
			v.pos += 1
		}
		if !validate_digits(v) {
			return false
		}
	}
	return !is_integer || integer_fits_i64(string(v.data[start:v.pos]))
}

// integer_fits_i64 reports whether a syntactically valid JSON integer lies in the i64 range.
@(private = "file")
integer_fits_i64 :: proc(text: string) -> bool {
	digits := text
	limit := "9223372036854775807"
	if len(digits) > 0 && digits[0] == '-' {
		digits = digits[1:]
		limit = "9223372036854775808"
	}
	if len(digits) != len(limit) {
		return len(digits) < len(limit)
	}
	return digits <= limit
}

/*
parse_json_object parses `data` as one strict RFC 8259 JSON value, checked
first by validate_json, and rejects duplicate keys. On success, `obj` is non-nil only when the
value is an object; any other value is freed and `is_object` is false.
*/
@(private)
parse_json_object :: proc(data: []byte, allocator: runtime.Allocator) -> (obj: json.Object, is_object: bool, err: Error) {
	if !validate_json(data) {
		return nil, false, Format_Error.Invalid_Json
	}
	context.allocator = allocator
	value, json_err := json.parse(data, .JSON, true, allocator)
	if json_err != .None {
		// Only duplicate keys and allocation failures reach here, and the
		// object parser frees its own partial results for both.
		json.destroy_value(value, allocator)
		if json_err == .Out_Of_Memory {
			return nil, false, runtime.Allocator_Error.Out_Of_Memory
		}
		return nil, false, Format_Error.Invalid_Json
	}
	o, ok := value.(json.Object)
	if !ok {
		json.destroy_value(value, allocator)
		return nil, false, nil
	}
	return o, true, nil
}
