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
control characters, invalid escapes, unpaired UTF-16 surrogate escapes,
which the parser would silently replace with U+FFFD, empty member names,
which the parser would silently drop, invalid UTF-8, malformed numbers,
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
		key_start := v.pos
		if peek(v) != '"' || !validate_string(v) {
			return false
		}
		// core:encoding/json silently drops members with an empty key, which
		// would also hide duplicates of it, so reject them outright.
		if v.pos - key_start == 2 {
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

// read_hex4 reads the four hex digits of a `\u` escape and returns the UTF-16 code unit they encode.
@(private = "file")
read_hex4 :: proc(v: ^Json_Validator) -> (unit: u16, ok: bool) {
	if len(v.data) - v.pos < 4 {
		return 0, false
	}
	for i in 0 ..< 4 {
		c := v.data[v.pos + i]
		if !is_hex(c) {
			return 0, false
		}
		digit: u16
		switch c {
		case '0' ..= '9':
			digit = u16(c - '0')
		case 'a' ..= 'f':
			digit = u16(c - 'a' + 10)
		case 'A' ..= 'F':
			digit = u16(c - 'A' + 10)
		}
		unit = unit << 4 | digit
	}
	v.pos += 4
	return unit, true
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
				v.pos += 1
				unit := read_hex4(v) or_return
				switch unit {
				case 0xd800 ..= 0xdbff:
					// A high surrogate must be followed by an escaped low surrogate.
					if !expect_literal(v, `\u`) {
						return false
					}
					low := read_hex4(v) or_return
					if low < 0xdc00 || low > 0xdfff {
						return false
					}
				case 0xdc00 ..= 0xdfff:
					return false
				}
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

`core:encoding/json` ignores allocation failures in some paths: it leaks an
array element and drops it from the result when growing the array fails. So
the parser only ever allocates from a private Scratch_Arena that records any
failure, and the result is copied into `allocator` with every allocation
checked. The arena is freed in one piece, so nothing can leak.
*/
@(private)
parse_json_object :: proc(data: []byte, allocator: runtime.Allocator) -> (obj: json.Object, is_object: bool, err: Error) {
	if !validate_json(data) {
		return nil, false, Format_Error.Invalid_Json
	}

	arena := Scratch_Arena{backing = allocator}
	defer scratch_arena_destroy(&arena)
	scratch := scratch_arena_allocator(&arena)

	value, json_err := json.parse(data, .JSON, true, scratch)
	if arena.failed || json_err == .Out_Of_Memory {
		return nil, false, runtime.Allocator_Error.Out_Of_Memory
	}
	if json_err != .None {
		// Only duplicate keys reach here, because validate_json passed.
		return nil, false, Format_Error.Invalid_Json
	}
	parsed, ok := value.(json.Object)
	if !ok {
		return nil, false, nil
	}
	copied := clone_json_value(parsed, allocator) or_return
	return copied.(json.Object), true, nil
}

/*
clone_json_value deep-copies `value` into `allocator`. Unlike json.clone_value,
it checks every allocation and frees the partial copy when one fails.
*/
@(private = "file")
clone_json_value :: proc(value: json.Value, allocator: runtime.Allocator) -> (out: json.Value, err: runtime.Allocator_Error) {
	switch v in value {
	case json.Null, json.Integer, json.Float, json.Boolean:
		return value, nil
	case json.String:
		s := make([]byte, len(v), allocator) or_return
		copy(s, v)
		return json.String(s), nil
	case json.Array:
		arr := make(json.Array, 0, len(v), allocator) or_return
		for elem in v {
			c, cerr := clone_json_value(elem, allocator)
			if cerr != nil {
				json.destroy_value(arr, allocator)
				return nil, cerr
			}
			// The capacity is reserved, so this append can't allocate or fail.
			append(&arr, c)
		}
		return arr, nil
	case json.Object:
		o := make(json.Object, allocator)
		if rerr := reserve(&o, len(v)); rerr != nil {
			delete(o)
			return nil, rerr
		}
		for key, elem in v {
			k, kerr := make([]byte, len(key), allocator)
			if kerr != nil {
				json.destroy_value(o, allocator)
				return nil, kerr
			}
			copy(k, key)
			c, cerr := clone_json_value(elem, allocator)
			if cerr != nil {
				delete(k, allocator)
				json.destroy_value(o, allocator)
				return nil, cerr
			}
			// The capacity is reserved, so this insert can't allocate.
			o[string(k)] = c
		}
		return o, nil
	}
	return nil, nil
}

/*
Scratch_Arena is a bump allocator over blocks taken from `backing`. Frees are
no-ops, scratch_arena_destroy returns every block, and `failed` records
whether any allocation failed, even one whose error the caller ignored.
*/
@(private = "file")
Scratch_Arena :: struct {
	backing: runtime.Allocator,
	head:    ^Scratch_Block,
	failed:  bool,
}

// Scratch_Block heads one block; the usable bytes follow it in memory.
@(private = "file")
Scratch_Block :: struct {
	next: ^Scratch_Block,
	size: int,
	used: int,
}

// SCRATCH_MIN_BLOCK and SCRATCH_MAX_BLOCK bound the block sizes; each new block doubles the last one.
@(private = "file")
SCRATCH_MIN_BLOCK :: 256

@(private = "file")
SCRATCH_MAX_BLOCK :: 64 * 1024

@(private = "file")
scratch_arena_allocator :: proc(a: ^Scratch_Arena) -> runtime.Allocator {
	return {procedure = scratch_arena_proc, data = a}
}

@(private = "file")
scratch_arena_destroy :: proc(a: ^Scratch_Arena) {
	for b := a.head; b != nil; {
		next := b.next
		runtime.mem_free_with_size(b, b.size, a.backing)
		b = next
	}
	a.head = nil
}

@(private = "file")
scratch_arena_alloc :: proc(a: ^Scratch_Arena, size, alignment: int) -> ([]byte, runtime.Allocator_Error) {
	if size < 0 || alignment <= 0 {
		a.failed = true
		return nil, .Invalid_Argument
	}
	if size == 0 {
		return nil, nil
	}
	header :: size_of(Scratch_Block)
	if b := a.head; b != nil {
		base := uintptr(b) + header
		start := runtime.align_forward_uintptr(base + uintptr(b.used), uintptr(alignment))
		if int(start - base) + size <= b.size - header {
			b.used = int(start - base) + size
			return ([^]byte)(rawptr(start))[:size], nil
		}
	}
	block_size := SCRATCH_MIN_BLOCK
	if a.head != nil {
		block_size = min(a.head.size * 2, SCRATCH_MAX_BLOCK)
	}
	block_size = max(block_size, header + alignment + size)
	raw, err := runtime.mem_alloc(block_size, align_of(Scratch_Block), a.backing)
	if err != nil {
		a.failed = true
		return nil, err
	}
	b := (^Scratch_Block)(raw_data(raw))
	b^ = {next = a.head, size = block_size}
	a.head = b
	base := uintptr(b) + header
	start := runtime.align_forward_uintptr(base, uintptr(alignment))
	b.used = int(start - base) + size
	return ([^]byte)(rawptr(start))[:size], nil
}

@(private = "file")
scratch_arena_proc :: proc(
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
	a := (^Scratch_Arena)(data)
	switch mode {
	case .Alloc, .Alloc_Non_Zeroed:
		// Blocks come zeroed from mem_alloc and are never reused.
		return scratch_arena_alloc(a, size, alignment)
	case .Resize, .Resize_Non_Zeroed:
		if old_memory != nil && size <= old_size {
			return ([^]byte)(old_memory)[:size], nil
		}
		bytes, err := scratch_arena_alloc(a, size, alignment)
		if err == nil && old_memory != nil {
			copy(bytes, ([^]byte)(old_memory)[:old_size])
		}
		return bytes, err
	case .Free:
		return nil, nil
	case .Query_Features:
		set := (^runtime.Allocator_Mode_Set)(old_memory)
		if set != nil {
			set^ = {.Alloc, .Alloc_Non_Zeroed, .Free, .Resize, .Resize_Non_Zeroed, .Query_Features}
		}
		return nil, nil
	case .Free_All, .Query_Info:
	}
	return nil, .Mode_Not_Implemented
}
