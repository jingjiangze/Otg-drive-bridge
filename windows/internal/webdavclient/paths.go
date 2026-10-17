package webdavclient

import (
	"errors"
	"fmt"
	"strings"
)

// ErrUnsafePath is a path the client refuses to put on the wire.
var ErrUnsafePath = errors.New("webdav: traversal-unsafe path")

// validatePath mirrors the server's traversal defence
// (`WebDavPaths.normalize` + `isSafeSegment`): every non-empty segment,
// percent-DECODED, is rejected when it is "." or "..", or contains a "/" or a
// backslash. Checking the decoded form is the whole point — a literal ".."
// is the obvious case, and `%2e%2e` is the one a naive client leaks through.
//
// The server answers either with a 400; refusing here costs nothing and stops
// a bug that turns a local filesystem path into a request from reaching the
// wire at all. What is deliberately NOT checked here, left to the server's
// 400 so a future relaxation server-side does not strand this client:
// Windows reserved names, trailing dots and spaces, and whole empty encoded
// segments — those are naming conveniences, not traversal.
func validatePath(path string) error {
	if strings.ContainsRune(path, 0) {
		return fmt.Errorf("%w: NUL byte in %q", ErrUnsafePath, path)
	}
	for _, piece := range strings.Split(path, "/") {
		if piece == "" {
			continue
		}
		decoded, err := percentDecode(piece)
		if err != nil {
			return fmt.Errorf("%w: segment %q does not decode: %v", ErrUnsafePath, piece, err)
		}
		if decoded == "." || decoded == ".." || strings.ContainsRune(decoded, '/') || strings.ContainsRune(decoded, '\\') {
			return fmt.Errorf("%w: segment %q (decoded %q) in %q", ErrUnsafePath, piece, decoded, path)
		}
	}
	return nil
}

// percentDecode decodes a percent-encoded path segment.
//
// The rules mirror WebDavPaths.percentDecode on the Kotlin side, and matching
// them exactly is the point — a client that decodes more or less than the
// server disagrees with it on the same href:
//
//   - escapes encode *bytes*, so a run of them is decoded as one UTF-8
//     sequence; decoding byte-by-byte would turn every non-ASCII name into
//     mojibake
//   - `+` is *not* a space: a path segment is not a query string
//   - a malformed escape is left as-is rather than dropped
//
// A malformed run is replaced with U+FFFD rather than dropped, which is what
// String(bytes, UTF_8) does on the Kotlin side; the two must agree or the
// client and the server see different names for the same file.
func percentDecode(segment string) (string, error) {
	if !strings.ContainsRune(segment, '%') {
		return segment, nil
	}
	var out strings.Builder
	out.Grow(len(segment))
	var pending []byte
	flush := func() {
		if len(pending) > 0 {
			out.WriteString(string(pending))
			pending = pending[:0]
		}
	}
	for i := 0; i < len(segment); {
		if segment[i] == '%' && i+2 < len(segment) {
			hi := unhex(segment[i+1])
			lo := unhex(segment[i+2])
			if hi >= 0 && lo >= 0 {
				pending = append(pending, byte(hi<<4|lo))
				i += 3
				continue
			}
		}
		flush()
		out.WriteByte(segment[i])
		i++
	}
	flush()
	return out.String(), nil
}

func unhex(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	case c >= 'A' && c <= 'F':
		return int(c-'A') + 10
	}
	return -1
}

// percentEncode is the inverse, used to build hrefs for requests.
//
// Uppercase hex and space → %20, matching WebDavPaths.percentEncode. The server
// emits hrefs in this form, so a client that echoes them back must not
// re-encode a `%` that is already an escape.
func percentEncode(segment string) string {
	const unreserved = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"
	var out strings.Builder
	out.Grow(len(segment) * 2)
	for i := 0; i < len(segment); i++ {
		c := segment[i]
		if strings.IndexByte(unreserved, c) >= 0 {
			out.WriteByte(c)
			continue
		}
		// Space is the one non-unreserved byte with a canonical escape of its
		// own; everything else is encoded byte-wise, which is what makes a
		// multi-byte UTF-8 name round-trip.
		if c == ' ' {
			out.WriteString("%20")
			continue
		}
		out.WriteString(fmt.Sprintf("%%%02X", c))
	}
	return out.String()
}

// JoinSegments builds a root-relative, percent-encoded path from raw segment
// names. This is what a caller hands to Propfind, Put and MoveOrCopy.
func JoinSegments(segments ...string) string {
	if len(segments) == 0 {
		return "/"
	}
	parts := make([]string, len(segments))
	for i, s := range segments {
		parts[i] = percentEncode(s)
	}
	return "/" + strings.Join(parts, "/")
}
