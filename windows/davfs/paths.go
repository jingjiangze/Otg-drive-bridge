package davfs

import (
	"os"
	"strings"
	"time"

	"github.com/jingjiangze/Otg-drive-bridge/windows/internal/webdavclient"
)

// This file is deliberately free of gofs imports: everything here compiles and
// runs on Linux too, so the path/href translation — the part where a wrong
// choice silently corrupts names — has real unit tests in the main CI gate.

// Segments splits a gofs name (`\docs\a.txt`, root `""` or `"\"`) into raw
// (decoded) segment names. Both separators are accepted because gofs unifies
// through filepath on Windows, but a forward slash must never be treated as a
// name character.
func Segments(name string) []string {
	name = strings.ReplaceAll(name, "\\", "/")
	var out []string
	for _, s := range strings.Split(name, "/") {
		if s == "." || s == ".." {
			// gofs has already cleaned (UnifyFilePath → path.Clean), so a dot
			// here is foreign input; refusing is safer than encoding it away.
			// Treat as noise: skip. The server-side traversal guard is the
			// real defence; this keeps our href well-formed.
			continue
		}
		if s == "" {
			continue
		}
		out = append(out, s)
	}
	return out
}

// Href builds the root-relative encoded request path for [segments]; the root
// is "/" — exactly what webdavclient.JoinSegments produces for no segments.
func Href(segments []string) string {
	return webdavclient.JoinSegments(segments...)
}

// DecodeHref percent-decodes every segment of a server href so it can be
// compared with our own decoded paths; trailing slashes are ignored (the
// server marks collections with one).
func DecodeHref(href string) string {
	href = strings.TrimSuffix(href, "/")
	parts := strings.Split(strings.TrimPrefix(href, "/"), "/")
	for i, p := range parts {
		// Reuse the client's decoder rules by round-tripping through
		// JoinSegments is impossible for a single decoded segment; decode
		// manually with the same "leave malformed escapes alone" rule.
		parts[i] = rawPercentDecode(p)
	}
	return "/" + strings.Join(parts, "/")
}

func rawPercentDecode(s string) string {
	if !strings.Contains(s, "%") {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); {
		if s[i] == '%' && i+2 < len(s) {
			hi, lo := unhex(s[i+1]), unhex(s[i+2])
			if hi >= 0 && lo >= 0 {
				b.WriteByte(byte(hi<<4 | lo))
				i += 3
				continue
			}
		}
		b.WriteByte(s[i])
		i++
	}
	return b.String()
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

// NodeToFileInfo converts a PROPFIND row into the os.FileInfo the gofs
// behaviour layer wants. mode is 0755 for collections and 0644 otherwise:
// the Windows attributes are derived from those bits by gofs, and everything
// on the share is meant to be writable — an HTTP 403 is the real gate, not
// the attribute display.
func NodeToFileInfo(n webdavclient.Node) os.FileInfo {
	mode := os.FileMode(0o644)
	if n.IsDir {
		mode = os.FileMode(0o755) | os.ModeDir
	}
	name := n.Name
	if name == "" {
		name = "/"
	}
	return &nodeInfo{
		name:    name,
		size:    n.Length,
		mode:    mode,
		modTime: n.LastModified,
	}
}

type nodeInfo struct {
	name    string
	size    int64
	mode    os.FileMode
	modTime time.Time
}

func (i *nodeInfo) Name() string { return i.name }

func (i *nodeInfo) Size() int64 { return i.size }

func (i *nodeInfo) Mode() os.FileMode { return i.mode }

func (i *nodeInfo) ModTime() time.Time { return i.modTime }

func (i *nodeInfo) IsDir() bool { return i.mode.IsDir() }

func (i *nodeInfo) Sys() any { return nil }
