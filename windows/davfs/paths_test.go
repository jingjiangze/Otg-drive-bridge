package davfs

import (
	"os"
	"testing"
	"time"

	"github.com/jingjiangze/Otg-drive-bridge/windows/internal/webdavclient"
)

// The pure pieces of the adapter run on every platform — and they are exactly
// the pieces where a wrong decision silently corrupts names on the wire, so
// they get real tests here rather than rides on the manual mount check.

func TestSegmentsAcceptsBothSeparators(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{`\docs\a.txt`, []string{"docs", "a.txt"}},
		{`/docs/a.txt`, []string{"docs", "a.txt"}},
		{`\a b\c.txt`, []string{"a b", "c.txt"}},
		{``, nil},
		{`\`, nil},
		{`\\`, nil},
		// Foreign dot segments are dropped, never encoded away.
		{`\a\.\b\..\c`, []string{"a", "b", "c"}},
	}
	for _, c := range cases {
		got := Segments(c.in)
		if len(got) != len(c.want) {
			t.Errorf("Segments(%q) = %v, want %v", c.in, got, c.want)
			continue
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("Segments(%q)[%d] = %q, want %q", c.in, i, got[i], c.want[i])
			}
		}
	}
}

func TestHrefMatchesClientEncoding(t *testing.T) {
	// The single ground truth is what the client itself builds.
	if got, want := Href(Segments(`\中文.txt`)), webdavclient.JoinSegments("中文.txt"); got != want {
		t.Errorf("Href = %q, want %q (client join)", got, want)
	}
	if got := Href(nil); got != "/" {
		t.Errorf("root Href = %q, want /", got)
	}
	// A literal "%" must arrive as one escape, not double-encoded: the server
	// decodes exactly once.
	if got := Href([]string{"100%.txt"}); got != "/100%25.txt" {
		t.Errorf("Href with percent = %q, want /100%25.txt", got)
	}
}

func TestDecodeHrefRoundTrips(t *testing.T) {
	href := "/%E4%B8%AD%E6%96%87%20with%20space/100%25.txt"
	decoded := DecodeHref(href)
	want := "/中文 with space/100%.txt"
	if decoded != want {
		t.Errorf("DecodeHref = %q, want %q", decoded, want)
	}
	// Collections arrive with a trailing slash; self-entry comparison in
	// Remove/Readdir relies on trimming it to the same form as our own href.
	if DecodeHref("/docs/") != "/docs" {
		t.Errorf("trailing slash not trimmed: %q", DecodeHref("/docs/"))
	}
	// A malformed escape must survive as-is (server's String(bytes,UTF_8) rule
	// replaces, but the *segment* stays findable; keeping raw matches the
	// client's percentDecode which leaves malformed sequences alone).
	if DecodeHref("/%zz") != "/%zz" {
		t.Errorf("malformed escape mangled: %q", DecodeHref("/%zz"))
	}
}

func TestNodeToFileInfo(t *testing.T) {
	now := time.Now()
	fi := NodeToFileInfo(webdavclient.Node{Name: "a.txt", Length: 7, IsDir: false, LastModified: now})
	if fi.Name() != "a.txt" || fi.Size() != 7 || fi.IsDir() || !fi.ModTime().Equal(now) {
		t.Errorf("file info = %+v", fi)
	}
	di := NodeToFileInfo(webdavclient.Node{Name: "docs", IsDir: true})
	if !di.IsDir() || di.Mode()&os.ModeDir == 0 {
		t.Errorf("dir info mode = %v", di.Mode())
	}
	if di.Mode().Perm() != 0o755 {
		t.Errorf("dir perm = %v", di.Mode().Perm())
	}
	root := NodeToFileInfo(webdavclient.Node{Href: "/"})
	if root.Name() != "/" {
		t.Errorf("root display name = %q", root.Name())
	}
}
