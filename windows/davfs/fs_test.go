//go:build windows

package davfs

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"

	"github.com/jingjiangze/Otg-drive-bridge/windows/internal/webdavclient"
)

// Functional tests for the adapter against a fake WebDAV server shaped like
// the phone's: 207 with iscollection, percent-encoded hrefs, the collection
// SELF entry included in depth-1 listings, 405 for MKCOL on an existing
// resource. The digest handshake is stubbed (static nonce, accept any echo)
// because this file tests davfs, not the handshake — client_test.go owns
// that.

type fake struct {
	mu    sync.Mutex
	files map[string][]byte // "/docs/a.txt" -> content
	dirs  map[string]bool   // "/docs" -> true
	puts  map[string]int    // PUT count per path: proof read-only opens never upload
}

const fakeNonce = "fakenonce"

func newFake() *fake {
	return &fake{
		files: map[string][]byte{},
		dirs:  map[string]bool{"/": true},
		puts:  map[string]int{},
	}
}

func (f *fake) serve(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		w.Header().Set("DAV", "1, 2")
		w.Header().Set("Allow", "OPTIONS, GET, HEAD, PUT, DELETE, MKCOL, PROPFIND, MOVE, COPY, LOCK, UNLOCK")
		w.Header().Set("Accept-Ranges", "bytes")
		w.WriteHeader(http.StatusOK)
		return
	}
	if !strings.Contains(r.Header.Get("Authorization"), `nonce="`+fakeNonce+`"`) {
		w.Header().Set("WWW-Authenticate",
			`Digest realm="OTG Drive Bridge", qop="auth", nonce="`+fakeNonce+`", opaque="fake"`)
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	p := r.URL.Path
	switch r.Method {
	case "PROPFIND":
		f.propfind(w, r, p)
	case http.MethodGet:
		f.get(w, p)
	case http.MethodPut:
		f.put(w, r, p)
	case "MKCOL":
		f.mkcol(w, p)
	case http.MethodDelete:
		f.del(w, p)
	case "MOVE":
		f.move(w, r, p)
	default:
		http.Error(w, "405", http.StatusMethodNotAllowed)
	}
}

func (f *fake) get(w http.ResponseWriter, p string) {
	f.mu.Lock()
	body, ok := f.files[p]
	isDir := f.dirs[p]
	f.mu.Unlock()
	if !ok || isDir {
		http.Error(w, "404", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("ETag", `"fake"`)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}

func (f *fake) put(w http.ResponseWriter, r *http.Request, p string) {
	data, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "400", http.StatusBadRequest)
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.dirs[p] {
		http.Error(w, "405", http.StatusMethodNotAllowed)
		return
	}
	parent := path.Dir(p)
	if !f.dirs[parent] {
		http.Error(w, "409", http.StatusConflict)
		return
	}
	_, existed := f.files[p]
	f.files[p] = data
	f.puts[p]++
	if existed {
		w.WriteHeader(http.StatusNoContent)
	} else {
		w.WriteHeader(http.StatusCreated)
	}
}

func (f *fake) mkcol(w http.ResponseWriter, p string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.dirs[p] {
		http.Error(w, "405", http.StatusMethodNotAllowed)
		return
	}
	if !f.dirs[path.Dir(p)] {
		http.Error(w, "409", http.StatusConflict)
		return
	}
	f.dirs[p] = true
	w.WriteHeader(http.StatusCreated)
}

func (f *fake) del(w http.ResponseWriter, p string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, isFile := f.files[p]
	isDir := f.dirs[p]
	if !isFile && !isDir {
		http.Error(w, "404", http.StatusNotFound)
		return
	}
	// The phone's DELETE is recursive; mirror it so the adapter's own
	// ENOTEMPTY rule is what protects callers, not the fake's mercy.
	delete(f.files, p)
	delete(f.dirs, p)
	for k := range f.files {
		if strings.HasPrefix(k, p+"/") {
			delete(f.files, k)
		}
	}
	for k := range f.dirs {
		if strings.HasPrefix(k, p+"/") && k != "/" {
			delete(f.dirs, k)
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

func (f *fake) move(w http.ResponseWriter, r *http.Request, p string) {
	dest := destinationPath(r.Header.Get("Destination"))
	f.mu.Lock()
	defer f.mu.Unlock()
	body, isFile := f.files[p]
	isDir := f.dirs[p]
	if !isFile && !isDir {
		http.Error(w, "404", http.StatusNotFound)
		return
	}
	if !f.dirs[path.Dir(dest)] {
		http.Error(w, "409", http.StatusConflict)
		return
	}
	delete(f.files, p)
	delete(f.dirs, p)
	if isFile {
		f.files[dest] = body
	} else {
		f.dirs[dest] = true
	}
	w.WriteHeader(http.StatusCreated)
}

func destinationPath(dest string) string {
	if i := strings.Index(dest, "://"); i >= 0 {
		rest := dest[i+3:]
		if s := strings.IndexByte(rest, '/'); s >= 0 {
			return rest[s:]
		}
		return "/"
	}
	if !strings.HasPrefix(dest, "/") {
		return "/" + dest
	}
	return dest
}

func (f *fake) propfind(w http.ResponseWriter, r *http.Request, p string) {
	depth := r.Header.Get("Depth")
	if depth == "" {
		depth = "1"
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	_, isFile := f.files[p]
	isDir := f.dirs[p]
	if !isFile && !isDir {
		http.Error(w, "404", http.StatusNotFound)
		return
	}
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="utf-8"?><D:multistatus xmlns:D="DAV:">`)
	writeEntry := func(h string, name string, dir bool, size int) {
		b.WriteString("<D:response><D:href>" + h + "</D:href><D:propstat><D:prop>")
		b.WriteString("<D:displayname>" + xmlEscape(name) + "</D:displayname>")
		if dir {
			b.WriteString("<D:iscollection>1</D:iscollection><D:resourcetype><D:collection/></D:resourcetype>")
		} else {
			b.WriteString("<D:getcontentlength>" + strconv.Itoa(size) + "</D:getcontentlength>")
			b.WriteString("<D:getetag>\"e\"</D:getetag>")
			b.WriteString("<D:getlastmodified>Mon, 01 Jan 2026 00:00:00 GMT</D:getlastmodified>")
			b.WriteString("<D:resourcetype/>")
		}
		b.WriteString("</D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response>")
	}
	writeEntry(encodeTestHref(p), testDisplayName(p), isDir, len(f.files[p]))
	if isDir && depth != "0" {
		// Children are exactly the entries whose parent is p — path.Dir, not
		// a "/"+p prefix: for p="/" a prefix check would hunt for "//" and
		// list nothing, which is the case this fake exists to exercise.
		for k := range f.dirs {
			if k != "/" && k != p && path.Dir(k) == p {
				writeEntry(encodeTestHref(k)+"/", testDisplayName(k), true, 0)
			}
		}
		for k, v := range f.files {
			if path.Dir(k) == p {
				writeEntry(encodeTestHref(k), testDisplayName(k), false, len(v))
			}
		}
	}
	b.WriteString("</D:multistatus>")
	w.Header().Set("Content-Type", "application/xml; charset=utf-8")
	w.Header().Set("Depth", depth)
	w.WriteHeader(http.StatusMultiStatus)
	_, _ = io.WriteString(w, b.String())
}

// encodeTestHref percent-encodes every segment, the way the server emits
// hrefs; the client decoder turns it back into the raw name.
func encodeTestHref(p string) string {
	parts := strings.Split(strings.TrimPrefix(p, "/"), "/")
	for i, s := range parts {
		parts[i] = webdavclient.JoinSegments(s)[1:]
	}
	return "/" + strings.Join(parts, "/")
}

func testDisplayName(p string) string {
	base := path.Base(strings.TrimRight(p, "/"))
	if base == "." || base == "/" || base == "\\" {
		return "/"
	}
	return base
}

func xmlEscape(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;")
	return r.Replace(s)
}

func newFSTest(t *testing.T) (*fake, *FS) {
	f := newFake()
	srv := httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(srv.Close)
	client := webdavclient.New(srv.URL, "otg", "pass", "OTG Drive Bridge")
	// Complete the handshake up front, exactly like the cmd does: without a
	// recorded challenge, PutStream refuses at upload time.
	if err := client.Probe(context.Background()); err != nil {
		t.Fatalf("probe: %v", err)
	}
	// One authenticated request to make the fake record our nonce echo — the
	// fake accepts anything containing the nonce, and Probe itself is exempt.
	if _, err := client.Propfind(context.Background(), "/", "0"); err != nil {
		t.Fatalf("warm-up propfind: %v", err)
	}
	return f, NewFS(client)
}

func TestOpenReadHydratesAndNeverUploads(t *testing.T) {
	f, fs := newFSTest(t)
	f.dirs["/docs"] = true
	f.files["/docs/a.txt"] = []byte("hello davfs")

	file, err := fs.OpenFile(`\docs\a.txt`, os.O_RDONLY, 0)
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	buf := make([]byte, 64)
	n, err := file.Read(buf)
	if err != nil && err != io.EOF {
		t.Fatalf("Read: %v", err)
	}
	if string(buf[:n]) != "hello davfs" {
		t.Fatalf("read %q, want hello davfs", buf[:n])
	}
	if err := file.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if f.puts["/docs/a.txt"] != 0 {
		t.Fatalf("read-only open PUT %d times, want 0", f.puts["/docs/a.txt"])
	}
}

func TestOpenWriteCommitsOnClose(t *testing.T) {
	f, fs := newFSTest(t)
	f.files["/a.txt"] = []byte("old")

	file, err := fs.OpenFile(`/a.txt`, os.O_RDWR, 0)
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	if _, err := file.Write([]byte("new-content")); err != nil {
		t.Fatalf("Write: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if got := string(f.files["/a.txt"]); got != "new-content" {
		t.Fatalf("committed %q, want new-content", got)
	}
	if f.puts["/a.txt"] != 1 {
		t.Fatalf("puts %d, want 1", f.puts["/a.txt"])
	}
}

func TestTruncateOnOpen(t *testing.T) {
	f, fs := newFSTest(t)
	f.files["/t.txt"] = []byte("to-be-truncated")

	file, err := fs.OpenFile(`/t.txt`, os.O_WRONLY|os.O_TRUNC, 0)
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if len(f.files["/t.txt"]) != 0 {
		t.Fatalf("not truncated: %q", f.files["/t.txt"])
	}
}

func TestNewFileCommitsEvenWithReadOnlyFlags(t *testing.T) {
	f, fs := newFSTest(t)
	// O_CREATE|O_RDONLY means "create this; I write nothing yet". Without the
	// node==nil rule the temp is dropped at Close and the create vanishes.
	file, err := fs.OpenFile(`/fresh.bin`, os.O_CREATE|os.O_RDONLY, 0)
	if err != nil {
		t.Fatalf("OpenFile: %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if _, ok := f.files["/fresh.bin"]; !ok {
		t.Fatal("created file vanished — Close did not commit")
	}
}

func TestCreateExclusiveOnExisting(t *testing.T) {
	f, fs := newFSTest(t)
	f.files["/exists.txt"] = []byte("x")
	if _, err := fs.OpenFile(`/exists.txt`, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0); !os.IsExist(err) {
		t.Fatalf("O_CREATE|O_EXCL on existing = %v, want ErrExist", err)
	}
}

func TestStatMissingIsErrNotExist(t *testing.T) {
	_, fs := newFSTest(t)
	if _, err := fs.Stat(`/nope`); !os.IsNotExist(err) {
		t.Fatalf("missing Stat = %v, want ErrNotExist", err)
	}
}

func TestRootListingSkipsSelfEntry(t *testing.T) {
	f, fs := newFSTest(t)
	f.dirs["/docs"] = true
	f.files["/docs/a b.txt"] = []byte("data")

	fi, err := fs.Stat(`\docs\a b.txt`)
	if err != nil {
		t.Fatalf("Stat spaced name: %v", err)
	}
	if fi.Name() != "a b.txt" || fi.Size() != 4 || fi.IsDir() {
		t.Fatalf("Stat = %+v", fi)
	}

	d, err := fs.OpenFile(``, os.O_RDONLY, 0)
	if err != nil {
		t.Fatalf("open root: %v", err)
	}
	defer d.Close()
	entries, err := d.Readdir(-1)
	if err != nil {
		t.Fatalf("Readdir: %v", err)
	}
	var got []string
	for _, e := range entries {
		got = append(got, e.Name())
	}
	// exactly one entry — "docs". The fake emits the root self entry like the
	// phone does; leaking it here means the skip logic broke.
	if len(got) != 1 || got[0] != "docs" {
		t.Fatalf("root listing %v, want [docs] (self entry leaked?)", got)
	}
}

func TestMkdirAndRemove(t *testing.T) {
	f, fs := newFSTest(t)

	if err := fs.Mkdir(`\sub`, 0); err != nil {
		t.Fatalf("Mkdir: %v", err)
	}
	if err := fs.Mkdir(`\sub`, 0); !os.IsExist(err) {
		t.Fatalf("duplicate Mkdir = %v, want ErrExist", err)
	}
	if err := fs.Mkdir(`\sub\deep`, 0); err != nil {
		t.Fatalf("nested Mkdir: %v", err)
	}
	if err := fs.Mkdir(`\missing\dir`, 0); !os.IsNotExist(err) {
		t.Fatalf("Mkdir under missing parent = %v, want ErrNotExist", err)
	}

	if err := fs.Remove(`\sub\deep`); err != nil {
		t.Fatalf("Remove empty dir: %v", err)
	}
	f.mu.Lock()
	f.files["/sub/f.txt"] = []byte("1")
	f.mu.Unlock()
	if err := fs.Remove(`\sub`); err != syscall.ENOTEMPTY {
		t.Fatalf("Remove non-empty dir = %v, want ENOTEMPTY", err)
	}
	f.mu.Lock()
	survives := f.dirs["/sub"]
	f.mu.Unlock()
	if !survives {
		t.Fatal("refused Remove destroyed the tree anyway")
	}
}

func TestRenameFile(t *testing.T) {
	f, fs := newFSTest(t)
	f.files["/a.txt"] = []byte("A")

	if err := fs.Rename(`/a.txt`, `/b.txt`); err != nil {
		t.Fatalf("Rename: %v", err)
	}
	if got := string(f.files["/b.txt"]); got != "A" {
		t.Fatalf("moved content %q", got)
	}
	if _, ok := f.files["/a.txt"]; ok {
		t.Fatal("source survived rename")
	}
	if err := fs.Rename(`/gone.txt`, `/c.txt`); !os.IsNotExist(err) {
		t.Fatalf("Rename missing source = %v, want ErrNotExist", err)
	}
}
