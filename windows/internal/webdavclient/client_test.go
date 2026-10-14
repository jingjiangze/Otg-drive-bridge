package webdavclient

import (
	"context"
	"crypto/md5"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// fakeServer: a stand-in for the Kotlin server, reproducing its behaviour
// exactly where the nine gaps live.
//
// This is a fake, not the real server. Its job is to make the client's
// judgement calls observable in a unit test; the real server is driven by the
// cross-language interop suite in tools/interop. Anything asserted here about
// the *server* is a comment, not a test.
//
// Where it deliberately diverges from RFC 4918 (mirroring
// WebDavRequestHandler), the divergence is named in a comment so that a reader
// does not mistake it for an accident:
//   - PUT ignores If-Match
//   - COPY/MOVE ignore Overwrite
//   - PROPPATCH answers 207 with current values and applies nothing
//   - PROPFIND treats Depth "infinity" as "1"
//   - errors are plain text, not XML
// ---------------------------------------------------------------------------

type fakeServer struct {
	t *testing.T

	// httpServer is the wire endpoint; client is the webdavclient under test
	// pointed at it. Kept as two named fields rather than embedding both, so
	// the roles cannot be confused and the constructor cannot shadow itself.
	httpServer *httptest.Server
	client     *Server

	mu        sync.Mutex
	files     map[string][]byte
	authCalls []authRecord
	// forceStale invalidates the client's current nonce on the next request.
	//
	// This is how RFC 2617 stale actually arises: the server has dropped the
	// nonce (it aged out, or the process restarted), so a request carrying it is
	// answered with a fresh challenge marked stale=true. Arming a flag is the
	// only way to drive that path without waiting out the real 300s lifetime,
	// and it exercises the same client branch a genuine expiry would.
	forceStale bool
	// realmOverride answers a challenge with a different realm, which the client
	// must refuse rather than answer.
	realmOverride string

	lastSeen map[string]http.Header
}

type authRecord struct {
	method  string
	uri     string
	nc      string
	nonce   string
	opaque  string
	cnonce string
	qop     string
	present bool
}

const (
	fakeRealm = "OTG Drive Bridge"
	fakeUser  = "otg"
	fakePass  = "SuperSecretPassw0rd"
)

func newFakeServer(t *testing.T) *fakeServer {
	t.Helper()
	f := &fakeServer{
		t:        t,
		files:    map[string][]byte{},
		lastSeen: map[string]http.Header{},
	}
	f.httpServer = httptest.NewServer(http.HandlerFunc(f.handle))
	t.Cleanup(f.httpServer.Close)
	f.client = New(f.httpServer.URL, fakeUser, fakePass, fakeRealm)
	return f
}

// handle is the Kotlin server's dispatch, in miniature.
//
// It runs on the HTTP server's goroutine, so it must not call t.Helper() or
// t.Fatal: those belong to the test goroutine and would mis-report the failing
// line or panic the binary. Failures here surface as a non-200 status that the
// assertions catch.
func (f *fakeServer) handle(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.lastSeen[r.Method+" "+r.URL.Path] = r.Header.Clone()
	f.mu.Unlock()

	if r.Method == http.MethodOptions {
		f.writeOptions(w)
		return
	}
	if !f.authorize(w, r) {
		return
	}

	switch r.Method {
	case "PROPFIND":
		f.handlePropfind(w, r)
	case "GET":
		f.handleGet(w, r)
	case "PUT":
		f.handlePut(w, r)
	case "MKCOL":
		f.handleMkcol(w, r)
	case "DELETE":
		f.handleDelete(w, r)
	case "COPY", "MOVE":
		f.handleCopyOrMove(w, r)
	case "LOCK":
		f.handleLock(w, r)
	case "UNLOCK":
		f.handleUnlock(w, r)
	case "PROPPATCH":
		f.handleProppatch(w, r)
	default:
		http.Error(w, "405 Method Not Allowed", http.StatusMethodNotAllowed)
	}
}

func (f *fakeServer) writeOptions(w http.ResponseWriter) {
	h := w.Header()
	h.Set("DAV", "1, 2")
	h.Set("MS-Author-Via", "DAV")
	h.Set("Allow", "OPTIONS, GET, HEAD, PUT, DELETE, PROPFIND, PROPPATCH, MKCOL, COPY, MOVE, LOCK, UNLOCK")
	h.Set("Accept-Ranges", "bytes")
	w.WriteHeader(http.StatusOK)
}

// authorize mirrors DigestAuthenticator: an unparseable or wrong Authorization
// produces a 401 with a challenge, and that challenge carries stale=true when
// the server has deliberately dropped the nonce the client was using.
func (f *fakeServer) authorize(w http.ResponseWriter, r *http.Request) bool {
	f.mu.Lock()
	header := r.Header.Get("Authorization")
	realm := fakeRealm
	if f.realmOverride != "" {
		realm = f.realmOverride
	}
	// A stale nonce is rejected *and* answered with stale=true, exactly as
	// DigestAuthenticator would once it starts sending the flag. Consuming the
	// flag here keeps it a one-shot: the request after the retry must succeed.
	invalidated := f.forceStale
	f.forceStale = false
	f.mu.Unlock()

	ok := f.verifyDigest(header, r.Method)
	if ok && !invalidated {
		return true
	}

	nonce := fmt.Sprintf("nonce-%d", time.Now().UnixNano())
	opaque := fmt.Sprintf("opaque-%d", time.Now().UnixNano()%100000)
	challenge := fmt.Sprintf(`Digest realm=%q, qop="auth", nonce=%q, opaque=%q`, realm, nonce, opaque)
	if invalidated {
		challenge += ", stale=true"
	}
	w.Header().Set("WWW-Authenticate", challenge)
	http.Error(w, "401 Unauthorized", http.StatusUnauthorized)
	return false
}

// verifyDigest computes the response the way the Kotlin server does and
// compares it. It records what it saw so the tests can assert on nc climbing,
// opaque echoing, and the request-URI form.
//
// Only an attempt that actually carried an Authorization header is recorded.
// The first attempt of a Do() deliberately carries none, so recording it would
// shift every index by one and make `records[0]` the anonymous request — which
// is exactly the off-by-one that hides a broken nc sequence.
func (f *fakeServer) verifyDigest(header, method string) bool {
	if !strings.HasPrefix(header, "Digest ") {
		return false
	}
	fields := digestFields(header)
	rec := authRecord{
		method:  method,
		uri:     fields["uri"],
		nc:      fields["nc"],
		nonce:   fields["nonce"],
		opaque:  fields["opaque"],
		cnonce:  fields["cnonce"],
		qop:     fields["qop"],
		present: fields["username"] != "",
	}
	if !rec.present {
		return false
	}
	f.mu.Lock()
	f.authCalls = append(f.authCalls, rec)
	f.mu.Unlock()

	if fields["realm"] != fakeRealm || fields["username"] != fakeUser {
		return false
	}
	// The server computes HA2 over the request-URI it saw on the request line.
	// This is what makes the absolute-URI-in-Authorization failure visible: the
	// client's HA2 would be over a different string.
	want := digestResponse(fakeUser, fakePass, fakeRealm, method, rec.uri, rec.nonce, rec.nc, rec.cnonce, rec.qop)
	return want == fields["response"]
}

func (f *fakeServer) handlePropfind(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	depth := r.Header.Get("Depth")
	if depth == "" {
		// WebDavRequestHandler defaults to "1"; "infinity" behaves the same.
		depth = "1"
	}
	entries, ok := f.propfindEntries(path, depth)
	if !ok {
		http.Error(w, "404 Not Found", http.StatusNotFound)
		return
	}
	w.Header().Set("Depth", depth)
	w.Header().Set("Content-Type", "application/xml; charset=utf-8")
	w.WriteHeader(http.StatusMultiStatus)
	fmt.Fprint(w, `<?xml version="1.0" encoding="utf-8"?><D:multistatus xmlns:D="DAV:">`+
		strings.Join(entries, "")+`</D:multistatus>`)
}

// propfindEntries builds the <response> list for [path] at [depth], mirroring
// WebDavXml.collectionListing. It reports ok=false for a path that resolves to
// nothing, which is the server's 404.
//
// Three details are what make the parse meaningful rather than merely
// well-formed, and all three come from the real builder:
//
//   - a collection's href carries a trailing slash, a file's does not. A client
//     that trims it, or assumes the opposite, mis-reads the last segment.
//   - a child href is the parent's href plus the encoded child name, so the
//     parent href in the response is the thing to join against — not the
//     request path, which for a collection lacks the slash.
//   - directories are listed before files, then by lowercased name.
func (f *fakeServer) propfindEntries(path, depth string) ([]string, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()

	// A directory is a `path + "/"` key with a nil body (MKCOL creates one), and
	// the root always exists. A directory that was never MKCOL'ed but has
	// children is still a directory: the real storage has a node for it, and a
	// listing that dropped it would show a folder as empty — the "0 files on
	// Windows" failure this XML shape was written against.
	dir := path == "/"
	if !dir {
		if _, ok := f.files[path+"/"]; ok {
			dir = true
		} else {
			for name := range f.files {
				if strings.HasPrefix(name, path+"/") {
					dir = true
					break
				}
			}
		}
	}
	if !dir {
		if _, ok := f.files[path]; !ok {
			return nil, false
		}
	}

	href := path
	if dir {
		href = strings.TrimSuffix(path, "/") + "/"
	}
	// Depth 0 answers only the resource itself, and so does a file: a file has no
	// children to list, whatever the depth asked for.
	if depth == "0" || !dir {
		return []string{multistatusEntry(href, len(f.files[path]), dir)}, true
	}

	// One level of children. Matching on the first path segment of the remainder
	// rather than on `HasPrefix(name, path)` keeps /docs2 out of /docs and pulls
	// in a grandchild's parent as a directory.
	prefix := href
	childNames := map[string]bool{}
	for name := range f.files {
		if !strings.HasPrefix(name, prefix) {
			continue
		}
		rest := name[len(prefix):]
		if rest == "" {
			continue // the collection's own key
		}
		head := rest
		if slash := strings.IndexByte(rest, '/'); slash >= 0 {
			head = rest[:slash]
		}
		if head != "" {
			childNames[head] = true
		}
	}
	names := make([]string, 0, len(childNames))
	for name := range childNames {
		names = append(names, name)
	}
	// Directory-ness per child, computed once: the sort needs it and so does the
	// entry builder, and reading the map twice under one lock is not free.
	dirs := make(map[string]bool, len(names))
	for _, name := range names {
		dirs[name] = f.isDirLocked(prefix + name + "/")
	}
	sort.Slice(names, func(i, j int) bool {
		if dirs[names[i]] != dirs[names[j]] {
			return dirs[names[i]]
		}
		return strings.ToLower(names[i]) < strings.ToLower(names[j])
	})

	entries := make([]string, 0, len(names)+1)
	entries = append(entries, multistatusEntry(href, 0, true))
	for _, name := range names {
		childIsDir := dirs[name]
		childHref := prefix + percentEncode(name)
		if childIsDir {
			childHref += "/"
		}
		entries = append(entries, multistatusEntry(childHref, len(f.files[prefix+name]), childIsDir))
	}
	return entries, true
}

// isDirLocked answers whether key names a collection. The caller must hold mu.
func (f *fakeServer) isDirLocked(key string) bool {
	if _, ok := f.files[key]; ok {
		return true
	}
	for name := range f.files {
		if strings.HasPrefix(name, key) {
			return true
		}
	}
	return false
}

func multistatusEntry(href string, length int, isDir bool) string {
	// Mirrors WebDavXml.response: displayname, iscollection, getcontentlength,
	// getlastmodified, resourcetype — all inside propstat/prop.
	dir := "0"
	resType := ""
	if isDir {
		dir = "1"
		resType = "<D:collection/>"
	}
	lengthPart := fmt.Sprintf("<D:getcontentlength>%d</D:getcontentlength>", length)
	if isDir {
		lengthPart = ""
	}
	return "<D:response><D:href>" + href + "</D:href><D:propstat><D:prop>" +
		"<D:displayname>" + href + "</D:displayname>" +
		"<D:iscollection>" + dir + "</D:iscollection>" +
		lengthPart +
		"<D:getlastmodified>Mon, 02 Jan 2006 15:04:05 GMT</D:getlastmodified>" +
		"<D:resourcetype>" + resType + "</D:resourcetype>" +
		"<D:supportedlock><D:lockentry><D:lockscope><D:exclusive/></D:lockscope>" +
		"<D:locktype><D:write/></D:locktype></D:lockentry></D:supportedlock>" +
		"</D:prop><D:status>HTTP/1.1 200 OK</D:status></D:propstat></D:response>"
}

func (f *fakeServer) handleGet(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	body, ok := f.files[r.URL.Path]
	f.mu.Unlock()
	if !ok {
		http.Error(w, "404 Not Found", http.StatusNotFound)
		return
	}
	// WebDavRequestHandler sends an ETag but no Range support.
	w.Header().Set("ETag", `"1735689600000-42"`)
	w.Header().Set("Last-Modified", "Mon, 02 Jan 2006 15:04:05 GMT")
	w.Header().Set("Accept-Ranges", "bytes")
	w.WriteHeader(http.StatusOK)
	w.Write(body)
}

func (f *fakeServer) handlePut(w http.ResponseWriter, r *http.Request) {
	// Gap 8: the server ignores If-Match. Recording it so the test can assert
	// the client *sent* it — the server-side gap is a Stage-3 item.
	f.mu.Lock()
	f.lastSeen["PUT "+r.URL.Path+" If-Match"] = r.Header.Clone()
	f.mu.Unlock()
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "400 Upload failed", http.StatusBadRequest)
		return
	}
	f.mu.Lock()
	_, existed := f.files[r.URL.Path]
	f.files[r.URL.Path] = body
	f.mu.Unlock()
	w.Header().Set("ETag", `"1735689600000-`+fmt.Sprint(len(body))+`"`)
	if existed {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	w.WriteHeader(http.StatusCreated)
}

func (f *fakeServer) handleMkcol(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.files[r.URL.Path]; ok {
		http.Error(w, "405 Already exists", http.StatusMethodNotAllowed)
		return
	}
	f.files[r.URL.Path+"/"] = nil
	w.WriteHeader(http.StatusCreated)
}

func (f *fakeServer) handleDelete(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.files[r.URL.Path]; !ok {
		http.Error(w, "404 Not Found", http.StatusNotFound)
		return
	}
	delete(f.files, r.URL.Path)
	delete(f.files, r.URL.Path+"/")
	w.WriteHeader(http.StatusNoContent)
}

// handleCopyOrMove reproduces the server's Destination parsing, including the
// gap: Overwrite is never read.
func (f *fakeServer) handleCopyOrMove(w http.ResponseWriter, r *http.Request) {
	dest := r.Header.Get("Destination")
	if dest == "" {
		http.Error(w, "400 Missing Destination", http.StatusBadRequest)
		return
	}
	// WebDavRequestHandler strips a scheme and takes everything after the first
	// slash, defaulting to "/" when there is none. Written as a guard rather
	// than SplitN(...)[1] so a bare relative Destination cannot panic the
	// server goroutine — which would fail the whole test binary, not the case.
	destPath := strings.SplitN(dest, "?", 2)[0]
	if strings.HasPrefix(destPath, "http://") || strings.HasPrefix(destPath, "https://") {
		if slash := strings.IndexByte(destPath, '/'); slash >= 0 {
			destPath = destPath[slash:]
		} else {
			destPath = "/"
		}
	}
	if !strings.HasPrefix(destPath, "/") {
		destPath = "/" + destPath
	}

	f.mu.Lock()
	body, ok := f.files[r.URL.Path]
	if !ok {
		f.mu.Unlock()
		http.Error(w, "404 Not Found", http.StatusNotFound)
		return
	}
	// The destination's parent must exist and be a directory — the checks the
	// real handler makes, so a copy into a missing folder is a 409 here too
	// rather than silently creating the folder.
	parent := "/"
	if slash := strings.LastIndexByte(strings.TrimSuffix(destPath, "/"), '/'); slash > 0 {
		parent = destPath[:slash]
	}
	if parent != "/" && !f.isDirLocked(parent + "/") {
		f.mu.Unlock()
		http.Error(w, "409 Destination missing", http.StatusConflict)
		return
	}
	if r.Method == "MOVE" {
		delete(f.files, r.URL.Path)
	}
	f.files[destPath] = body
	f.mu.Unlock()
	w.WriteHeader(http.StatusCreated)
}

func (f *fakeServer) handleLock(w http.ResponseWriter, r *http.Request) {
	token := fmt.Sprintf("opaquelocktoken:lock-%d", time.Now().UnixNano())
	w.Header().Set("Lock-Token", "<"+token+">")
	w.Header().Set("Content-Type", "application/xml; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, `<?xml version="1.0" encoding="utf-8"?><D:prop xmlns:D="DAV:">`+
		`<D:lockdiscovery><D:activelock><D:locktype><D:write/></D:locktype>`+
		`<D:lockscope><D:exclusive/></D:lockscope><D:depth>infinity</D:depth>`+
		`<D:owner>otg-drive-bridge</D:owner><D:timeout>Second-3600</D:timeout>`+
		`<D:locktoken><D:href>`+token+`</D:href></D:locktoken>`+
		`</D:activelock></D:lockdiscovery></D:prop>`)
}

func (f *fakeServer) handleUnlock(w http.ResponseWriter, r *http.Request) {
	if strings.Trim(r.Header.Get("Lock-Token"), "<> ") == "" {
		http.Error(w, "409 No such lock", http.StatusConflict)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// handleProppatch reproduces the server's behaviour: 207 with current values,
// body ignored.
func (f *fakeServer) handleProppatch(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	body, ok := f.files[r.URL.Path]
	f.mu.Unlock()
	if !ok {
		http.Error(w, "404 Not Found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/xml; charset=utf-8")
	w.WriteHeader(http.StatusMultiStatus)
	fmt.Fprint(w, `<?xml version="1.0" encoding="utf-8"?><D:multistatus xmlns:D="DAV:">`+
		multistatusEntry(r.URL.Path, len(body), false)+`</D:multistatus>`)
}

// --- test helpers ----------------------------------------------------------

func (f *fakeServer) authRecords() []authRecord {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]authRecord, len(f.authCalls))
	copy(out, f.authCalls)
	return out
}

func (f *fakeServer) lastHeader(key string) http.Header {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lastSeen[key]
}

// md5hex is the server-side digest helper for the fake. crypto/md5 in a test
// file is fine; the client-side hash lives in internal/digest.
func md5hex(s string) string {
	sum := md5.Sum([]byte(s))
	return hex.EncodeToString(sum[:])
}

func digestFields(value string) map[string]string {
	fields := map[string]string{}
	for _, part := range strings.Split(value, ",") {
		eq := strings.Index(part, "=")
		if eq <= 0 {
			continue
		}
		key := strings.TrimSpace(part[:eq])
		key = strings.TrimPrefix(key, "Digest ")
		raw := strings.TrimSpace(part[eq+1:])
		if len(raw) >= 2 && strings.HasPrefix(raw, `"`) && strings.HasSuffix(raw, `"`) {
			raw = raw[1 : len(raw)-1]
		}
		fields[key] = raw
	}
	return fields
}

// digestResponse is the server side of the digest exchange, mirroring
// DigestAuthenticator.computeResponse.
func digestResponse(user, pass, realm, method, uri, nonce, nc, cnonce, qop string) string {
	ha1 := md5hex(user + ":" + realm + ":" + pass)
	ha2 := md5hex(strings.ToUpper(method) + ":" + uri)
	if qop == "" {
		return md5hex(ha1 + ":" + nonce + ":" + ha2)
	}
	return md5hex(ha1 + ":" + nonce + ":" + nc + ":" + cnonce + ":" + qop + ":" + ha2)
}

// --- tests -----------------------------------------------------------------

// TestProbeSucceedsBeforeAnyCredentials covers the pre-handshake capability
// check: OPTIONS is the one method the server answers unauthenticated.
func TestProbeSucceedsBeforeAnyCredentials(t *testing.T) {
	f := newFakeServer(t)
	if err := f.client.Probe(context.Background()); err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if got := f.client.Client.NonceCount(); got != 0 {
		t.Errorf("Probe recorded a nonce (got %d); it must not consume a challenge", got)
	}
}

// TestProbeRejectsNonWebDav checks that a plain HTTP endpoint is reported as
// such rather than producing a confusing protocol error later.
func TestProbeRejectsNonWebDav(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	defer srv.Close()
	c := New(srv.URL, fakeUser, fakePass, fakeRealm)
	err := c.Probe(context.Background())
	if !errors.Is(err, ErrNotWebDav) {
		t.Fatalf("Probe on a non-WebDAV endpoint = %v, want ErrNotWebDav", err)
	}
}

// TestChallengeIsAnsweredTransparently is gap 1's happy path: the first request
// 401s, the client answers, and the caller never sees the challenge.
func TestChallengeIsAnsweredTransparently(t *testing.T) {
	f := newFakeServer(t)
	f.putFile("/hello.txt", []byte("hello"))

	resp, err := f.client.Get(context.Background(), "/hello.txt")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	defer resp.Close()
	body, err := io.ReadAll(resp)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(body) != "hello" {
		t.Errorf("body = %q, want %q", body, "hello")
	}
	if got := f.client.Client.NonceCount(); got != 1 {
		t.Errorf("nonce count = %d, want 1", got)
	}
}

// TestRequestURIIsRootRelative pins the form of the Authorization `uri` field.
//
// The server hashes `method:uri` from its own view of the request line. A
// client that puts the absolute URL there produces a hash the server can never
// match, and every request 401s with no visible cause. This asserts the
// relative form was used, which the fake server's own HA2 computation enforces
// — a wrong form simply fails to authenticate.
func TestRequestURIIsRootRelative(t *testing.T) {
	f := newFakeServer(t)
	f.putFile("/hello.txt", []byte("hello"))

	if _, err := f.client.Get(context.Background(), "/hello.txt"); err != nil {
		t.Fatalf("Get: %v", err)
	}
	for i, rec := range f.authCallsSlice() {
		if rec.uri != "/hello.txt" {
			t.Errorf("auth[%d] uri = %q, want the root-relative request-URI", i, rec.uri)
		}
		if !strings.HasPrefix(rec.uri, "/") || strings.Contains(rec.uri, "://") {
			t.Errorf("auth[%d] uri = %q, want no scheme or host", i, rec.uri)
		}
	}
}

// TestStaleChallengeRotatesNonce is gap 1's second half: a nonce the server
// has decided is stale must produce a fresh challenge and a retry that
// succeeds, and the nonce-count must restart rather than continue climbing on a
// nonce the server has thrown away.
func TestStaleChallengeRotatesNonce(t *testing.T) {
	f := newFakeServer(t)
	f.putFile("/a.txt", []byte("a"))

	// First request completes the handshake.
	if _, err := f.client.Get(context.Background(), "/a.txt"); err != nil {
		t.Fatalf("first Get: %v", err)
	}
	before := f.client.Client.NonceCount()

	// Invalidate the nonce the client is holding, so the next request carries one
	// the server has decided to drop.
	f.armStale()

	if _, err := f.client.Get(context.Background(), "/a.txt"); err != nil {
		t.Fatalf("Get after stale: %v", err)
	}

	after := f.client.Client.NonceCount()
	if after != 1 {
		t.Errorf("nonce count after a stale rotation = %d, want 1 (the counter restarts)", after)
	}
	if before != 1 {
		t.Errorf("nonce count before the rotation = %d, want 1", before)
	}
	// The nonce actually used must be the one from the stale challenge.
	records := f.authCallsSlice()
	last := records[len(records)-1]
	if !strings.HasPrefix(last.nonce, "nonce-") {
		t.Errorf("final nonce = %q, want the freshly issued one", last.nonce)
	}
}

// TestForeignRealmIsNotAnswered is gap 2's refusal path.
//
// A challenge whose realm is not ours means something else is listening on this
// address. Answering it would hand our credentials to that peer; the client
// must surface the 401 instead.
func TestForeignRealmIsNotAnswered(t *testing.T) {
	f := newFakeServer(t)
	f.putFile("/a.txt", []byte("a"))

	f.mu.Lock()
	f.realmOverride = "Some Other Realm"
	f.mu.Unlock()

	_, err := f.client.Get(context.Background(), "/a.txt")
	if err == nil {
		t.Fatal("Get against a foreign realm succeeded; the client must not answer")
	}
	if Code(err) != http.StatusUnauthorized {
		t.Fatalf("error = %v, want 401", err)
	}
}

// TestOpaqueIsEchoed pins gap 2's other half: the client must send back the
// opaque the server handed it, verbatim.
//
// The Kotlin server only compares opaque when it is non-blank
// (DigestAuthenticator.verify), so a client that drops the field still works —
// which is exactly why this is worth pinning: the day the server makes it
// mandatory, a client that never echoes it breaks with no client-side symptom.
func TestOpaqueIsEchoed(t *testing.T) {
	f := newFakeServer(t)
	f.putFile("/a.txt", []byte("a"))

	if _, err := f.client.Get(context.Background(), "/a.txt"); err != nil {
		t.Fatalf("Get: %v", err)
	}
	records := f.authCallsSlice()
	if len(records) == 0 {
		t.Fatal("no Authorization header reached the server")
	}
	last := records[len(records)-1]
	if last.opaque == "" {
		t.Fatal("no opaque was echoed; the server sent one and the client dropped it")
	}
	if !strings.HasPrefix(last.opaque, "opaque-") {
		t.Errorf("opaque = %q, want the server's own value echoed back", last.opaque)
	}
}

// TestNonceCountClimbs guards the replay defence: the server rejects an nc that
// does not strictly increase, so the client must not reuse one.
func TestNonceCountClimbs(t *testing.T) {
	f := newFakeServer(t)
	f.putFile("/a.txt", []byte("a"))

	for i := 1; i <= 3; i++ {
		if _, err := f.client.Get(context.Background(), "/a.txt"); err != nil {
			t.Fatalf("Get #%d: %v", i, err)
		}
	}
	want := []string{"00000001", "00000002", "00000003"}
	for i, rec := range f.authCallsSlice() {
		if rec.nc != want[i] {
			t.Errorf("request %d nc = %q, want %q", i+1, rec.nc, want[i])
		}
	}
}

// TestCnonceIsStableWithinSession: the server requires cnonce to be present
// when qop=auth, and it participates in the response hash. It does not require
// it to change, so a stable per-session value is correct and is what makes the
// hash reproducible for the same request.
func TestCnonceIsStableWithinSession(t *testing.T) {
	f := newFakeServer(t)
	f.putFile("/a.txt", []byte("a"))

	if _, err := f.client.Get(context.Background(), "/a.txt"); err != nil {
		t.Fatalf("first Get: %v", err)
	}
	if _, err := f.client.Get(context.Background(), "/a.txt"); err != nil {
		t.Fatalf("second Get: %v", err)
	}
	records := f.authCallsSlice()
	if records[0].cnonce != records[1].cnonce {
		t.Errorf("cnonce changed between requests: %q then %q",
			records[0].cnonce, records[1].cnonce)
	}
	if records[0].cnonce == "" {
		t.Error("cnonce is empty; the server requires it with qop=auth")
	}
}

// TestDepthIsAlwaysSent is gap 5.
//
// The server defaults a missing Depth to "1", so an omitted header appears to
// work — until the server or an intermediary changes the default, and the
// caller concludes an empty folder is empty. Depth 0 must also be honoured: it
// is the one case where a listing with one entry is correct.
func TestDepthIsAlwaysSent(t *testing.T) {
	f := newFakeServer(t)
	f.putFile("/docs/one.txt", []byte("1"))
	f.putFile("/docs/two.txt", []byte("2"))

	all, err := f.client.Propfind(context.Background(), "/docs", "1")
	if err != nil {
		t.Fatalf("Propfind depth 1: %v", err)
	}
	if len(all) < 3 {
		t.Errorf("depth 1 returned %d entries, want the collection plus its children", len(all))
	}

	one, err := f.client.Propfind(context.Background(), "/docs", "0")
	if err != nil {
		t.Fatalf("Propfind depth 0: %v", err)
	}
	if len(one) != 1 {
		t.Errorf("depth 0 returned %d entries, want exactly 1", len(one))
	}

	// "infinity" is treated as "1" by this server; a client must not assume it
	// gets more.
	inf, err := f.client.Propfind(context.Background(), "/docs", "infinity")
	if err != nil {
		t.Fatalf("Propfind infinity: %v", err)
	}
	if len(inf) != len(all) {
		t.Errorf("infinity returned %d entries, depth 1 returned %d; this server treats them alike",
			len(inf), len(all))
	}
}

// TestPropfindParsesRealServerShape guards the parser against the exact XML
// WebDavXml emits: properties nested in propstat/prop, iscollection as 0/1, and
// resourcetype/collection as the directory marker.
func TestPropfindParsesRealServerShape(t *testing.T) {
	f := newFakeServer(t)
	f.putFile("/dir/file.txt", []byte("payload"))

	nodes, err := f.client.Propfind(context.Background(), "/dir", "1")
	if err != nil {
		t.Fatalf("Propfind: %v", err)
	}
	if len(nodes) == 0 {
		t.Fatal("no entries parsed")
	}
	var dir, file *Node
	for i := range nodes {
		switch nodes[i].Href {
		case "/dir/":
			dir = &nodes[i]
		case "/dir/file.txt":
			file = &nodes[i]
		}
	}
	if dir == nil {
		var hrefs []string
		for _, n := range nodes {
			hrefs = append(hrefs, n.Href)
		}
		t.Fatalf("collection entry missing from %v", hrefs)
	}
	if !dir.IsDir {
		t.Error("collection entry is not marked as a directory")
	}
	if file == nil {
		t.Fatal("child entry missing")
	}
	if file.IsDir {
		t.Error("file entry is marked as a directory")
	}
	if file.Length != int64(len("payload")) {
		t.Errorf("file length = %d, want %d", file.Length, len("payload"))
	}
	if file.LastModified.IsZero() {
		t.Error("getlastmodified was not parsed")
	}
	if !file.SupportedLock {
		t.Error("supportedlock was not parsed; the server does emit it")
	}
}

// TestRelativeDestination is gap 3.
//
// The Kotlin tests only ever send an absolute URL; Windows' redirector sends
// the request-URI form. The server accepts both, and a client that can only
// produce one of them will pass its own tests while failing on Windows.
func TestRelativeDestination(t *testing.T) {
	for _, style := range []DestinationStyle{DestAbsolute, DestRelative} {
		t.Run(style.String(), func(t *testing.T) {
			f := newFakeServer(t)
			f.putFile("/src.txt", []byte("moved"))

			resp, err := f.client.MoveOrCopy(context.Background(), "MOVE", "/src.txt",
				"/dst.txt", true, style)
			if err != nil {
				t.Fatalf("MOVE: %v", err)
			}
			resp.Body.Close()
			if resp.StatusCode != http.StatusCreated {
				t.Fatalf("MOVE status = %d, want 201", resp.StatusCode)
			}
			if _, ok := f.file("/dst.txt"); !ok {
				t.Errorf("destination /dst.txt does not exist after MOVE with %s", style)
			}
			if _, ok := f.file("/src.txt"); ok {
				t.Errorf("source still present after MOVE with %s", style)
			}
		})
	}
}

// TestOverwriteHeaderIsSent pins gap 4 on the client side.
//
// The server ignores the header today, so this asserts the client *sends* it —
// the wire format a future server-side check will read — and records that the
// 412 is not produced yet.
func TestOverwriteHeaderIsSent(t *testing.T) {
	f := newFakeServer(t)
	f.putFile("/src.txt", []byte("a"))
	f.putFile("/dst.txt", []byte("b"))

	resp, err := f.client.MoveOrCopy(context.Background(), "COPY", "/src.txt",
		"/dst.txt", false, DestAbsolute)
	if err != nil {
		t.Fatalf("COPY: %v", err)
	}
	resp.Body.Close()

	h := f.lastHeader("COPY /src.txt")
	if got := h.Get("Overwrite"); got != "F" {
		t.Errorf("Overwrite header = %q, want \"F\" (RFC 4918 §10.6: refuse to overwrite)", got)
	}
	// Recorded, not fixed: the server ignores Overwrite, so a request that asked
	// not to overwrite still succeeds.
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusNoContent {
		t.Errorf("COPY status = %d", resp.StatusCode)
	}
}

// TestErrorBodiesArePlainText is gap 7.
//
// The server answers every failure with a short reason phrase, not a DAV
// <error> document. A client that only understands XML errors reports an empty
// or useless message, which is the difference between "404 Not Found" and a
// bare status code when a sync fails in the field.
func TestErrorBodiesArePlainText(t *testing.T) {
	f := newFakeServer(t)

	_, err := f.client.Get(context.Background(), "/missing.txt")
	if err == nil {
		t.Fatal("Get of a missing file succeeded")
	}
	var se *StatusError
	if !errors.As(err, &se) {
		t.Fatalf("error = %v (%T), want *StatusError", err, err)
	}
	if se.Code != http.StatusNotFound {
		t.Errorf("code = %d, want 404", se.Code)
	}
	if !strings.Contains(se.Message, "404") {
		t.Errorf("message = %q, want the server's plain-text reason", se.Message)
	}
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("errors.Is(err, ErrNotFound) = false; sentinels must match on code")
	}
}

// TestXMLErrorBodyIsAlsoRead keeps the client working if the server ever moves
// to RFC 4918 §11-style errors. The condition element becomes the message.
func TestXMLErrorBodyIsAlsoRead(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "" {
			w.Header().Set("WWW-Authenticate",
				fmt.Sprintf(`Digest realm=%q, qop="auth", nonce="n", opaque="o"`, fakeRealm))
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/xml; charset=utf-8")
		w.WriteHeader(http.StatusConflict)
		fmt.Fprint(w, `<?xml version="1.0" encoding="utf-8"?><D:error xmlns:D="DAV:">`+
			`<D:no-conflicting-lock/></D:error>`)
	}))
	defer srv.Close()
	c := New(srv.URL, fakeUser, fakePass, fakeRealm)

	_, err := c.Get(context.Background(), "/x")
	var se *StatusError
	if !errors.As(err, &se) {
		t.Fatalf("error = %v, want *StatusError", err)
	}
	if se.Code != http.StatusConflict {
		t.Errorf("code = %d, want 409", se.Code)
	}
	if !strings.Contains(se.Message, "no-conflicting-lock") {
		t.Errorf("message = %q, want the DAV condition from the XML body", se.Message)
	}
}

// TestPutSendsIfMatch is gap 8's client half.
func TestPutSendsIfMatch(t *testing.T) {
	f := newFakeServer(t)
	f.putFile("/a.txt", []byte("old"))

	resp, err := f.client.Put(context.Background(), "/a.txt", []byte("new"), `"1735689600000-3"`)
	if err != nil {
		t.Fatalf("Put: %v", err)
	}
	resp.Body.Close()

	h := f.lastHeader("PUT /a.txt If-Match")
	if got := h.Get("If-Match"); got != `"1735689600000-3"` {
		t.Errorf("If-Match = %q, want the entity-tag sent verbatim", got)
	}
	if got, _ := f.file("/a.txt"); string(got) != "new" {
		t.Errorf("file = %q, want the new content (the server ignores If-Match today)", got)
	}
}

// TestGetExposesETag is gap 8's read half: the server emits an ETag, and a
// client that discards it can never send a meaningful If-Match later.
func TestGetExposesETag(t *testing.T) {
	f := newFakeServer(t)
	f.putFile("/a.txt", []byte("content"))

	_, _, header, err := f.client.Get(context.Background(), "/a.txt")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if header.Get("ETag") == "" {
		t.Error("no ETag on the response; the server does send one")
	}
}

// TestStreamingRequestIsNotSilentlyRetried covers the failure mode a retry loop
// creates: a 401 arriving after the body has been consumed.
//
// Silently re-sending with an empty body truncates an upload and reports
// success. The client must refuse instead, and the caller must be told to
// re-read the body.
func TestStreamingRequestIsNotSilentlyRetried(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Always 401: no handshake can complete, so the retry path is reached
		// with a body that has already been consumed.
		w.Header().Set("WWW-Authenticate",
			fmt.Sprintf(`Digest realm=%q, qop="auth", nonce="n", opaque="o"`, fakeRealm))
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()
	c := New(srv.URL, fakeUser, fakePass, fakeRealm)

	_, err := c.Do(context.Background(), "PUT", "/a.txt",
		strings.NewReader("payload"), map[string]string{"Content-Type": "application/octet-stream"})
	if !errors.Is(err, ErrStreamingRetry) {
		t.Fatalf("Do with a streaming body = %v, want ErrStreamingRetry", err)
	}
}

// TestPutStreamRefusesWithoutHandshake: an unreplayable upload must not be
// sent before the handshake has completed, because a 401 then is unrecoverable.
func TestPutStreamRefusesWithoutHandshake(t *testing.T) {
	f := newFakeServer(t)
	f.putFile("/a.txt", []byte("x"))

	_, err := f.client.PutStream(context.Background(), "/b.txt",
		strings.NewReader("payload"), -1)
	if !errors.Is(err, ErrNoChallenge) {
		t.Fatalf("PutStream before a handshake = %v, want ErrNoChallenge", err)
	}

	// After a replayable request the handshake is on record and the stream goes
	// through.
	if _, err := f.client.Get(context.Background(), "/a.txt"); err != nil {
		t.Fatalf("handshake Get: %v", err)
	}
	resp, err := f.client.PutStream(context.Background(), "/b.txt",
		strings.NewReader("streamed"), int64(len("streamed")))
	if err != nil {
		t.Fatalf("PutStream after handshake: %v", err)
	}
	resp.Body.Close()
	if got, _ := f.file("/b.txt"); string(got) != "streamed" {
		t.Errorf("file = %q, want %q", got, "streamed")
	}
}

// TestProppatchGets207WithCurrentValues is gap 6.
//
// The server ignores the request body and answers with the resource's current
// properties. A client that expects an echo of what it sent would report a
// failure that did not happen; one that expects the values to have changed
// would never notice they did not.
func TestProppatchGets207WithCurrentValues(t *testing.T) {
	f := newFakeServer(t)
	f.putFile("/a.txt", []byte("content"))

	nodes, resp, err := f.client.Proppatch(context.Background(), "/a.txt",
		map[string]string{"displayname": "renamed.txt"})
	if err != nil {
		t.Fatalf("Proppatch: %v", err)
	}
	if resp.StatusCode != http.StatusMultiStatus {
		t.Errorf("status = %d, want 207", resp.StatusCode)
	}
	if len(nodes) != 1 {
		t.Fatalf("got %d nodes, want 1", len(nodes))
	}
	// The name is still the href-derived one, because the server applied
	// nothing. This is the assertion that would catch a client believing the
	// rename took effect.
	if nodes[0].Href != "/a.txt" {
		t.Errorf("href = %q, want /a.txt (the server applies no properties)", nodes[0].Href)
	}
}

// TestLockReturnsTokenAndUnlockReleasesIt covers the token lifecycle, including
// the server's angle-bracket wrapping.
func TestLockReturnsTokenAndUnlockReleasesIt(t *testing.T) {
	f := newFakeServer(t)
	f.putFile("/a.txt", []byte("x"))

	token, resp, err := f.client.Lock(context.Background(), "/a.txt")
	if err != nil {
		t.Fatalf("Lock: %v", err)
	}
	resp.Body.Close()
	if token == "" {
		t.Fatal("no lock token returned")
	}
	if strings.ContainsAny(token, "<>") {
		t.Errorf("token = %q, want the angle brackets stripped", token)
	}

	unlock, err := f.client.Unlock(context.Background(), "/a.txt", token)
	if err != nil {
		t.Fatalf("Unlock: %v", err)
	}
	unlock.Body.Close()
	if unlock.StatusCode != http.StatusNoContent {
		t.Errorf("UNLOCK status = %d, want 204", unlock.StatusCode)
	}
}

// TestMkcolSendsNoBody: RFC 4918 §9.3, and a body is the usual cause of a
// mysterious 415 from servers that check.
func TestMkcolSendsNoBody(t *testing.T) {
	f := newFakeServer(t)

	resp, err := f.client.Mkcol(context.Background(), "/newdir")
	if err != nil {
		t.Fatalf("Mkcol: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("MKCOL status = %d, want 201", resp.StatusCode)
	}
	if got := resp.Request.ContentLength; got != 0 {
		t.Errorf("request Content-Length = %d, want 0", got)
	}
	if _, ok := f.file("/newdir/"); !ok {
		t.Error("directory was not created")
	}
}

// TestNamespacePrefixDoesNotMatter: the server emits `D:` bound to `DAV:`, but
// a conforming server may use any prefix or a default namespace. The parser
// must not depend on the literal prefix.
func TestNamespacePrefixDoesNotMatter(t *testing.T) {
	body := `<?xml version="1.0" encoding="utf-8"?>` +
		`<multistatus xmlns="DAV:">` +
		`<response><href>/a.txt</href><propstat><prop>` +
		`<displayname>a.txt</displayname><iscollection>0</iscollection>` +
		`<getcontentlength>7</getcontentlength>` +
		`</prop><status>HTTP/1.1 200 OK</status></propstat></response>` +
		`</multistatus>`
	nodes, err := parseMultistatus(strings.NewReader(body))
	if err != nil {
		t.Fatalf("parseMultistatus: %v", err)
	}
	if len(nodes) != 1 {
		t.Fatalf("got %d nodes, want 1", len(nodes))
	}
	if nodes[0].Name != "a.txt" {
		t.Errorf("name = %q, want a.txt", nodes[0].Name)
	}
	if nodes[0].Length != 7 {
		t.Errorf("length = %d, want 7", nodes[0].Length)
	}
}

// TestNonASCIINameRoundTrips is the percent-encoding contract with the Kotlin
// side: escapes encode bytes, decoded as one UTF-8 run, and `+` is not a space.
func TestNonASCIINameRoundTrips(t *testing.T) {
	name := "文件 1+2.txt"
	encoded := JoinSegments("docs", name)
	if !strings.Contains(encoded, "%E6%96%87") {
		t.Errorf("encoded = %q, want the UTF-8 bytes percent-encoded", encoded)
	}
	if strings.Contains(encoded, "+") {
		t.Errorf("encoded = %q, want '+' left as-is (a path is not a query)", encoded)
	}
	if !strings.Contains(encoded, "%20") {
		t.Errorf("encoded = %q, want a space as %%20", encoded)
	}
	back, err := percentDecode(strings.TrimPrefix(encoded, "/docs/"))
	if err != nil {
		t.Fatalf("percentDecode: %v", err)
	}
	if back != name {
		t.Errorf("round-trip = %q, want %q", back, name)
	}
}

// TestContextCancellationStopsTheRequest: a cancelled context must surface as
// an error rather than a hang, which is what makes a CfApi cancel callback
// implementable.
func TestContextCancellationStopsTheRequest(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
	}))
	defer srv.Close()
	defer close(release)

	c := New(srv.URL, fakeUser, fakePass, fakeRealm)
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(20 * time.Millisecond)
		cancel()
	}()
	start := time.Now()
	if _, err := c.Do(ctx, "PROPFIND", "/", nil, map[string]string{"Depth": "0"}); err == nil {
		t.Fatal("cancelled request returned no error")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("request took %v after cancellation; it did not stop promptly", elapsed)
	}
}

// --- small accessors used above -------------------------------------------

func (f *fakeServer) authCallsSlice() []authRecord { return f.authRecords() }

func (f *fakeServer) putFile(name string, body []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.files[name] = body
}

func (f *fakeServer) file(name string) ([]byte, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	b, ok := f.files[name]
	return b, ok
}

// armStale invalidates the nonce the client is currently holding, so the next
// request carries one the server will refuse and answer with stale=true. This
// is how a genuine expiry arrives; the flag exists so a test need not wait out
// the 300s lifetime.
func (f *fakeServer) armStale() {
	f.mu.Lock()
	f.forceStale = true
	f.mu.Unlock()
}
