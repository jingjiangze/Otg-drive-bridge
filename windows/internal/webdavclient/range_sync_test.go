package webdavclient

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// --- Range -------------------------------------------------------------------
//
// The server did not implement Range until 1979f4f; the client therefore has to
// cope with a 200 answer to a request for a slice, which is what a WebDAV
// endpoint without Range support is required to do (RFC 9110 §14.2: an
// unsupported Range is ignored, not an error). The three-way outcome is the
// thing worth pinning.

func TestGetRangeSlicesTheBody(t *testing.T) {
	f := newFakeServer(t)
	f.putFile("/a.txt", []byte("0123456789"))

	slice, err := f.client.GetRange(context.Background(), "/a.txt", 2, 5)
	if err != nil {
		t.Fatalf("GetRange: %v", err)
	}
	defer slice.Body.Close()
	if slice.Status != http.StatusPartialContent {
		t.Fatalf("status = %d, want 206", slice.Status)
	}
	got, err := io.ReadAll(slice.Body)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(got) != "2345" {
		t.Errorf("body = %q, want %q", got, "2345")
	}
	if slice.FirstByte != 2 || slice.CompleteBytes != 4 || slice.TotalBytes != 10 {
		t.Errorf("range = %d+%d/%d, want 2+4/10",
			slice.FirstByte, slice.CompleteBytes, slice.TotalBytes)
	}
}

func TestGetRangeClampsPastTheEnd(t *testing.T) {
	f := newFakeServer(t)
	f.putFile("/a.txt", []byte("0123456789"))

	slice, err := f.client.GetRange(context.Background(), "/a.txt", 6, 9999)
	if err != nil {
		t.Fatalf("GetRange: %v", err)
	}
	defer slice.Body.Close()
	if slice.Status != http.StatusPartialContent {
		t.Fatalf("status = %d, want 206 (a last-byte past the end clamps)", slice.Status)
	}
	got, _ := io.ReadAll(slice.Body)
	if string(got) != "6789" {
		t.Errorf("body = %q, want %q", got, "6789")
	}
	// The clamped length, not the one asked for.
	if slice.CompleteBytes != 4 || slice.TotalBytes != 10 {
		t.Errorf("range = %d+%d/%d, want 6+4/10",
			slice.FirstByte, slice.CompleteBytes, slice.TotalBytes)
	}
}

func TestGetRangePastTheEndIs416WithTheRealLength(t *testing.T) {
	f := newFakeServer(t)
	f.putFile("/a.txt", []byte("0123456789"))

	slice, err := f.client.GetRange(context.Background(), "/a.txt", 20, 30)
	if err != nil {
		t.Fatalf("GetRange: %v", err)
	}
	if slice.Status != http.StatusRequestedRangeNotSatisfiable {
		t.Fatalf("status = %d, want 416", slice.Status)
	}
	if slice.Body != nil {
		slice.Body.Close()
		t.Error("416 carries a body; it must not")
	}
	// The total is the useful part of a 416: it tells the caller the file's real
	// size without a second HEAD.
	if slice.TotalBytes != 10 {
		t.Errorf("total = %d, want 10", slice.TotalBytes)
	}
}

func TestGetRangeFallsBackToFull200WithoutServerSupport(t *testing.T) {
	f := newFakeServer(t)
	f.rangeEnabled = false
	f.putFile("/a.txt", []byte("0123456789"))

	slice, err := f.client.GetRange(context.Background(), "/a.txt", 2, 5)
	if err != nil {
		t.Fatalf("GetRange: %v", err)
	}
	defer slice.Body.Close()
	if slice.Status != http.StatusOK {
		t.Fatalf("status = %d, want 200 (the server ignored Range)", slice.Status)
	}
	got, _ := io.ReadAll(slice.Body)
	if string(got) != "0123456789" {
		t.Errorf("body = %q, want the whole file", got)
	}
	if slice.TotalBytes != 10 || slice.FirstByte != 0 {
		t.Errorf("range = %d+?/%d, want 0+?/10", slice.FirstByte, slice.TotalBytes)
	}
}

func TestGetRangeRefusesBadRangesLocally(t *testing.T) {
	f := newFakeServer(t)
	f.putFile("/a.txt", []byte("0123456789"))

	// First a good one, so the assertion below has something to compare
	// against: without it `lastHeader` returns nil and the check silently
	// passes whether or not a bad range ever reached the wire.
	good, err := f.client.GetRange(context.Background(), "/a.txt", 2, 5)
	if err != nil {
		t.Fatalf("GetRange(2,5): %v", err)
	}
	good.Body.Close()

	for _, pair := range [][2]int64{{-1, 5}, {5, 2}, {-1, -1}} {
		slice, err := f.client.GetRange(context.Background(), "/a.txt", pair[0], pair[1])
		if err == nil {
			t.Errorf("GetRange(%d,%d) returned %+v with no error", pair[0], pair[1], slice)
			if slice != nil && slice.Body != nil {
				slice.Body.Close()
			}
		}
	}
	// A reversed or negative range must not reach the wire: sending it would
	// have the server decide what to ignore, and the client would then have to
	// interpret a full 200 as if it were the answer to a question it never asked.
	h := f.lastHeader("GET /a.txt")
	if h == nil {
		t.Fatal("no GET /a.txt recorded at all; the good range above should have been")
	}
	if got := h.Get("Range"); got != "bytes=2-5" {
		t.Errorf("Range on the wire = %q, want the good bytes=2-5 and nothing else", got)
	}
}

func TestGetRangeOnMissingFileIsNotFound(t *testing.T) {
	f := newFakeServer(t)

	slice, err := f.client.GetRange(context.Background(), "/nope.txt", 0, 1)
	if slice != nil && slice.Body != nil {
		slice.Body.Close()
	}
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetRange on a missing file = %v, want ErrNotFound", err)
	}
}

func TestContentRangeParsing(t *testing.T) {
	cases := []struct {
		header                 string
		first, complete, total int64
		ok                     bool
	}{
		{"bytes 0-99/1000", 0, 100, 1000, true},
		{"bytes 5-9/10", 5, 5, 10, true},
		{"bytes 0-0/1", 0, 1, 1, true},
		// A total of 0 is impossible on the wire and would zero out the caller's
		// progress arithmetic, so it is refused rather than returned.
		{"bytes 0-0/0", 0, 0, 0, false},
		{"", 0, 0, 0, false},
		{"bytes */10", 0, 0, 0, false},
		{"bytes 9-0/10", 0, 0, 0, false},
		{"bytes 0-x/10", 0, 0, 0, false},
		{"bytes 0-10", 0, 0, 0, false},
		{"items 0-9/10", 0, 0, 0, false},
	}
	for _, c := range cases {
		first, complete, total, ok := parseContentRange(c.header)
		if ok != c.ok {
			t.Errorf("parseContentRange(%q) ok = %v, want %v", c.header, ok, c.ok)
			continue
		}
		if !ok {
			continue
		}
		// The one invariant worth asserting beyond the parsed values: the
		// complete byte count is the inclusive interval's width, and the whole
		// interval lies inside the total. Anything else means the caller's
		// progress arithmetic is being fed a slice that cannot exist.
		if complete != c.complete || complete <= 0 {
			t.Errorf("parseContentRange(%q) complete = %d, want %d (a positive interval width)",
				c.header, complete, c.complete)
		}
		if first+complete > total {
			t.Errorf("parseContentRange(%q) = bytes %d-%d/%d: the interval runs past the total",
				c.header, first, first+complete-1, total)
		}
		if first != c.first || total != c.total {
			t.Errorf("parseContentRange(%q) = %d+%d/%d, want first=%d total=%d",
				c.header, first, complete, total, c.first, c.total)
		}
	}
}

func TestUnsatisfiableLengthParsing(t *testing.T) {
	if got := parseUnsatisfiableLength("bytes */12345"); got != 12345 {
		t.Errorf("parseUnsatisfiableLength = %d, want 12345", got)
	}
	if got := parseUnsatisfiableLength(""); got != 0 {
		t.Errorf("an absent header must read as 0 (unknown), got %d", got)
	}
	if got := parseUnsatisfiableLength("bytes */notanumber"); got != 0 {
		t.Errorf("a malformed header must read as 0, got %d", got)
	}
}

func TestFormatRange(t *testing.T) {
	got, err := FormatRange(0, 0)
	if err != nil || got != "bytes=0-0" {
		t.Errorf("FormatRange(0,0) = %q, %v; want bytes=0-0", got, err)
	}
	got, err = FormatRange(1024, 2047)
	if err != nil || got != "bytes=1024-2047" {
		t.Errorf("FormatRange(1024,2047) = %q, %v", got, err)
	}
	if _, err := FormatRange(-1, 0); err == nil {
		t.Error("FormatRange accepted a negative first byte")
	}
	if _, err := FormatRange(10, 5); err == nil {
		t.Error("FormatRange accepted a reversed range")
	}
}

// --- sync-collection (RFC 6578) ---------------------------------------------

func TestSyncCollectionReportsChangedAndRemoved(t *testing.T) {
	f := newFakeServer(t)
	f.putFile("/kept.txt", []byte("one"))
	f.putFile("/new.txt", []byte("two"))
	f.reported = []string{"/kept.txt", "/new.txt", "/gone.txt"}

	result, err := f.client.SyncCollection(context.Background(), "/", "", SyncLevel1)
	if err != nil {
		t.Fatalf("SyncCollection: %v", err)
	}
	if len(result.Changed) != 2 {
		t.Fatalf("changed = %d, want 2 (%v)", len(result.Changed), result.Changed)
	}
	if len(result.Removed) != 1 || result.Removed[0].Href != "/gone.txt" {
		t.Fatalf("removed = %+v, want just /gone.txt", result.Removed)
	}
	for _, change := range result.Changed {
		if change.Node.ETag == "" {
			t.Errorf("%s came back with no getetag; the request asked for one", change.Href)
		}
	}
	// The token must be echoed verbatim next time — the whole mechanism is that
	// the client does not understand it.
	if result.Token == "" {
		t.Error("no sync-token in the response; the next report could not ask for a delta")
	}
}

func TestSyncCollectionTokenRoundTrips(t *testing.T) {
	f := newFakeServer(t)
	f.putFile("/a.txt", []byte("one"))
	f.reported = []string{"/a.txt"}
	token := f.nextToken

	first, err := f.client.SyncCollection(context.Background(), "/", "", SyncLevel1)
	if err != nil {
		t.Fatalf("initial sync: %v", err)
	}
	if first.Token != token {
		t.Fatalf("token = %q, want %q", first.Token, token)
	}
	// Sending the token back must be accepted; the fake answers the same report
	// again because it does not track deltas, so what this pins is that the
	// token is not rejected — not that the delta is empty.
	second, err := f.client.SyncCollection(context.Background(), "/", token, SyncLevel1)
	if err != nil {
		t.Fatalf("second sync: %v", err)
	}
	if second.Token != token {
		t.Errorf("second token = %q, want %q", second.Token, token)
	}
}

func TestSyncCollectionRejectsAnInventedToken(t *testing.T) {
	f := newFakeServer(t)
	f.putFile("/a.txt", []byte("one"))

	_, err := f.client.SyncCollection(context.Background(), "/", "https://jingjiangze.otgdrivebridge/ns#sync/9999", SyncLevel1)
	if !errors.Is(err, ErrPrecondition) {
		t.Fatalf("SyncCollection with a made-up token = %v, want 412 ErrPrecondition", err)
	}
	// A 412 here is not a failure: RFC 6578 §3.4 says it means "sync from
	// scratch". The client's job is to surface the status so the caller can
	// retry with an empty token, which is what ErrPrecondition lets it do.
	if Code(err) != http.StatusPreconditionFailed {
		t.Errorf("Code(err) = %d, want 412", Code(err))
	}
}

func TestSyncCollectionRefusesANonRootCollection(t *testing.T) {
	f := newFakeServer(t)
	f.putFile("/sub/a.txt", []byte("one"))

	_, err := f.client.SyncCollection(context.Background(), "/sub", "", SyncLevel1)
	if !errors.Is(err, ErrForbidden) {
		t.Fatalf("SyncCollection on /sub = %v, want 403 ErrForbidden", err)
	}
}

func TestSyncCollectionSendsDepthZero(t *testing.T) {
	f := newFakeServer(t)
	f.putFile("/a.txt", []byte("one"))
	f.reported = []string{"/a.txt"}

	if _, err := f.client.SyncCollection(context.Background(), "/", "", SyncLevel1); err != nil {
		t.Fatalf("SyncCollection: %v", err)
	}
	h := f.lastHeader("REPORT /")
	if h == nil {
		t.Fatal("no REPORT recorded")
	}
	if got := h.Get("Depth"); got != "0" {
		t.Errorf("Depth = %q, want 0 (RFC 6578 §3.2 pins it; sync-level scopes the report, not Depth)", got)
	}
}

func TestBuildSyncRequestNamesTheProperties(t *testing.T) {
	body := string(BuildSyncRequest("tok", SyncLevelInfinite))
	for _, want := range []string{"<D:sync-token>tok</D:sync-token>", "<D:sync-level>infinite</D:sync-level>", "<D:getetag/>", "<D:getlastmodified/>"} {
		if !strings.Contains(body, want) {
			t.Errorf("request body is missing %s:\n%s", want, body)
		}
	}
	if strings.Contains(body, "<D:limit>") {
		t.Error("the client must not send a limit; the server truncates by design and a client that asks for one is asking for a partial answer it cannot detect")
	}
}

func TestSyncCollectionWithoutATokenIsNotASilentStop(t *testing.T) {
	// A server that answers REPORT with a PROPFIND-shaped multistatus (no
	// sync-token) must not be read as "nothing changed": the client would stop
	// syncing silently. The empty token is the visible signal.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml; charset=utf-8")
		w.WriteHeader(http.StatusMultiStatus)
		fmt.Fprint(w, `<?xml version="1.0" encoding="utf-8"?><D:multistatus xmlns:D="DAV:">`+
			`</D:multistatus>`)
	}))
	defer srv.Close()
	c := New(srv.URL, fakeUser, fakePass, fakeRealm)

	result, err := c.SyncCollection(context.Background(), "/", "", SyncLevel1)
	if err != nil {
		t.Fatalf("SyncCollection: %v", err)
	}
	if result.Token != "" {
		t.Errorf("a multistatus with no sync-token produced %q; that cannot be used for a delta", result.Token)
	}
}

// --- traversal defence ------------------------------------------------------

func TestTraversalPathsNeverReachTheWire(t *testing.T) {
	f := newFakeServer(t)
	f.putFile("/a.txt", []byte("one"))

	bad := []string{
		"/../etc/passwd",
		"/a/../../b",
		"/%2e%2e/etc",
		"/..%2f..%2fetc",
		"/a/\x00b",
	}
	for _, path := range bad {
		body, _, _, err := f.client.Get(context.Background(), path)
		if body != nil {
			body.Close()
		}
		if !errors.Is(err, ErrUnsafePath) {
			t.Errorf("Get(%q) = %v, want ErrUnsafePath", path, err)
		}
	}
}

func TestEncodedNamesStillPass(t *testing.T) {
	f := newFakeServer(t)
	// The file is named 中文.txt. Stored under the decoded name, because that
	// is what the real server serves on — see storedPath. The client is still
	// handed the percent-encoded spelling, so this exercises the round trip.
	f.putFile("/中文.txt", []byte("one"))

	// A percent-encoded UTF-8 name is legal and must not be caught by the guard:
	// the guard is about traversal, not about encoding.
	body, _, _, err := f.client.Get(context.Background(), "/%E4%B8%AD%E6%96%87.txt")
	if err != nil {
		t.Fatalf("Get with an encoded name: %v", err)
	}
	body.Close()
	// The request on the wire kept the encoding — the guard decoded it to check
	// for traversal, which is the only reason it is allowed to look at it.
	if h := f.lastHeader("GET /%E4%B8%AD%E6%96%87.txt"); h == nil {
		t.Error("the request was never sent")
	}
	// And the same file is reachable through the client's own encoder, so a
	// caller that builds the path from a raw name is not talking to a file the
	// fake cannot find.
	other, _, _, err := f.client.Get(context.Background(), JoinSegments("中文.txt"))
	if err != nil {
		t.Fatalf("Get through JoinSegments: %v", err)
	}
	other.Close()
}
