// Package webdavclient is a WebDAV client for this project's own server,
// written against net/http and nothing else.
//
// It exists because the nine protocol gaps the audit found are all places where
// a general-purpose client makes a choice the Kotlin server does not expect, or
// where the server makes a choice a general client would reject. Reaching for
// studio-b12/gowebdav would have hidden those choices behind its defaults;
// spelling them out here is the point, and it is what makes the cross-language
// interop suite meaningful rather than tautological.
//
// The nine, and where each one lives:
//
//  1. stale re-challenge      Do(): one bounded retry on 401, digest.Client.Use
//  2. opaque mismatch         Do() re-challenges; Client echoes the current
//     opaque rather than caching a header
//  3. relative Destination    DestinationStyle — absolute, relative, or custom
//  4. Overwrite: F → 412      DestinationStyle carries it; the server ignores it
//     today (WebDavRequestHandler.handleCopyOrMove
//     never reads the header), which is recorded in
//     findings.md as a Stage-3 server fix
//  5. Depth                   Propfind always sends it explicitly
//  6. PROPPATCH               BuildProppatch; the server answers 207 with the
//     current values and applies nothing
//  7. error XML shape         ParseError reads this server's plain-text bodies
//     and a DAV XML <error> if one ever arrives
//  8. ETag / If-Match         Put sends If-Match; the server ignores it on PUT
//     but does emit an ETag on GET/HEAD
//  9. 100-continue            Transport.ExpectContinueTimeout; see PutStream
//
// Everything below is written against the server as it is, not as RFC 4918
// would prefer it to be. Where the two differ, the comment says so.
package webdavclient

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/jingjiangze/Otg-drive-bridge/windows/internal/digest"
)

// Server describes one WebDAV endpoint.
type Server struct {
	BaseURL string
	Client  digestClient

	// realm is kept on the Server as well as on the digest client so that a
	// challenge from another realm can be refused before any credential is
	// sent, even when a substituted digestClient is in use.
	realm string

	http *http.Client
}

// digestClient is what this package needs from the digest package. Declared
// here rather than calling digest directly so the interop tests can substitute
// a client that answers with a chosen nonce and opaque, which is the only way
// to drive the stale and opaque-mismatch paths deterministically.
type digestClient interface {
	Authorize(method, uri string) digest.Authorization
	Use(challenge digest.Challenge)
	NonceCount() uint64
}

// New returns a client for [baseURL] speaking Digest in [realm].
//
// The realm must match the server's (DigestAuthenticator.DEFAULT_REALM is
// "OTG Drive Bridge"): Do() refuses to answer a challenge from any other realm
// rather than sending credentials to a peer that happens to share the port.
func New(baseURL, username, password, realm string) *Server {
	return &Server{
		BaseURL: strings.TrimSuffix(baseURL, "/"),
		Client:  digest.NewClient(username, password, realm),
		realm:   realm,
		http: &http.Client{
			// A hydration or upload against a phone over Wi-Fi can legitimately
			// take minutes; the default 30s would abort mid-transfer.
			Timeout: 0,
			Transport: &http.Transport{
				DialContext:           (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
				MaxIdleConns:          8,
				MaxIdleConnsPerHost:   4,
				IdleConnTimeout:       90 * time.Second,
				TLSHandshakeTimeout:   10 * time.Second,
				ResponseHeaderTimeout: 120 * time.Second,
				// Gap 9. Go only waits for a `100 Continue` when this is
				// positive and the request carried an explicit `Expect`. The
				// Ktor server does not implement Expect at all, so this client
				// never sets it; the timeout is set anyway so that the day the
				// server grows the header the behaviour is a bounded wait
				// rather than Go's zero value, which is "never wait" and
				// therefore a silent full-body upload.
				ExpectContinueTimeout: 2 * time.Second,
			},
		},
	}
}

// ErrNotWebDav is returned when the endpoint answers 404 to OPTIONS, which is
// how a wrong port or a plain HTTP server shows up.
var ErrNotWebDav = errors.New("endpoint is not a WebDAV server")

// ErrStreamingRetry reports that a 401 arrived for a request whose body had
// already been consumed, so the handshake cannot be replayed.
//
// The alternative — silently re-sending with an empty body — is how a client
// truncates an upload and reports success. Callers holding the body in memory
// should use DoBytes, which is replayable.
var ErrStreamingRetry = errors.New("webdav: cannot replay a streaming request after a 401")

// Do performs one request. It answers a 401 Digest challenge transparently and
// re-challenges once, which covers both a first request and a nonce that has
// aged out.
//
// It deliberately does not follow the "retry on any 401" pattern several
// clients use: an unbounded retry turns a wrong password into a hang, and one
// retry is enough for the only two legitimate causes (first contact, stale or
// aged-out nonce).
//
// A body that cannot be replayed is refused at the point of the 401 rather than
// re-sent empty; callers that hold the bytes should use DoBytes, which is
// replayable by construction.
func (s *Server) Do(ctx context.Context, method, path string, body io.Reader, headers map[string]string) (*http.Response, error) {
	return s.doReplayable(ctx, method, path, body, headers, nil)
}

// doReplayable is Do with an explicit way to rebuild the body.
//
// [replay] nil means the body is a one-shot stream: the request is answered
// once and a 401 that needs a re-send becomes ErrStreamingRetry. Non-nil means
// the caller can produce a fresh reader, so the second attempt is a complete
// request rather than a truncated one.
func (s *Server) doReplayable(ctx context.Context, method, path string, body io.Reader, headers map[string]string, replay func() io.Reader) (*http.Response, error) {
	streaming := body != nil && body != http.NoBody

	// Whether a challenge has been recorded yet. The very first request of a
	// session has not, and must go out unauthenticated to collect one; every
	// later request carries the answer straight away.
	firstContact := s.Client.NonceCount() == 0

	// The first attempt carries no Authorization: the handshake has not happened
	// yet, and sending an empty or stale header is what produces a 401 whose
	// reason is not "no credentials yet".
	//
	// Once a nonce is known, the attempt is sent *with* Authorization. Sending
	// every request blind and answering the 401 is not a harmless extra round
	// trip: the server counts requests per nonce and rejects a nonce-count that
	// does not strictly increase (DigestAuthenticator.isNcIncreasing), so a
	// client that re-challenges on every request restarts its counter each time
	// and is refused from the second request onward. It also means the request
	// runs twice, which for a body-carrying method is a truncated upload.
	authorization := ""
	if !firstContact {
		authorization = s.authorize(method, path)
	}
	resp, err := s.send(ctx, method, path, body, headers, authorization)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusUnauthorized {
		return resp, nil
	}

	// A 401 on a request that already carried credentials means the nonce the
	// client holds is no longer the server's — aged out, or the server restarted.
	// The challenge below is the fresh one, and answering it is the retry.
	//
	// It can also mean the credentials are simply wrong, which one retry cannot
	// fix and must not turn into a loop: a wrong password otherwise becomes a
	// hang.
	challenge, ok := digest.ParseChallenge(resp.Header.Get("WWW-Authenticate"))
	if !ok {
		// Not a Digest challenge: a plain 401, or Basic. Either way there is
		// nothing to answer with.
		return resp, nil
	}
	// A challenge from another realm is a different origin answering on this
	// address. Sending our credentials to it would be the bug.
	if !strings.EqualFold(challenge.Realm, s.realm) {
		return resp, nil
	}
	if streaming && replay == nil {
		// The body has already been drained by the first attempt. Re-sending it
		// would upload zero bytes and report success, which is the truncation
		// this error exists to prevent. The response is closed rather than
		// returned: a 401 challenge body is one short reason phrase, and handing
		// back an unclosed response invites a caller that checks err first to
		// leak the connection.
		resp.Body.Close()
		return nil, ErrStreamingRetry
	}

	s.Client.Use(challenge)
	retry := body
	if replay != nil {
		retry = replay()
	}
	return s.send(ctx, method, path, retry, headers, s.authorize(method, path))
}

// DoBytes is Do for callers that hold the whole body in memory — the shape a
// PUT of a hydrated file takes.
//
// It keeps its own copy of the bytes so the replay after a 401 is a fresh
// reader rather than a seek: the reader handed to Do has already been drained by
// the first attempt, and a bytes.Reader that was rewound would still be wrong
// the moment a caller passed something else. Building the replay from the
// slice makes "replayable" a property of this function, not of its caller's
// reader type.
func (s *Server) DoBytes(ctx context.Context, method, path string, body []byte, headers map[string]string) (*http.Response, error) {
	var reader io.Reader
	if body != nil {
		reader = bytes.NewReader(body)
	}
	replay := func() io.Reader {
		if body == nil {
			return nil
		}
		return bytes.NewReader(body)
	}
	return s.doReplayable(ctx, method, path, reader, headers, replay)
}

// PutStream uploads from a reader that cannot be replayed.
//
// Because a 401 cannot be retried after the body is consumed, the handshake is
// performed up front: Probe-style OPTIONS is not enough (it is unauthenticated),
// so the caller must have completed at least one DoBytes against the server
// first, which records the challenge. When no challenge has been recorded yet,
// this returns ErrNoChallenge rather than sending a request that will 401 after
// the body is gone.
func (s *Server) PutStream(ctx context.Context, path string, body io.Reader, size int64) (*http.Response, error) {
	if s.Client.NonceCount() == 0 {
		return nil, ErrNoChallenge
	}
	headers := map[string]string{"Content-Type": "application/octet-stream"}
	if size >= 0 {
		headers["Content-Length"] = strconv.FormatInt(size, 10)
	}
	req, err := http.NewRequestWithContext(ctx, "PUT", s.URL(path), body)
	if err != nil {
		return nil, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	req.Header.Set("Authorization", s.authorize("PUT", path))
	return s.http.Do(req)
}

// ErrNoChallenge reports that a Digest handshake has not completed yet.
var ErrNoChallenge = errors.New("webdav: no digest challenge recorded; send a replayable request first")

// send issues one request. [authorization] is the pre-computed header value, or
// "" for a request made before the handshake (the first attempt, and OPTIONS,
// which the server answers without credentials).
func (s *Server) send(ctx context.Context, method, path string, body io.Reader, headers map[string]string, authorization string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, method, s.URL(path), body)
	if err != nil {
		return nil, err
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	if authorization != "" {
		req.Header.Set("Authorization", authorization)
	}
	return s.http.Do(req)
}

// authorize returns the header value to send, answering the challenge most
// recently recorded by Use.
func (s *Server) authorize(method, path string) string {
	return s.Client.Authorize(method, requestURI(path)).String()
}

// Realm reports the realm this client answers for.
func (s *Server) Realm() string { return s.realm }

// URL turns a server-relative path into an absolute URL.
//
// The path is expected to be percent-encoded already by the caller; encoding it
// here as well would double-escape a literal "%" in a filename.
func (s *Server) URL(path string) string {
	if strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://") {
		return path
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return s.BaseURL + path
}

// requestURI is what goes into the Authorization `uri` field and therefore into
// HA2.
//
// It must be the request-URI as it appears on the request line — encoded,
// root-relative, with no scheme or host. Sending the absolute form here is a
// classic interop failure: the server hashes `method:uri` from its own view of
// the request line, the two never match, and every request 401s with no visible
// cause.
func requestURI(path string) string {
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return path
}

// --- capabilities ----------------------------------------------------------

// Probe checks that the endpoint speaks WebDAV. OPTIONS is the only method the
// server answers without credentials, which makes it the one request that can
// be made before the handshake.
func (s *Server) Probe(ctx context.Context) error {
	resp, err := s.Do(ctx, "OPTIONS", "/", nil, nil)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		return ErrNotWebDav
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("OPTIONS returned %d", resp.StatusCode)
	}
	// The server advertises "1, 2". A class-1 answer is the minimum a client
	// needs for PROPFIND; anything less means it is not the server we think.
	if !strings.Contains(resp.Header.Get("DAV"), "1") {
		return fmt.Errorf("DAV header = %q, expected a class-1 server",
			resp.Header.Get("DAV"))
	}
	return nil
}

// --- reads -----------------------------------------------------------------

// Node is one entry in a PROPFIND response.
type Node struct {
	Href          string
	Name          string
	IsDir         bool
	Length        int64
	LastModified  time.Time
	ContentType   string
	ETag          string
	SupportedLock bool
}

// Propfind lists [path].
//
// Depth is sent explicitly. The server defaults a missing Depth to "1" and
// treats "infinity" identically, but a server that defaulted to "0" would
// return one entry and the caller would conclude the folder is empty — the
// "0 files on Windows" failure the Kotlin XML builder was written against.
func (s *Server) Propfind(ctx context.Context, path, depth string) ([]Node, error) {
	if depth == "" {
		depth = "1"
	}
	resp, err := s.DoBytes(ctx, "PROPFIND", path, nil, map[string]string{"Depth": depth})
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMultiStatus {
		// ParseError closes too; the deferred close is then a no-op. Keeping it
		// means the success path below has one owner, and the error path is not
		// the only one that has to remember to close.
		return nil, ParseError(resp)
	}
	return parseMultistatus(resp.Body)
}

// Get downloads [path]. The caller owns the returned reader and must close it.
//
// The server sends an ETag of the form `"<lastModified>-<length>"` and
// Last-Modified, but it does not implement Range: a `Range` header is ignored
// and the whole body comes back with 200. There is deliberately no ResumableGet
// here — a client that resumes must re-read the whole file and truncate locally,
// because the server will not help.
func (s *Server) Get(ctx context.Context, path string) (io.ReadCloser, int64, http.Header, error) {
	resp, err := s.Do(ctx, "GET", path, nil, nil)
	if err != nil {
		return nil, 0, nil, err
	}
	if resp.StatusCode != http.StatusOK {
		// ParseError reads and closes the body; do not close it here first.
		return nil, 0, nil, ParseError(resp)
	}
	return resp.Body, resp.ContentLength, resp.Header, nil
}

// Head fetches headers only, for size/date without the body.
func (s *Server) Head(ctx context.Context, path string) (*http.Response, error) {
	resp, err := s.Do(ctx, "HEAD", path, nil, nil)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		// ParseError reads and closes the body; do not close it here first.
		return resp, ParseError(resp)
	}
	return resp, nil
}

// --- writes ----------------------------------------------------------------

// Put uploads [body] to [path].
//
// ifMatch is sent as a bare entity-tag. The server ignores If-Match on PUT
// entirely (WebDavRequestHandler.handlePut never reads it), so this is recorded
// rather than relied upon: when the server grows the check, a stale client will
// begin receiving 412 here, which is the correct signal and not a regression.
func (s *Server) Put(ctx context.Context, path string, body []byte, ifMatch string) (*http.Response, error) {
	headers := map[string]string{"Content-Type": "application/octet-stream"}
	if ifMatch != "" {
		headers["If-Match"] = ifMatch
	}
	return s.DoBytes(ctx, "PUT", path, body, headers)
}

// Mkcol creates a directory.
//
// RFC 4918 §9.3 requires the request to carry no body; sending one is the usual
// cause of a mysterious 415. A nil body also means Go sets no Content-Length,
// which is what the server expects.
func (s *Server) Mkcol(ctx context.Context, path string) (*http.Response, error) {
	return s.Do(ctx, "MKCOL", path, nil, nil)
}

// Delete removes [path].
func (s *Server) Delete(ctx context.Context, path string) (*http.Response, error) {
	return s.Do(ctx, "DELETE", path, nil, nil)
}

// DestinationStyle controls the form of the Destination header.
//
// Gap 3. The Kotlin tests only ever send an absolute URL, and Windows' MRxDAV
// redirector sends whichever form it happens to hold — usually the request-URI
// it was navigating with, i.e. relative. A client that only produces absolute
// URLs therefore never exercises the relative branch, and a server that only
// accepts absolute URLs breaks on Windows. All three forms are selectable so
// the interop suite can pin the behaviour instead of inheriting a default.
type DestinationStyle int

const (
	// DestAbsolute sends `http://host:port/path`.
	DestAbsolute DestinationStyle = iota
	// DestRelative sends the bare request-URI `/path`.
	DestRelative
	// DestCustom sends exactly what the caller supplied.
	DestCustom
)

// String names the style for test output, so a failing subtest says which form
// of the header broke rather than printing a bare integer.
func (d DestinationStyle) String() string {
	switch d {
	case DestAbsolute:
		return "absolute"
	case DestRelative:
		return "relative"
	case DestCustom:
		return "custom"
	}
	return fmt.Sprintf("DestinationStyle(%d)", int(d))
}

// MoveOrCopy renames or copies [path] to [destination].
//
// destination is a server-relative path, percent-encoded exactly like the one
// used for the request URI. overwrite maps to the Overwrite header, whose value
// is the single letter "T" or "F" per RFC 4918 §10.6 — not "true"/"false". The
// server currently ignores it either way, but a server that starts enforcing it
// rejects an unrecognised value, and the failure would look like a permissions
// problem rather than a spelling one.
func (s *Server) MoveOrCopy(ctx context.Context, method, path, destination string, overwrite bool, style DestinationStyle) (*http.Response, error) {
	dest := destination
	switch style {
	case DestAbsolute:
		dest = JoinDestination(s.BaseURL, destination)
	case DestRelative:
		dest = RelativeDestination(destination)
	case DestCustom:
		// Used verbatim.
	}
	overwriteHeader := "F"
	if overwrite {
		overwriteHeader = "T"
	}
	return s.Do(ctx, method, path, nil, map[string]string{
		"Destination": dest,
		"Overwrite":   overwriteHeader,
	})
}

// Lock takes an exclusive write lock on [path] and returns the token from the
// Lock-Token response header, unwrapped from its angle brackets.
//
// The server returns 200 (not 201) and, when a lock already exists, returns the
// *existing* token — refresh semantics per RFC 4918 §9.10.1. It does not check
// that the caller owns the existing lock, so two clients can both believe they
// hold the same lock; that is recorded, not fixed here.
func (s *Server) Lock(ctx context.Context, path string) (string, *http.Response, error) {
	resp, err := s.DoBytes(ctx, "LOCK", path, BuildLockRequest(), map[string]string{
		"Content-Type": "application/xml; charset=utf-8",
		"Timeout":      "Second-3600",
	})
	if err != nil {
		return "", nil, err
	}
	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		// No defer here: ParseError closes the body, and on the success path the
		// caller owns the response (the lock token is read from its headers and
		// the body is the caller's to consume).
		return "", resp, ParseError(resp)
	}
	token := strings.Trim(resp.Header.Get("Lock-Token"), "<> ")
	return token, resp, nil
}

// Unlock releases [token]. The server accepts the token with or without angle
// brackets and answers 409 when no such lock exists.
func (s *Server) Unlock(ctx context.Context, path, token string) (*http.Response, error) {
	return s.Do(ctx, "UNLOCK", path, nil, map[string]string{"Lock-Token": "<" + token + ">"})
}

// --- protocol bodies -------------------------------------------------------

// BuildLockRequest is the LOCK body. Scope and depth are hard-coded exclusive
// and infinity, which is what this server grants regardless of what was asked
// for; requesting something else would only produce a mismatch.
func BuildLockRequest() []byte {
	return []byte(`<?xml version="1.0" encoding="utf-8"?>` +
		`<D:lockinfo xmlns:D="DAV:">` +
		`<D:lockscope><D:exclusive/></D:lockscope>` +
		`<D:locktype><D:write/></D:locktype>` +
		`<D:owner>otg-drive-bridge</D:owner>` +
		`</D:lockinfo>`)
}

// BuildProppatch builds a propertyupdate body.
//
// The server does not apply it: handleProppatch reads the path, ignores the
// body, and answers 207 with the resource's current properties. The body is
// still needed to exercise the method at all, and the shape is what a server
// that did apply it would expect.
func BuildProppatch(props map[string]string) []byte {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="utf-8"?>`)
	b.WriteString(`<D:propertyupdate xmlns:D="DAV:"><D:set><D:prop>`)
	for name, value := range props {
		b.WriteString("<D:" + name + ">" + escapeXML(value) + "</D:" + name + ">")
	}
	b.WriteString(`</D:prop></D:set></D:propertyupdate>`)
	return []byte(b.String())
}

// Proppatch sends [BuildProppatch] and parses the 207 the server answers with,
// which is the resource's current state rather than an echo of the request.
func (s *Server) Proppatch(ctx context.Context, path string, props map[string]string) ([]Node, *http.Response, error) {
	resp, err := s.DoBytes(ctx, "PROPPATCH", path, BuildProppatch(props), map[string]string{
		"Content-Type": "application/xml; charset=utf-8",
	})
	if err != nil {
		return nil, nil, err
	}
	if resp.StatusCode != http.StatusMultiStatus {
		// ParseError reads and closes the body. On the success path the caller
		// owns the response and closes it itself.
		return nil, resp, ParseError(resp)
	}
	nodes, err := parseMultistatus(resp.Body)
	if err != nil {
		return nil, resp, err
	}
	return nodes, resp, nil
}

// JoinDestination builds the Destination header value for a server-relative
// path, in absolute form.
func JoinDestination(baseURL, path string) string {
	if strings.HasPrefix(path, "http://") || strings.HasPrefix(path, "https://") {
		return path
	}
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return baseURL + path
}

// RelativeDestination is the other half of the same test: the bare
// request-URI, with no scheme or host.
func RelativeDestination(path string) string {
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}
	return path
}

func escapeXML(s string) string {
	r := strings.NewReplacer("&", "&amp;", "<", "&lt;", ">", "&gt;", `"`, "&quot;", "'", "&apos;")
	return r.Replace(s)
}

// --- errors ----------------------------------------------------------------

// ParseError reads a response body into an error, and closes the body.
//
// It closes because every caller that has reached this point is done with the
// response, and a caller that closes first would leave nothing to read — the
// body is the message. Handing back a closed response and an error built from
// an empty body is how "409 Conflict" ends up where "<D:no-conflicting-lock/>"
// belongs.
//
// This server answers every failure with a short plain-text reason phrase
// (WebDavRequestHandler.respondText), not with a DAV `<error>` XML document.
// That is the shape it has, and a client must be able to read it. An XML error
// body is still parsed when one is present, so the client keeps working if the
// server ever moves to RFC 4918 §11-style errors.
func ParseError(resp *http.Response) error {
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<10))
	text := strings.TrimSpace(string(body))
	if strings.HasPrefix(text, "<?xml") {
		if msg := parseXMLError(text); msg != "" {
			text = msg
		}
	}
	if text == "" {
		text = resp.Status
	}
	return &StatusError{Code: resp.StatusCode, Message: text}
}

// StatusError is a WebDAV failure carrying its status code.
type StatusError struct {
	Code    int
	Message string
}

func (e *StatusError) Error() string {
	return fmt.Sprintf("webdav: %d %s", e.Code, e.Message)
}

// Is reports whether [target] is a status this error matches, so callers write
// `errors.Is(err, ErrNotFound)` instead of comparing codes.
func (e *StatusError) Is(target error) bool {
	t, ok := target.(*StatusError)
	return ok && t.Code == e.Code
}

// Sentinel statuses used across the client and its tests. Message is filled in
// from the response by ParseError; these are only matched on Code.
var (
	ErrUnauthorized = &StatusError{Code: http.StatusUnauthorized}
	ErrForbidden    = &StatusError{Code: http.StatusForbidden}
	ErrNotFound     = &StatusError{Code: http.StatusNotFound}
	ErrConflict     = &StatusError{Code: http.StatusConflict}
	ErrPrecondition = &StatusError{Code: http.StatusPreconditionFailed}
	ErrLocked       = &StatusError{Code: http.StatusLocked}
)

// Code returns the status code carried by [err], or 0.
func Code(err error) int {
	var se *StatusError
	if errors.As(err, &se) {
		return se.Code
	}
	return 0
}

// --- XML parsing -----------------------------------------------------------

// parseMultistatus reads a 207 body.
//
// The namespace prefix is not assumed. The server emits `D:` bound to `DAV:`,
// but a conforming server may bind any prefix or use a default namespace, so
// elements are matched on their local name — and the interop suite pins this
// because MRxDAV is the one client that does care about the prefix.
func parseMultistatus(r io.Reader) ([]Node, error) {
	data, err := io.ReadAll(io.LimitReader(r, 64<<20))
	if err != nil {
		return nil, err
	}
	root, err := parseXML(string(data))
	if err != nil {
		return nil, fmt.Errorf("multistatus: %w", err)
	}
	if root.name != "multistatus" {
		return nil, fmt.Errorf("multistatus: root element is %q", root.name)
	}
	var nodes []Node
	for _, response := range root.findAllDeep("response") {
		node := Node{}
		node.Href = unescapeXML(response.findText("href"))
		node.Name = response.findPropText("displayname")
		if node.Name == "" {
			node.Name = nameFromHref(node.Href)
		}
		node.Length = response.findPropInt("getcontentlength")
		node.IsDir = response.findPropText("iscollection") == "1" ||
			response.findProp("resourcetype", "collection") != nil
		node.ContentType = response.findPropText("getcontenttype")
		node.ETag = response.findPropText("getetag")
		node.SupportedLock = response.findProp("supportedlock", "lockentry") != nil
		if lm := response.findPropText("getlastmodified"); lm != "" {
			if t, err := http.ParseTime(lm); err == nil {
				node.LastModified = t
			}
		}
		nodes = append(nodes, node)
	}
	return nodes, nil
}

// nameFromHref is the fallback when a response carries no displayname: the last
// path segment, percent-decoded.
func nameFromHref(href string) string {
	trimmed := strings.TrimRight(href, "/")
	if slash := strings.LastIndexByte(trimmed, '/'); slash >= 0 {
		trimmed = trimmed[slash+1:]
	}
	if decoded, err := percentDecode(trimmed); err == nil {
		return decoded
	}
	return trimmed
}

// parseXMLError pulls the condition out of a DAV `<error>` body, for the day
// the server switches to XML errors.
func parseXMLError(body string) string {
	root, err := parseXML(body)
	if err != nil {
		return ""
	}
	if root.name != "error" {
		return ""
	}
	if len(root.children) > 0 {
		return root.children[0].name
	}
	return ""
}

func unescapeXML(s string) string {
	r := strings.NewReplacer("&lt;", "<", "&gt;", ">", "&quot;", `"`, "&apos;", "'", "&amp;", "&")
	return r.Replace(s)
}

// --- minimal XML reader ----------------------------------------------------

// xmlNode is a trimmed-down element: name, children, text.
//
// A small reader instead of encoding/xml keeps the binary free of the
// reflection-heavy decoder and keeps the parsing rules — namespace-agnostic,
// prefix-insensitive — visible and testable. The cost is that it does not
// validate; every input it is given here comes from our own server or from a
// test fixture.
type xmlNode struct {
	name     string
	children []*xmlNode
	text     string
}

// parseXML returns the document's root element, skipping the prolog and any
// comments or DOCTYPE that precede it.
func parseXML(doc string) (*xmlNode, error) {
	i := strings.IndexByte(doc, '<')
	if i < 0 {
		return nil, errors.New("no xml element found")
	}
	root := &xmlNode{}
	stack := []*xmlNode{root}
	for i < len(doc) {
		rest := doc[i:]
		switch {
		case strings.HasPrefix(rest, "<?"), strings.HasPrefix(rest, "<!"):
			end := strings.IndexByte(rest, '>')
			if end < 0 {
				i = len(doc)
				continue
			}
			i += end + 1
		case strings.HasPrefix(rest, "</"):
			if len(stack) > 1 {
				stack = stack[:len(stack)-1]
			}
			end := strings.IndexByte(rest, '>')
			if end < 0 {
				i = len(doc)
				continue
			}
			i += end + 1
		default:
			end := strings.IndexByte(rest, '>')
			if end < 0 {
				i = len(doc)
				continue
			}
			raw := rest[1:end]
			i += end + 1
			selfClosing := strings.HasSuffix(raw, "/")
			raw = strings.TrimSuffix(raw, "/")
			name := raw
			if sp := strings.IndexAny(raw, " \t\r\n"); sp >= 0 {
				name = raw[:sp]
			}
			name = localName(name)
			if name == "" {
				continue
			}
			node := &xmlNode{name: name}
			parent := stack[len(stack)-1]
			parent.children = append(parent.children, node)
			if selfClosing {
				continue
			}
			// Text up to the next tag belongs to this element.
			next := strings.IndexByte(doc[i:], '<')
			if next < 0 {
				i = len(doc)
				continue
			}
			if next > 0 {
				node.text += doc[i : i+next]
				i += next
			}
			stack = append(stack, node)
		}
	}
	if len(root.children) == 0 {
		return nil, errors.New("no xml element found")
	}
	return root.children[0], nil
}

// localName strips any namespace prefix, so `D:multistatus` and `multistatus`
// compare equal.
func localName(name string) string {
	if colon := strings.IndexByte(name, ':'); colon >= 0 {
		return name[colon+1:]
	}
	return name
}

// find descends through a path of direct-child local names, returning nil if
// any step is missing.
func (n *xmlNode) find(path ...string) *xmlNode {
	cur := n
	for _, want := range path {
		var next *xmlNode
		for _, child := range cur.children {
			if child.name == want {
				next = child
				break
			}
		}
		if next == nil {
			return nil
		}
		cur = next
	}
	return cur
}

// findAllDeep collects every descendant with the given local name, at any
// depth. Used for `response`, whose position under multistatus is not
// guaranteed to be a direct child once a server introduces intermediate
// elements.
func (n *xmlNode) findAllDeep(name string) []*xmlNode {
	var out []*xmlNode
	var walk func(*xmlNode)
	walk = func(node *xmlNode) {
		for _, child := range node.children {
			if child.name == name {
				out = append(out, child)
			}
			walk(child)
		}
	}
	walk(n)
	return out
}

// findProp looks inside `<propstat><prop>`, which is where every live property
// actually lives. Looking for one as a direct child of <response> would
// silently return empty for every field.
func (n *xmlNode) findProp(path ...string) *xmlNode {
	for _, propstat := range n.findAllDeep("propstat") {
		if found := propstat.find("prop"); found != nil {
			if node := found.find(path...); node != nil {
				return node
			}
		}
	}
	return nil
}

func (n *xmlNode) findPropText(name string) string {
	node := n.findProp(name)
	if node == nil {
		return ""
	}
	return unescapeXML(strings.TrimSpace(node.text))
}

func (n *xmlNode) findPropInt(name string) int64 {
	text := n.findPropText(name)
	if text == "" {
		return 0
	}
	v, err := strconv.ParseInt(text, 10, 64)
	if err != nil {
		return 0
	}
	return v
}

func (n *xmlNode) findText(path ...string) string {
	node := n.find(path...)
	if node == nil {
		return ""
	}
	return unescapeXML(strings.TrimSpace(node.text))
}
