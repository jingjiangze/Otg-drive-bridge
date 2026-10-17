package webdavclient

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
)

// The sync-collection report of RFC 6578, and the one shape of it this server
// implements.
//
// The point of the report is that a client stops diffing: instead of listing the
// whole tree and comparing it to what it has, it asks "what changed since the
// token you gave me". That is only true if the client keeps the token and the
// server is honest about it, so the two rules that matter most are encoded
// below rather than left to the caller:
//
//   - the token MUST be sent back unchanged (RFC 6578 §3.2). It is opaque, and
//     this server's happens to be a URI with a sequence number in it, which
//     makes parsing it tempting and wrong — a client that reads the digits and
//     sends back "one more" would be inventing a token the server never issued,
//     which the server correctly answers with the DAV:valid-sync-token
//     precondition (412).
//   - a 412 is not an error, it is the signal to fall back to an initial sync
//     (empty token) — RFC 6578 §3.4. It fires after every server restart here,
//     because the change log is in memory by design (see Kotlin ChangeLog).

// FormatRange builds a `Range` header value for the inclusive byte range
// [from, to]. Exported so a caller that wants to log or record what it asked for
// does not re-derive the spelling, and so the malformed cases (negative,
// reversed) are refused in one place instead of producing a header the server
// must then interpret.
func FormatRange(from, to int64) (string, error) {
	if from < 0 || to < 0 {
		return "", fmt.Errorf("webdav: negative range %d-%d", from, to)
	}
	if to < from {
		return "", fmt.Errorf("webdav: reversed range %d-%d", from, to)
	}
	return "bytes=" + strconv.FormatInt(from, 10) + "-" + strconv.FormatInt(to, 10), nil
}

// SyncLevel is how much of the tree one report covers.
type SyncLevel int

const (
	// SyncLevel1 reports the collection's immediate members — §6.3's `1`.
	SyncLevel1 SyncLevel = iota
	// SyncLevelInfinite reports the whole subtree — §6.3's `infinite`.
	SyncLevelInfinite
)

// String is the value that goes on the wire, so a test that records the request
// body can assert on the level it asked for without re-deriving it.
func (l SyncLevel) String() string {
	if l == SyncLevelInfinite {
		return "infinite"
	}
	return "1"
}

// SyncChange is one member of a sync-collection report.
//
// Removed is the field that carries the whole point of the report: a removed
// member arrives with a bare 404 status and NO propstat (§3.2), which is how the
// client distinguishes "gone" from "changed" without a second round trip. So the
// type is one struct with a flag, not two types — a caller writing a switch on
// two types would be encoding that asymmetry twice.
type SyncChange struct {
	// Href is the server-relative, percent-encoded path the server reported.
	// Use [SyncChange.Name] for a decoded leaf name.
	Href string
	// Name is the leaf segment of Href, percent-decoded.
	Name string
	// Removed is true when the member no longer exists. When true, Node is the
	// zero value.
	Removed bool
	// Node carries the properties the request asked for, for a changed member.
	Node Node
}

// SyncResult is one 207 report.
type SyncResult struct {
	// Changed is every member added or modified since the token.
	Changed []SyncChange
	// Removed is every member deleted since the token.
	Removed []SyncChange
	// Token is the token to send next time. It MUST be echoed verbatim.
	Token string
	// Header is the response header, for ETag and friends.
	Header http.Header
}

// BuildSyncRequest is the sync-collection request body.
//
// The property list is explicit rather than `allprop`: §3.2's `prop` is a list of
// names, and the server returns exactly what was asked for (plus a synthetic
// minimum when it can answer nothing else). Asking for getetag and
// getlastmodified is what makes the "changed" answer usable — a client that asks
// for nothing in particular gets nothing in particular.
//
// An empty [token] is the initial sync (§3.4: all member URLs), not "since the
// beginning of time" on the server's side. It is sent as an empty
// `<D:sync-token/>` element rather than omitted, because §6.1's element list has
// no optional member except `limit` and the server answers a missing one with a
// 400.
func BuildSyncRequest(token string, level SyncLevel) []byte {
	return []byte(`<?xml version="1.0" encoding="utf-8"?>` +
		`<D:sync-collection xmlns:D="DAV:">` +
		`<D:sync-token>` + escapeXML(token) + `</D:sync-token>` +
		`<D:sync-level>` + level.String() + `</D:sync-level>` +
		`<D:prop><D:getetag/><D:getlastmodified/><D:getcontentlength/><D:getcontenttype/></D:prop>` +
		`</D:sync-collection>`)
}

// SyncCollection asks the server what changed in [path] since [token].
//
// [token] is the token from a previous SyncResult, or "" for an initial sync.
// Depth is sent explicitly as 0: §3.2 pins it, `sync-level` is what scopes the
// report, and a server that received Depth: 1 would be entitled to answer 400.
//
// A 412 (DAV:valid-sync-token) is returned to the caller as a non-nil
// *StatusError with Code 412 and an empty result, because it is the documented
// signal to retry with an empty token rather than a failure to surface to a user.
func (s *Server) SyncCollection(ctx context.Context, path, token string, level SyncLevel) (*SyncResult, error) {
	resp, err := s.DoBytes(ctx, "REPORT", path, BuildSyncRequest(token, level), map[string]string{
		"Depth":        "0",
		"Content-Type": "application/xml; charset=utf-8",
	})
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMultiStatus {
		return nil, ParseError(resp)
	}
	result, err := parseSyncResponse(resp.Body)
	if err != nil {
		return nil, err
	}
	result.Header = resp.Header
	return result, nil
}

// parseSyncResponse reads one 207 sync-collection body.
//
// The asymmetry that makes the report useful is preserved exactly: a `<response>`
// with a `<status>` and no propstat is a removal, everything else is a change.
// A response carrying neither is reported as a change with an empty Node rather
// than dropped, so a server bug shows up as a caller seeing a member with no
// properties instead of silently never hearing about it again.
func parseSyncResponse(r io.Reader) (*SyncResult, error) {
	data, err := io.ReadAll(io.LimitReader(r, 64<<20))
	if err != nil {
		return nil, err
	}
	root, err := parseXML(string(data))
	if err != nil {
		return nil, fmt.Errorf("sync-collection: %w", err)
	}
	if root.name != "multistatus" {
		return nil, fmt.Errorf("sync-collection: root element is %q", root.name)
	}
	result := &SyncResult{}
	for _, response := range root.findAllDeep("response") {
		change := SyncChange{
			Href: unescapeXML(response.findText("href")),
		}
		change.Name = nameFromHref(change.Href)
		status := response.findText("status")
		if status != "" && strings.Contains(status, "404") {
			// A removed member: no propstat by construction, and its href is the
			// only thing worth keeping.
			change.Removed = true
			result.Removed = append(result.Removed, change)
			continue
		}
		fillNodeFromResponse(response, &change.Node)
		change.Node.Href = change.Href
		change.Node.Name = change.Name
		result.Changed = append(result.Changed, change)
	}
	result.Token = unescapeXML(root.findText("sync-token"))
	return result, nil
}

// fillNodeFromResponse reads the live properties of one changed member into
// [node].
//
// It is the same reading rule parseMultistatus uses — properties live inside
// `<propstat><prop>`, never as direct children of `<response>` — factored out so
// the two readers cannot drift apart. The one difference is that a sync response
// carries exactly one propstat, the 200, so there is no per-property status to
// disambiguate: an empty result here means the member changed in a way the
// server could not describe, which the caller is expected to notice.
func fillNodeFromResponse(response *xmlNode, node *Node) {
	node.Length = response.findPropInt("getcontentlength")
	node.ContentType = response.findPropText("getcontenttype")
	node.ETag = response.findPropText("getetag")
	node.IsDir = response.findProp("resourcetype", "collection") != nil
	if lm := response.findPropText("getlastmodified"); lm != "" {
		if t, err := http.ParseTime(lm); err == nil {
			node.LastModified = t
		}
	}
}
