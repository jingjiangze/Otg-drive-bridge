// Package digest implements the client half of HTTP Digest Access
// Authentication (RFC 2617 §3.2.2, MD5 qop=auth) — the algorithm the Android
// side of this project speaks, and therefore the one the Windows side must
// speak.
//
// The reason this package exists at all instead of reaching for
// studio-b12/gowebdav: that library's Digest support covers MD5 and MD5-sess
// with qop=auth and auth-int, but it keeps its own nonce counter and never
// re-challenges. This project's server is deliberately RFC-2617-minimal, and
// the exact points where a real client has to make a judgement call — a stale
// nonce, an opaque that does not match, a nonce-count that has to keep
// climbing — are the points that are easiest to get subtly wrong. Writing the
// algorithm out keeps them visible and testable.
//
// The golden vectors in digest_test.go were produced with `md5sum` before this
// code was written, not by running it: a self-consistent test proves nothing
// about interoperability.
package digest

import (
	"crypto/md5"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"sync"
)

// Challenge is the parsed WWW-Authenticate: Digest header a server sends with
// a 401.
type Challenge struct {
	Realm  string
	Nonce  string
	Opaque string
	Qop    string
	Stale  bool
}

// Authorization is what the client puts in an Authorization: Digest header.
type Authorization struct {
	Username string
	Realm    string
	Nonce    string
	URI      string
	Response string
	Qop      string
	Nc       string
	Cnonce   string
	Opaque   string
}

// ParseChallenge reads a `WWW-Authenticate: Digest realm="…", qop="auth", …`
// value. It returns ok=false for anything that is not a Digest challenge, which
// is how a caller tells "no challenge" from "a challenge I cannot use".
//
// Values may be quoted or bare, per RFC 2617 §3.2.1; `stale` is a bare token.
func ParseChallenge(value string) (Challenge, bool) {
	fields, ok := parseFields(value)
	if !ok {
		return Challenge{}, false
	}
	realm, ok := fields["realm"]
	if !ok {
		return Challenge{}, false
	}
	nonce, ok := fields["nonce"]
	if !ok {
		return Challenge{}, false
	}
	c := Challenge{
		Realm:  realm,
		Nonce:  nonce,
		Opaque: fields["opaque"],
		Qop:    fields["qop"],
		Stale:  strings.EqualFold(fields["stale"], "true"),
	}
	return c, true
}

// ParseAuthorization is the mirror image, used by the tests that drive this
// package's output through the same parser the server-side tests use.
func ParseAuthorization(value string) (Authorization, bool) {
	fields, ok := parseFields(value)
	if !ok {
		return Authorization{}, false
	}
	a := Authorization{
		Username: fields["username"],
		Realm:    fields["realm"],
		Nonce:    fields["nonce"],
		URI:      fields["uri"],
		Response: fields["response"],
		Qop:      fields["qop"],
		Nc:       fields["nc"],
		Cnonce:   fields["cnonce"],
		Opaque:   fields["opaque"],
	}
	if a.Username == "" || a.Realm == "" || a.Nonce == "" || a.URI == "" || a.Response == "" {
		return Authorization{}, false
	}
	return a, true
}

// String renders the header value. The field order is not significant to the
// server (it parses into a map), but it is kept stable so protocol captures and
// test failures stay comparable.
func (a Authorization) String() string {
	var b strings.Builder
	b.WriteString("Digest ")
	b.WriteString(`username="` + a.Username + `", `)
	b.WriteString(`realm="` + a.Realm + `", `)
	b.WriteString(`nonce="` + a.Nonce + `", `)
	b.WriteString(`uri="` + a.URI + `", `)
	b.WriteString(`response="` + a.Response + `"`)
	if a.Qop != "" {
		b.WriteString(", qop=" + a.Qop)
		b.WriteString(", nc=" + a.Nc)
		b.WriteString(`, cnonce="` + a.Cnonce + `"`)
	}
	if a.Opaque != "" {
		b.WriteString(`, opaque="` + a.Opaque + `"`)
	}
	return b.String()
}

// Response computes the RFC 2617 §3.2.2.1 `response` hash:
//
//	HA1 = MD5(username:realm:password)
//	HA2 = MD5(method:uri)
//	response = MD5(HA1:nonce:nc:cnonce:qop:HA2)   when qop is present
//	response = MD5(HA1:nonce:HA2)                  when qop is absent
//
// `uri` is the request-URI exactly as it will be sent on the request line —
// not the absolute form, not the percent-decoded form. HA2 is computed over
// whatever this value is, so the two must agree or the server's own HA2 will
// differ and every request will 401 with no visible cause.
func Response(username, password, realm, method, uri, nonce, nc, cnonce, qop string) string {
	ha1 := hashHex(username + ":" + realm + ":" + password)
	ha2 := hashHex(strings.ToUpper(method) + ":" + uri)
	if qop == "" {
		return hashHex(ha1 + ":" + nonce + ":" + ha2)
	}
	return hashHex(ha1 + ":" + nonce + ":" + nc + ":" + cnonce + ":" + qop + ":" + ha2)
}

// HA1 is exported for the table-driven tests, which assert the intermediate
// value against md5sum rather than only the final digest.
func HA1(username, realm, password string) string {
	return hashHex(username + ":" + realm + ":" + password)
}

// HA2 is exported for the same reason.
func HA2(method, uri string) string {
	return hashHex(strings.ToUpper(method) + ":" + uri)
}

// Client is a Digest responder for one realm's worth of credentials. It owns
// the nonce state: which challenge is current, how many requests have been
// answered with it, and what client-nonce to use.
//
// It is safe for concurrent use.
type Client struct {
	Username string
	Password string
	Realm    string

	mu     sync.Mutex
	nonce  string
	opaque string
	qop    string
	nc     uint64
	cnonce string
}

// NewClient returns a client that answers challenges for [realm].
func NewClient(username, password, realm string) *Client {
	return &Client{Username: username, Password: password, Realm: realm}
}

// Use records a challenge as the current one. A challenge with stale=true
// replaces the previous state outright: RFC 2617 §3.2.1 says the client should
// retry with the new nonce and, because the server issued a fresh one, the
// nonce-count restarts. Re-using a nonce across a stale rotation would make
// the counter meaningless.
func (c *Client) Use(ch Challenge) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.nonce = ch.Nonce
	c.opaque = ch.Opaque
	c.qop = ch.Qop
	if ch.Qop == "" {
		c.qop = "auth"
	}
	c.nc = 0
	if c.cnonce == "" {
		c.cnonce = newCnonce()
	}
}

// Authorize returns the Authorization header value to send with [method] and
// [uri], answering the challenge most recently passed to Use.
func (c *Client) Authorize(method, uri string) Authorization {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cnonce == "" {
		c.cnonce = newCnonce()
	}
	c.nc++
	nc := fmt.Sprintf("%08x", c.nc)
	qop := c.qop
	if qop == "" {
		qop = "auth"
	}
	resp := Response(c.Username, c.Password, c.Realm, method, uri, c.nonce, nc, c.cnonce, qop)
	return Authorization{
		Username: c.Username,
		Realm:    c.Realm,
		Nonce:    c.nonce,
		URI:      uri,
		Response: resp,
		Qop:      qop,
		Nc:       nc,
		Cnonce:   c.cnonce,
		Opaque:   c.opaque,
	}
}

// NonceCount reports how many requests have been answered with the current
// nonce. The tests use it to prove the counter climbs and resets on a stale
// rotation.
func (c *Client) NonceCount() uint64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.nc
}

func hashHex(s string) string {
	sum := md5.Sum([]byte(s))
	return hex.EncodeToString(sum[:])
}

// newCnonce produces the per-session client nonce. RFC 2617 leaves the exact
// value to the client; the server only requires it to be present and stable
// across requests answered with one nonce, so a random 8-byte value is enough.
func newCnonce() string {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand failing means the platform is broken; a fixed value keeps
		// the client usable (the server does not judge cnonce quality) rather
		// than taking down the whole sync path.
		return "0000000000000000"
	}
	return hex.EncodeToString(b)
}

// parseFields splits `Digest key=value, key="value"` into a lower-cased map.
//
// Splitting on commas is not correct in general — a quoted value may contain
// one — but it is what RFC 2617's ABNF permits for the fields this project
// uses, and it is exactly what the Kotlin server does (DigestAuthenticator
// .digestFields). Matching its behaviour is the point: a parser that is more
// clever than the peer's will disagree with it on the same input.
func parseFields(value string) (map[string]string, bool) {
	if !strings.HasPrefix(strings.TrimSpace(value), "Digest") {
		return nil, false
	}
	fields := make(map[string]string)
	for _, part := range strings.Split(value, ",") {
		eq := strings.Index(part, "=")
		if eq <= 0 {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(part[:eq]), "Digest")))
		if key == "" {
			continue
		}
		raw := strings.TrimSpace(part[eq+1:])
		if len(raw) >= 2 && strings.HasPrefix(raw, `"`) && strings.HasSuffix(raw, `"`) {
			raw = raw[1 : len(raw)-1]
			raw = strings.ReplaceAll(raw, `\"`, `"`)
			raw = strings.ReplaceAll(raw, `\\`, `\`)
		}
		fields[key] = raw
	}
	return fields, true
}
