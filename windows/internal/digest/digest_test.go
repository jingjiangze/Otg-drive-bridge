package digest

import (
	"strings"
	"testing"
)

// The golden vectors below were produced with `md5sum` before digest.go was
// written, on the command line, from the same inputs the algorithm uses:
//
//	printf 'otg:OTG Drive Bridge:SuperSecretPassw0rd' | md5sum   → 3c6c0711fbfaf9cb518ce59e702f251f
//	printf 'PROPFIND:/'                              | md5sum   → 47e3ec01eb822fd289b55d59ae9c9de0
//	printf 'GET:/hello.txt'                          | md5sum   → 72c2ad562f0075132e6f64f012c8e3b3
//	printf '%s:nonce:00000001:abcdef012345:auth:%s' $HA1 $HA2PROPFIND | md5sum → b115d1b032c48ed0379e90d7585bcc0a
//	printf '%s:nonce:%s' $HA1 $HA2GET                | md5sum   → 13c3dbde447ba5f8f23eb0f69614e98f
//
// This is the independent value-level check the audit found missing on the
// Kotlin side: the Kotlin tests compute a response with the code under test
// and then verify it with the same code, so they cannot catch a shared
// misreading of RFC 2617. A vector from md5sum can.

const (
	testUser       = "otg"
	testPass       = "SuperSecretPassw0rd"
	testRealm      = "OTG Drive Bridge"
	testHA1        = "3c6c0711fbfaf9cb518ce59e702f251f"
	testHA2GET     = "72c2ad562f0075132e6f64f012c8e3b3" // GET /hello.txt
	testHA2PROFIND = "47e3ec01eb822fd289b55d59ae9c9de0" // PROPFIND /
	testResp       = "b115d1b032c48ed0379e90d7585bcc0a" // qop=auth, PROPFIND /
	testRespNoQop  = "13c3dbde447ba5f8f23eb0f69614e98f" // no qop, GET /hello.txt
)

func TestHA1MatchesMd5sum(t *testing.T) {
	if got := HA1(testUser, testRealm, testPass); got != testHA1 {
		t.Fatalf("HA1 = %q, want %q (md5sum of %q)", got, testHA1,
			testUser+":"+testRealm+":"+testPass)
	}
}

func TestHA2MatchesMd5sum(t *testing.T) {
	if got := HA2("PROPFIND", "/"); got != testHA2PROFIND {
		t.Fatalf("HA2(PROPFIND, /) = %q, want %q", got, testHA2PROFIND)
	}
	if got := HA2("propfind", "/"); got != testHA2PROFIND {
		t.Fatalf("HA2(lower-case propfind, /) = %q, want %q; the method is upper-cased", got, testHA2PROFIND)
	}
	if got := HA2("get", "/hello.txt"); got != testHA2GET {
		t.Fatalf("HA2(get, /hello.txt) = %q, want %q", got, testHA2GET)
	}
	if got := HA2("GET", "/hello.txt"); got != testHA2GET {
		t.Fatalf("HA2(GET, /hello.txt) = %q, want %q", got, testHA2GET)
	}
}

func TestResponseMatchesMd5sum(t *testing.T) {
	got := Response(testUser, testPass, testRealm, "PROPFIND", "/",
		"nonce", "00000001", "abcdef012345", "auth")
	if got != testResp {
		t.Fatalf("Response = %q, want %q", got, testResp)
	}
}

// TestResponseWithoutQopIsTheTwoFieldForm pins the qop-less branch, which the
// server also implements (DigestAuthenticator.computeResponse) but never
// offers: a challenge always carries qop="auth". If a future server change
// drops qop, the client must not keep sending nc/cnonce.
func TestResponseWithoutQopIsTheTwoFieldForm(t *testing.T) {
	// md5sum of "$HA1:nonce:$HA2GET", i.e. no nc, no cnonce, no qop.
	got := Response(testUser, testPass, testRealm, "GET", "/hello.txt", "nonce", "", "", "")
	if got != testRespNoQop {
		t.Fatalf("qop-less response = %q, want %q", got, testRespNoQop)
	}
	if got == Response(testUser, testPass, testRealm, "GET", "/hello.txt", "nonce", "00000001", "cnonce", "auth") {
		t.Fatal("qop-less and qop=auth forms produced the same digest")
	}
}

// --- challenge parsing -----------------------------------------------------

func TestParseChallengeReadsEveryField(t *testing.T) {
	const header = `Digest realm="OTG Drive Bridge", qop="auth", nonce="abc123", opaque="op4", stale=true`
	ch, ok := ParseChallenge(header)
	if !ok {
		t.Fatal("ParseChallenge rejected a well-formed challenge")
	}
	if ch.Realm != "OTG Drive Bridge" || ch.Qop != "auth" ||
		ch.Nonce != "abc123" || ch.Opaque != "op4" || !ch.Stale {
		t.Fatalf("parsed %+v", ch)
	}
}

func TestParseChallengeDefaultsStaleToFalse(t *testing.T) {
	ch, ok := ParseChallenge(`Digest realm="r", qop="auth", nonce="n", opaque="o"`)
	if !ok {
		t.Fatal("rejected a challenge without stale")
	}
	if ch.Stale {
		t.Fatal("stale defaulted to true")
	}
}

func TestParseChallengeRejectsNonDigestValues(t *testing.T) {
	for _, value := range []string{
		"",
		"Basic realm=\"x\"",
		"Bearer token",
		`Digest qop="auth", nonce="n"`,     // no realm
		`Digest realm="r", qop="auth"`,    // no nonce
	} {
		if _, ok := ParseChallenge(value); ok {
			t.Errorf("ParseChallenge accepted %q", value)
		}
	}
}

func TestParseChallengeIsCaseInsensitiveOnStale(t *testing.T) {
	for _, token := range []string{"true", "True", "TRUE"} {
		ch, ok := ParseChallenge(`Digest realm="r", nonce="n", stale=` + token)
		if !ok || !ch.Stale {
			t.Errorf("stale=%s not recognised", token)
		}
	}
}

// --- client state machine --------------------------------------------------

func challenge(realm, nonce, opaque string, stale bool) Challenge {
	return Challenge{Realm: realm, Nonce: nonce, Opaque: opaque, Qop: "auth", Stale: stale}
}

func TestClientNonceCountClimbs(t *testing.T) {
	c := NewClient(testUser, testPass, testRealm)
	c.Use(challenge(testRealm, "n1", "o1", false))

	a1 := c.Authorize("PROPFIND", "/")
	if a1.Nc != "00000001" {
		t.Fatalf("first nc = %q", a1.Nc)
	}
	a2 := c.Authorize("PROPFIND", "/")
	if a2.Nc != "00000002" {
		t.Fatalf("second nc = %q, want 00000002", a2.Nc)
	}
	if c.NonceCount() != 2 {
		t.Fatalf("NonceCount = %d", c.NonceCount())
	}
	// The responses must differ, or replay protection is theatre.
	if a1.Response == a2.Response {
		t.Fatal("two requests with the same nonce produced identical responses")
	}
}

// TestClientStaleRotationResetsTheCounter is the "stale 重挑战" case the audit
// flagged: the server never sends stale=true today (WebDavRequestHandler
// .respondChallenge always calls challenge() with the default false), but
// RFC 2617 §3.2.1 defines it and the Kotlin authenticator carries a nonce
// lifetime of 300s, so the day it starts sending it the client must handle it
// rather than reusing a counter that the new nonce has no record of.
func TestClientStaleRotationResetsTheCounter(t *testing.T) {
	c := NewClient(testUser, testPass, testRealm)
	c.Use(challenge(testRealm, "old", "o-old", false))
	c.Authorize("PROPFIND", "/")
	c.Authorize("PROPFIND", "/")

	c.Use(challenge(testRealm, "fresh", "o-fresh", true))
	a := c.Authorize("PROPFIND", "/")
	if a.Nc != "00000001" {
		t.Fatalf("after a stale rotation nc = %q, want 00000001", a.Nc)
	}
	if a.Nonce != "fresh" || a.Opaque != "o-fresh" {
		t.Fatalf("stale rotation did not adopt the new nonce/opaque: %+v", a)
	}
}

func TestClientEchoesOpaque(t *testing.T) {
	c := NewClient(testUser, testPass, testRealm)
	c.Use(challenge(testRealm, "n", "opaque-value", false))
	a := c.Authorize("GET", "/x")
	if a.Opaque != "opaque-value" {
		t.Fatalf("opaque = %q", a.Opaque)
	}
}

// TestClientCarriesNoOpaqueWhenServerSentNone covers the opposite shape: the
// field must be absent, not empty, because an empty opaque="…" is a different
// value to a parser than a missing field.
func TestClientCarriesNoOpaqueWhenServerSentNone(t *testing.T) {
	c := NewClient(testUser, testPass, testRealm)
	c.Use(Challenge{Realm: testRealm, Nonce: "n", Qop: "auth"})
	a := c.Authorize("GET", "/x")
	if a.Opaque != "" {
		t.Fatalf("opaque = %q, want empty", a.Opaque)
	}
	if strings.Contains(a.String(), "opaque=") {
		t.Fatalf("header carries an opaque field: %s", a.String())
	}
}

func TestClientUsesRealmFromItsOwnCredentials(t *testing.T) {
	// The realm in the Authorization header must be the one this client was
	// built for, not whatever the challenge said: the server compares the two
	// with equals(realm, ignoreCase=true) and rejects a mismatch.
	c := NewClient(testUser, testPass, testRealm)
	c.Use(challenge("some-other-realm", "n", "o", false))
	a := c.Authorize("GET", "/")
	if a.Realm != testRealm {
		t.Fatalf("realm = %q, want %q", a.Realm, testRealm)
	}
}

func TestAuthorizationRoundTripsThroughTheParser(t *testing.T) {
	c := NewClient(testUser, testPass, testRealm)
	c.Use(challenge(testRealm, "n", "o", false))
	header := c.Authorize("PROPFIND", "/dav/").String()
	parsed, ok := ParseAuthorization(header)
	if !ok {
		t.Fatalf("could not parse back our own header: %s", header)
	}
	if parsed.Username != testUser || parsed.Nonce != "n" || parsed.Opaque != "o" ||
		parsed.URI != "/dav/" || parsed.Nc != "00000001" || parsed.Cnonce == "" {
		t.Fatalf("round trip lost fields: %+v (from %s)", parsed, header)
	}
	// The response must survive the round trip too, or the parser is dropping
	// the one field that carries the proof.
	want := Response(testUser, testPass, testRealm, "PROPFIND", "/dav/",
		"n", "00000001", parsed.Cnonce, "auth")
	if parsed.Response != want {
		t.Fatalf("response %q, want %q", parsed.Response, want)
	}
}

func TestCnonceIsStableWithinASession(t *testing.T) {
	c := NewClient(testUser, testPass, testRealm)
	c.Use(challenge(testRealm, "n", "o", false))
	first := c.Authorize("GET", "/a").Cnonce
	for i := 0; i < 5; i++ {
		if got := c.Authorize("GET", "/a").Cnonce; got != first {
			t.Fatalf("cnonce changed mid-session: %q then %q", first, got)
		}
	}
}
