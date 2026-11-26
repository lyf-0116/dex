// Package dpop implements the proof-of-possession checks defined by RFC 9449.
package dpop

import (
	"crypto"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

const (
	// Header is the HTTP header carrying a DPoP proof.
	Header = "DPoP"
	// Scheme is the Authorization scheme used with DPoP-bound access tokens.
	Scheme = "DPoP"
	// ProofType is the required JWT "typ" header of a DPoP proof.
	ProofType = "dpop+jwt"
)

// maxProofAge bounds how long a proof can be replayed.
const maxProofAge = 5 * time.Minute

// clockSkew allows for small differences between the client and server clocks.
const clockSkew = 30 * time.Second

var supportedAlgorithms = []jose.SignatureAlgorithm{
	jose.RS256,
	jose.RS384,
	jose.RS512,
	jose.PS256,
	jose.PS384,
	jose.PS512,
	jose.ES256,
	jose.ES384,
	jose.ES512,
	jose.EdDSA,
}

// ErrReplay is returned when a proof with the same key and jti was already used.
var ErrReplay = errors.New("dpop: proof has already been used")

// Claims are the JWT claims carried by a DPoP proof.
type Claims struct {
	JWTID           string `json:"jti"`
	Method          string `json:"htm"`
	URL             string `json:"htu"`
	IssuedAt        int64  `json:"iat"`
	AccessTokenHash string `json:"ath,omitempty"`
}

// Proof is a validated DPoP proof.
type Proof struct {
	JWK    *jose.JSONWebKey
	JKT    string
	Claims Claims
}

// ReplayCache remembers proof identifiers for as long as the proof would be
// accepted. It is safe for concurrent use.
type ReplayCache struct {
	mu   sync.Mutex
	seen map[string]time.Time
}

// NewReplayCache returns an empty replay cache.
func NewReplayCache() *ReplayCache {
	return &ReplayCache{seen: make(map[string]time.Time)}
}

// CheckAndStore records proof and rejects a jti that this key already used.
func (c *ReplayCache) CheckAndStore(proof *Proof, now time.Time) error {
	if c == nil || proof == nil {
		return nil
	}
	key := proof.JKT + "\x00" + proof.Claims.JWTID

	c.mu.Lock()
	defer c.mu.Unlock()
	for id, expires := range c.seen {
		if !expires.After(now) {
			delete(c.seen, id)
		}
	}
	if expires, ok := c.seen[key]; ok && expires.After(now) {
		return ErrReplay
	}
	c.seen[key] = now.Add(maxProofAge)
	return nil
}

// Thumbprint returns the base64url-encoded SHA-256 JWK thumbprint used in a
// token's cnf.jkt claim.
func Thumbprint(key *jose.JSONWebKey) (string, error) {
	if key == nil || !key.Valid() || !key.IsPublic() {
		return "", errors.New("dpop: proof key must be a valid public JWK")
	}
	sum, err := key.Thumbprint(crypto.SHA256)
	if err != nil {
		return "", fmt.Errorf("dpop: compute JWK thumbprint: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(sum), nil
}

// AccessTokenHash returns the ath claim value for an access token.
func AccessTokenHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// Verify validates proof for r. accessToken is empty when the proof is for a
// token request; for a protected-resource request it is the access token and
// the proof's ath claim must bind the proof to that token.
func Verify(r *http.Request, proof string, accessToken string, now time.Time) (*Proof, error) {
	if proof == "" {
		return nil, errors.New("dpop: missing proof")
	}

	jws, err := jose.ParseSignedCompact(proof, supportedAlgorithms)
	if err != nil {
		return nil, fmt.Errorf("dpop: parse proof: %w", err)
	}
	if len(jws.Signatures) != 1 {
		return nil, errors.New("dpop: proof must contain exactly one signature")
	}

	header := jws.Signatures[0].Header
	if !strings.EqualFold(asString(header.ExtraHeaders[jose.HeaderType]), ProofType) {
		return nil, fmt.Errorf("dpop: proof typ must be %q", ProofType)
	}
	key := header.JSONWebKey
	jkt, err := Thumbprint(key)
	if err != nil {
		return nil, err
	}

	payload, err := jws.Verify(key)
	if err != nil {
		return nil, fmt.Errorf("dpop: verify proof signature: %w", err)
	}

	var claims Claims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("dpop: decode proof claims: %w", err)
	}
	if claims.JWTID == "" {
		return nil, errors.New("dpop: proof is missing jti")
	}
	if claims.Method != r.Method {
		return nil, fmt.Errorf("dpop: proof htm %q does not match request method %q", claims.Method, r.Method)
	}
	if err := matchRequestURL(claims.URL, r); err != nil {
		return nil, err
	}
	if claims.IssuedAt == 0 {
		return nil, errors.New("dpop: proof is missing iat")
	}
	issuedAt := time.Unix(claims.IssuedAt, 0)
	if issuedAt.After(now.Add(clockSkew)) || issuedAt.Before(now.Add(-maxProofAge)) {
		return nil, errors.New("dpop: proof is outside the accepted time window")
	}

	if accessToken != "" {
		if claims.AccessTokenHash == "" {
			return nil, errors.New("dpop: proof is missing ath")
		}
		if claims.AccessTokenHash != AccessTokenHash(accessToken) {
			return nil, errors.New("dpop: proof ath does not match the access token")
		}
	}

	return &Proof{JWK: key, JKT: jkt, Claims: claims}, nil
}

func matchRequestURL(raw string, r *http.Request) error {
	if raw == "" {
		return errors.New("dpop: proof is missing htu")
	}
	got, err := url.Parse(raw)
	if err != nil || !got.IsAbs() || got.Host == "" {
		return errors.New("dpop: proof htu must be an absolute URL")
	}

	want := *r.URL
	if want.Scheme == "" {
		if r.TLS != nil {
			want.Scheme = "https"
		} else {
			want.Scheme = "http"
		}
	}
	if want.Host == "" {
		want.Host = r.Host
	}

	if !strings.EqualFold(got.Scheme, want.Scheme) ||
		!strings.EqualFold(got.Host, want.Host) ||
		got.EscapedPath() != want.EscapedPath() {
		return fmt.Errorf("dpop: proof htu %q does not match request URL %q", raw, want.String())
	}
	return nil
}

func asString(v any) string {
	s, _ := v.(string)
	return s
}
