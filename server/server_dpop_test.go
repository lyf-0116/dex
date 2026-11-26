package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/require"

	"github.com/dexidp/dex/server/dpop"
	"github.com/dexidp/dex/server/oauth2"
	"github.com/dexidp/dex/server/tokens"
	"github.com/dexidp/dex/storage"
)

func newDPoPKey(t *testing.T) (*ecdsa.PrivateKey, *jose.JSONWebKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return key, &jose.JSONWebKey{Key: &key.PublicKey, Algorithm: string(jose.ES256)}
}

func signDPoPProof(t *testing.T, key *ecdsa.PrivateKey, public *jose.JSONWebKey, method, htu, ath string) string {
	t.Helper()
	opts := (&jose.SignerOptions{}).
		WithType(dpop.ProofType).
		WithHeader("jwk", public.Public())
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES256, Key: key}, opts)
	require.NoError(t, err)

	payload := map[string]any{
		"jti": testRandomID(t),
		"htm": method,
		"htu": htu,
		"iat": time.Now().Unix(),
	}
	if ath != "" {
		payload["ath"] = ath
	}
	raw, err := json.Marshal(payload)
	require.NoError(t, err)
	object, err := signer.Sign(raw)
	require.NoError(t, err)
	proof, err := object.CompactSerialize()
	require.NoError(t, err)
	return proof
}

func testRandomID(t *testing.T) string {
	t.Helper()
	var b [16]byte
	_, err := rand.Read(b[:])
	require.NoError(t, err)
	return base64.RawURLEncoding.EncodeToString(b[:])
}

func postTokenRequest(t *testing.T, s *Server, tokenURL string, vals url.Values, proof string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, tokenURL, strings.NewReader(vals.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if proof != "" {
		req.Header.Set(dpop.Header, proof)
	}
	rr := httptest.NewRecorder()
	s.ServeHTTP(rr, req)
	return rr
}

func TestDPoPBindsTokensAndProtectsUserInfo(t *testing.T) {
	ctx := t.Context()
	httpServer, s := newTestServer(t, func(c *Config) {
		require.NoError(t, c.Storage.CreateClient(ctx, storage.Client{
			ID:          "bound-client",
			Secret:      "bound-secret",
			RequireDPoP: true,
		}))
		require.NoError(t, c.Storage.CreateClient(ctx, storage.Client{
			ID:     "legacy-client",
			Secret: "legacy-secret",
		}))
	})
	defer httpServer.Close()

	key, public := newDPoPKey(t)
	jkt, err := dpop.Thumbprint(public)
	require.NoError(t, err)

	vals := url.Values{
		"grant_type":    {oauth2.GrantTypeClientCredentials},
		"client_id":     {"bound-client"},
		"client_secret": {"bound-secret"},
		"scope":         {"openid"},
	}

	rr := postTokenRequest(t, s, httpServer.URL+"/token", vals, "")
	require.Equal(t, http.StatusBadRequest, rr.Code, rr.Body.String())
	require.Contains(t, rr.Body.String(), oauth2.InvalidDPoPProof)

	tokenProof := signDPoPProof(t, key, public, http.MethodPost, httpServer.URL+"/token", "")
	rr = postTokenRequest(t, s, httpServer.URL+"/token", vals, tokenProof)
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())

	var tokenResponse tokens.Response
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&tokenResponse))
	require.Equal(t, dpop.Scheme, tokenResponse.TokenType)

	jws, err := jose.ParseSignedCompact(tokenResponse.AccessToken, []jose.SignatureAlgorithm{jose.RS256})
	require.NoError(t, err)
	payload, err := jws.Verify(&testKey.PublicKey)
	require.NoError(t, err)
	var claims struct {
		Confirmation *tokens.Confirmation `json:"cnf"`
	}
	require.NoError(t, json.Unmarshal(payload, &claims))
	require.NotNil(t, claims.Confirmation)
	require.Equal(t, jkt, claims.Confirmation.JWKThumbprint)

	introspectData := url.Values{"token": {tokenResponse.AccessToken}}
	introspectReq := httptest.NewRequest(http.MethodPost, httpServer.URL+"/token/introspect", strings.NewReader(introspectData.Encode()))
	introspectReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	introspectRR := httptest.NewRecorder()
	s.ServeHTTP(introspectRR, introspectReq)
	require.Equal(t, http.StatusOK, introspectRR.Code, introspectRR.Body.String())
	var introspected struct {
		Active    bool   `json:"active"`
		TokenType string `json:"token_type"`
		Extra     struct {
			Confirmation *tokens.Confirmation `json:"cnf"`
		} `json:"ext"`
	}
	require.NoError(t, json.NewDecoder(introspectRR.Body).Decode(&introspected))
	require.True(t, introspected.Active)
	require.Equal(t, dpop.Scheme, introspected.TokenType)
	require.NotNil(t, introspected.Extra.Confirmation)
	require.Equal(t, jkt, introspected.Extra.Confirmation.JWKThumbprint)

	userInfoRequest := func(proof string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, httpServer.URL+"/userinfo", nil)
		req.Header.Set("Authorization", dpop.Scheme+" "+tokenResponse.AccessToken)
		if proof != "" {
			req.Header.Set(dpop.Header, proof)
		}
		rr := httptest.NewRecorder()
		s.ServeHTTP(rr, req)
		return rr
	}

	rr = userInfoRequest("")
	require.Equal(t, http.StatusUnauthorized, rr.Code, rr.Body.String())

	validProof := signDPoPProof(t, key, public, http.MethodGet, httpServer.URL+"/userinfo", dpop.AccessTokenHash(tokenResponse.AccessToken))
	rr = userInfoRequest(validProof)
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())

	rr = userInfoRequest(validProof)
	require.Equal(t, http.StatusUnauthorized, rr.Code, "a proof must not be replayable: %s", rr.Body.String())

	otherKey, otherPublic := newDPoPKey(t)
	wrongKeyProof := signDPoPProof(t, otherKey, otherPublic, http.MethodGet, httpServer.URL+"/userinfo", dpop.AccessTokenHash(tokenResponse.AccessToken))
	rr = userInfoRequest(wrongKeyProof)
	require.Equal(t, http.StatusUnauthorized, rr.Code, rr.Body.String())

	legacy := url.Values{
		"grant_type":    {oauth2.GrantTypeClientCredentials},
		"client_id":     {"legacy-client"},
		"client_secret": {"legacy-secret"},
		"scope":         {"openid"},
	}
	rr = postTokenRequest(t, s, httpServer.URL+"/token", legacy, "")
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
	require.NoError(t, json.NewDecoder(rr.Body).Decode(&tokenResponse))
	require.Equal(t, "bearer", tokenResponse.TokenType)

	req := httptest.NewRequest(http.MethodGet, httpServer.URL+"/userinfo", nil)
	req.Header.Set("Authorization", "Bearer "+tokenResponse.AccessToken)
	rr = httptest.NewRecorder()
	s.ServeHTTP(rr, req)
	require.Equal(t, http.StatusOK, rr.Code, rr.Body.String())
}

func TestDPoPRejectsWrongHTTPTarget(t *testing.T) {
	ctx := t.Context()
	httpServer, s := newTestServer(t, func(c *Config) {
		require.NoError(t, c.Storage.CreateClient(ctx, storage.Client{ID: "client", Secret: "secret"}))
	})
	defer httpServer.Close()

	key, public := newDPoPKey(t)
	proof := signDPoPProof(t, key, public, http.MethodPost, httpServer.URL+"/different", "")
	vals := url.Values{
		"grant_type":    {oauth2.GrantTypeClientCredentials},
		"client_id":     {"client"},
		"client_secret": {"secret"},
	}
	rr := postTokenRequest(t, s, httpServer.URL+"/token", vals, proof)
	require.Equal(t, http.StatusBadRequest, rr.Code, rr.Body.String())
	require.Contains(t, rr.Body.String(), oauth2.InvalidDPoPProof)
}
