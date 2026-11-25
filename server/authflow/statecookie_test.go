package authflow

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/dexidp/dex/storage"
)

func TestStateMACRoundTrip(t *testing.T) {
	key := []byte("per-auth-request-random-key")
	authID := "auth-request-id"

	nonce, err := newStateNonce()
	require.NoError(t, err)
	require.NotEmpty(t, nonce)

	mac := stateMAC(key, authID, nonce)

	r := httptest.NewRequest(http.MethodGet, "/callback?state="+authID, nil)
	r.AddCookie(&http.Cookie{Name: stateCookieName, Value: nonce + "." + mac})
	require.True(t, validStateCookie(r, key, authID), "the cookie issued for this auth request must validate")
}

func TestValidStateCookieRejectsForgedAndMismatched(t *testing.T) {
	key := []byte("per-auth-request-random-key")
	authID := "auth-request-id"
	nonce := "login-nonce"
	mac := stateMAC(key, authID, nonce)

	tests := []struct {
		name   string
		cookie *http.Cookie
	}{
		{
			name:   "missing cookie",
			cookie: nil,
		},
		{
			name:   "empty cookie",
			cookie: &http.Cookie{Name: stateCookieName, Value: ""},
		},
		{
			name:   "malformed cookie without separator",
			cookie: &http.Cookie{Name: stateCookieName, Value: nonce},
		},
		{
			name:   "tampered nonce",
			cookie: &http.Cookie{Name: stateCookieName, Value: "other-nonce." + mac},
		},
		{
			name:   "forged mac",
			cookie: &http.Cookie{Name: stateCookieName, Value: nonce + ".Zm9yZ2Vk"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/callback?state="+authID, nil)
			if tc.cookie != nil {
				r.AddCookie(tc.cookie)
			}
			require.False(t, validStateCookie(r, key, authID))
		})
	}
}

func TestStateCookieIsBoundToAuthRequest(t *testing.T) {
	key := []byte("per-auth-request-random-key")
	nonce := "login-nonce"

	// A cookie minted for one login must not validate against another state,
	// even within the same browser: that is what stops a stolen state value.
	victimCookie := &http.Cookie{
		Name:  stateCookieName,
		Value: nonce + "." + stateMAC(key, "attacker-auth-request", nonce),
	}

	r := httptest.NewRequest(http.MethodGet, "/callback?state=victim-auth-request", nil)
	r.AddCookie(victimCookie)
	require.False(t, validStateCookie(r, key, "victim-auth-request"))
}

// TestCallbackRequiresStateCookie drives the real login entry point and shows
// the attack the cookie closes: the state value alone is enough to locate the
// auth request, but no longer enough to complete the callback on a browser that
// did not start the login.
func TestCallbackRequiresStateCookie(t *testing.T) {
	ctx := t.Context()
	_, s := newTestHandler(t, nil)
	require.NoError(t, s.Storage.CreateClient(ctx, storage.Client{
		ID: "cli", Secret: "secret", Name: "cli", RedirectURIs: []string{"https://example.com/cb"},
	}))

	// The attacker starts their own login and receives both the upstream
	// redirect (carrying state) and the state cookie.
	loginRR := httptest.NewRecorder()
	q := url.Values{"client_id": {"cli"}, "redirect_uri": {"https://example.com/cb"}, "response_type": {"code"}, "scope": {"openid"}}
	s.ServeHTTP(loginRR, httptest.NewRequest(http.MethodGet, "/auth/mock?"+q.Encode(), nil))
	require.Equal(t, http.StatusFound, loginRR.Code)

	upstreamURL, err := url.Parse(loginRR.Header().Get("Location"))
	require.NoError(t, err)
	authID := upstreamURL.Query().Get("state")
	require.NotEmpty(t, authID)

	var stateCookie *http.Cookie
	for _, cookie := range loginRR.Result().Cookies() {
		if cookie.Name == stateCookieName {
			stateCookie = cookie
		}
	}
	require.NotNil(t, stateCookie, "starting a login must set the state cookie")

	// The victim's browser hits the attacker-crafted callback URL with the
	// stolen state but no matching cookie. Existence alone must not pass.
	victimRR := httptest.NewRecorder()
	s.ServeHTTP(victimRR, httptest.NewRequest(http.MethodGet, "/callback?state="+authID, nil))
	require.Equal(t, http.StatusBadRequest, victimRR.Code)

	// The initiating browser presenting its own cookie still completes the flow.
	legitRR := httptest.NewRecorder()
	legitReq := httptest.NewRequest(http.MethodGet, "/callback?state="+authID, nil)
	legitReq.AddCookie(stateCookie)
	s.ServeHTTP(legitRR, legitReq)
	require.Equal(t, http.StatusSeeOther, legitRR.Code)

	// The single-use cookie is cleared once the callback succeeds.
	var cleared bool
	for _, cookie := range legitRR.Result().Cookies() {
		if cookie.Name == stateCookieName && cookie.MaxAge < 0 {
			cleared = true
		}
	}
	require.True(t, cleared, "the state cookie must be cleared after a successful callback")
}
