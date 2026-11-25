package authflow

// statecookie.go binds the connector "state" parameter to the browser that
// started the login. The state value is the auth request ID, which is not
// secret: it appears in the upstream provider's address bar, browser history,
// Referer headers and logs. A cookie that only the initiating browser holds is
// therefore checked alongside it, so a state value taken from another login
// can only be replayed by the browser that started that login.

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"net/http"

	"github.com/dexidp/dex/storage"
)

const (
	stateCookieName = "dex_state"
	// stateNonceSize is the size in bytes of the per-login random nonce.
	stateNonceSize = 32
)

// newStateNonce returns a cryptographically random, URL-safe nonce.
func newStateNonce() (string, error) {
	buf := make([]byte, stateNonceSize)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func (h *Handler) stateCookiePath() string {
	if h.IssuerURL.Path == "" {
		return "/"
	}
	return h.IssuerURL.Path
}

// stateMAC derives the authenticator for a state cookie. The auth request's
// HMAC key is server-side random material created with the request, so the
// cookie cannot be forged without storage access and remains verifiable in a
// stateless deployment: nothing beyond the request record is kept.
func stateMAC(hmacKey []byte, authID, nonce string) string {
	mac := hmac.New(sha256.New, hmacKey)
	mac.Write([]byte(authID))
	mac.Write([]byte{'|'})
	mac.Write([]byte(nonce))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// setStateCookie records the nonce bound to this login on the response. The
// value carries its own HMAC over the auth request ID, so a cookie copied from
// another login cannot be replayed against a different state.
func (h *Handler) setStateCookie(w http.ResponseWriter, authReq storage.AuthRequest, nonce string) {
	value := nonce + "." + stateMAC(authReq.HMACKey, authReq.ID, nonce)
	http.SetCookie(w, &http.Cookie{
		Name:     stateCookieName,
		Value:    value,
		Path:     h.stateCookiePath(),
		MaxAge:   int(h.AuthRequestsValidFor.Seconds()),
		HttpOnly: true,
		Secure:   h.IssuerURL.Scheme == "https",
		SameSite: http.SameSiteLaxMode,
	})
}

// clearStateCookie removes the state cookie once it has served its purpose.
func (h *Handler) clearStateCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     stateCookieName,
		Value:    "",
		Path:     h.stateCookiePath(),
		HttpOnly: true,
		Secure:   h.IssuerURL.Scheme == "https",
		SameSite: http.SameSiteLaxMode,
		MaxAge:   -1,
	})
}

// validStateCookie reports whether the request carries the nonce cookie issued
// for this auth request. A missing, malformed or mismatched cookie means the
// callback was not driven by the browser that started the login.
func validStateCookie(r *http.Request, hmacKey []byte, authID string) bool {
	cookie, err := r.Cookie(stateCookieName)
	if err != nil || cookie.Value == "" {
		return false
	}

	nonce, mac, ok := splitCookieValue(cookie.Value)
	if !ok {
		return false
	}

	expected := stateMAC(hmacKey, authID, nonce)
	return subtle.ConstantTimeCompare([]byte(mac), []byte(expected)) == 1
}

func splitCookieValue(value string) (nonce, mac string, ok bool) {
	for i := len(value) - 1; i >= 0; i-- {
		if value[i] == '.' {
			if i == 0 || i == len(value)-1 {
				return "", "", false
			}
			return value[:i], value[i+1:], true
		}
	}
	return "", "", false
}
