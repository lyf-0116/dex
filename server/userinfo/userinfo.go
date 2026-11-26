package userinfo

import (
	"crypto/subtle"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"

	"github.com/dexidp/dex/server/dpop"
	"github.com/dexidp/dex/server/oauth2"
	"github.com/dexidp/dex/server/router"
	"github.com/dexidp/dex/server/signer"
	"github.com/dexidp/dex/server/tokens"
	"github.com/dexidp/dex/storage"
)

// Handler serves the OIDC /userinfo endpoint.
type Handler struct {
	Issuer string
	Signer signer.Signer
	Logger *slog.Logger
	// Storage resolves whether the token's client requires DPoP. Nil disables
	// that lookup; a token carrying cnf is still checked.
	Storage storage.Storage

	replayOnce sync.Once
	replay     *dpop.ReplayCache
}

// Mount registers the userinfo route.
func (h *Handler) Mount(m router.Mux) {
	m.HandleCORS("/userinfo", h.handle)
}

func (h *Handler) proofReplayCache() *dpop.ReplayCache {
	h.replayOnce.Do(func() {
		h.replay = dpop.NewReplayCache()
	})
	return h.replay
}

func (h *Handler) handle(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	rawIDToken, scheme, ok := accessTokenFromRequest(r)
	if !ok {
		w.Header().Set("WWW-Authenticate", "Bearer, DPoP")
		h.writeError(w, oauth2.AccessDenied, "Invalid bearer token.", http.StatusUnauthorized)
		return
	}

	verifier := oidc.NewVerifier(h.Issuer, &signer.KeySet{Signer: h.Signer, AcceptAccessTokens: true}, &oidc.Config{SkipClientIDCheck: true})
	idToken, err := verifier.Verify(ctx, rawIDToken)
	if err != nil {
		h.Logger.ErrorContext(ctx, "failed to verify ID token", "err", err)
		h.writeError(w, oauth2.AccessDenied, "Invalid bearer token.", http.StatusForbidden)
		return
	}

	var tokenClaims struct {
		Audience         tokens.Audience      `json:"aud"`
		AuthorizingParty string               `json:"azp"`
		Confirmation     *tokens.Confirmation `json:"cnf"`
	}
	if err := idToken.Claims(&tokenClaims); err != nil {
		h.Logger.ErrorContext(ctx, "failed to decode token confirmation", "err", err)
		h.writeError(w, oauth2.ServerError, "", http.StatusInternalServerError)
		return
	}
	var requiresDPoP bool
	if h.Storage != nil {
		if clientID, err := tokens.GetClientID(tokenClaims.Audience, tokenClaims.AuthorizingParty); err == nil {
			if client, err := h.Storage.GetClient(ctx, clientID); err == nil {
				requiresDPoP = client.RequiresDPoP()
			}
		}
	}
	bound := tokenClaims.Confirmation != nil && tokenClaims.Confirmation.JWKThumbprint != ""
	if requiresDPoP && !bound {
		w.Header().Set("WWW-Authenticate", `DPoP error="invalid_token"`)
		h.writeError(w, oauth2.AccessDenied, "Token is not DPoP-bound.", http.StatusUnauthorized)
		return
	}
	if bound {
		proof := r.Header.Get(dpop.Header)
		if proof == "" {
			w.Header().Set("WWW-Authenticate", `DPoP error="invalid_token"`)
			h.writeError(w, oauth2.AccessDenied, "DPoP proof is required for this token.", http.StatusUnauthorized)
			return
		}
		now := time.Now()
		verified, err := dpop.Verify(r, proof, rawIDToken, now)
		if err != nil {
			h.Logger.InfoContext(ctx, "invalid DPoP proof", "err", err)
			w.Header().Set("WWW-Authenticate", `DPoP error="invalid_token"`)
			h.writeError(w, oauth2.AccessDenied, "Invalid DPoP proof.", http.StatusUnauthorized)
			return
		}
		if err := h.proofReplayCache().CheckAndStore(verified, now); err != nil {
			h.Logger.InfoContext(ctx, "replayed DPoP proof", "err", err)
			w.Header().Set("WWW-Authenticate", `DPoP error="invalid_token"`)
			h.writeError(w, oauth2.AccessDenied, "Invalid DPoP proof.", http.StatusUnauthorized)
			return
		}
		if subtle.ConstantTimeCompare([]byte(verified.JKT), []byte(tokenClaims.Confirmation.JWKThumbprint)) != 1 {
			w.Header().Set("WWW-Authenticate", `DPoP error="invalid_token"`)
			h.writeError(w, oauth2.AccessDenied, "DPoP proof key does not match the token.", http.StatusUnauthorized)
			return
		}
	} else if scheme == dpop.Scheme {
		w.Header().Set("WWW-Authenticate", `DPoP error="invalid_token"`)
		h.writeError(w, oauth2.AccessDenied, "Token is not DPoP-bound.", http.StatusUnauthorized)
		return
	}

	var claims json.RawMessage
	if err := idToken.Claims(&claims); err != nil {
		h.Logger.ErrorContext(ctx, "failed to decode ID token claims", "err", err)
		h.writeError(w, oauth2.ServerError, "", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.Write(claims)
}

func accessTokenFromRequest(r *http.Request) (string, string, bool) {
	scheme, token, ok := strings.Cut(r.Header.Get("Authorization"), " ")
	if !ok || token == "" {
		return "", "", false
	}
	switch {
	case strings.EqualFold(scheme, "Bearer"):
		return token, "Bearer", true
	case strings.EqualFold(scheme, dpop.Scheme):
		return token, dpop.Scheme, true
	default:
		return "", "", false
	}
}

func (h *Handler) writeError(w http.ResponseWriter, typ, description string, statusCode int) {
	oauth2.WriteErrorResponse(h.Logger, w, typ, description, statusCode)
}
