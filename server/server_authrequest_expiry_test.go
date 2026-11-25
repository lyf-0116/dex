package server

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/dexidp/dex/server/internal"
	"github.com/dexidp/dex/server/oauth2"
	"github.com/dexidp/dex/storage"
)

func TestExpiredAuthRequestRejectedAtApproval(t *testing.T) {
	httpServer, server := newTestServer(t, nil)
	defer httpServer.Close()

	ctx := t.Context()
	authReq := storage.AuthRequest{
		ID:            "expired-approval",
		ClientID:      "test",
		ConnectorID:   "mock",
		ResponseTypes: []string{oauth2.ResponseTypeCode},
		RedirectURI:   "https://client.example/callback",
		Expiry:        time.Now().Add(-time.Minute),
		LoggedIn:      true,
		Claims:        storage.Claims{UserID: "user-1"},
		Scopes:        []string{"openid", "email"},
		HMACKey:       []byte("expired-approval-key"),
	}
	require.NoError(t, server.storage.CreateAuthRequest(ctx, authReq))

	mac := internal.SignStep(authReq, internal.StepApproval)
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		t.Run(method, func(t *testing.T) {
			var req *http.Request
			if method == http.MethodGet {
				req = httptest.NewRequest(method, "/approval?req="+authReq.ID+"&hmac="+mac, nil)
			} else {
				form := url.Values{
					"approval": {"approve"},
					"req":      {authReq.ID},
					"hmac":     {mac},
				}
				req = httptest.NewRequest(method, "/approval", strings.NewReader(form.Encode()))
				req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			}

			rr := httptest.NewRecorder()
			server.ServeHTTP(rr, req)

			require.Equal(t, http.StatusBadRequest, rr.Code)
			require.Contains(t, rr.Body.String(), internal.AuthRequestExpiredMessage)
		})
	}

	_, err := server.storage.GetAuthRequest(ctx, authReq.ID)
	require.NoError(t, err, "the expired row remains until garbage collection")
}
