package authflow

import (
	"crypto"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/dexidp/dex/connector"
	"github.com/dexidp/dex/server/internal"
	"github.com/dexidp/dex/server/oauth2"
	"github.com/dexidp/dex/storage"
)

func TestExpiredAuthRequestRejectedAtFlowEntries(t *testing.T) {
	httpServer, server := newTestHandler(t, nil)
	defer httpServer.Close()

	ctx := t.Context()
	expiry := time.Now().Add(-time.Minute)
	create := func(t *testing.T, id string, loggedIn bool) storage.AuthRequest {
		t.Helper()
		authReq := storage.AuthRequest{
			ID:            id,
			ClientID:      "example-app",
			ConnectorID:   "mock",
			RedirectURI:   "https://client.example/callback",
			ResponseTypes: []string{oauth2.ResponseTypeCode},
			Scopes:        []string{"openid"},
			LoggedIn:      loggedIn,
			Expiry:        expiry,
			HMACKey:       storage.NewHMACKey(crypto.SHA256),
		}
		require.NoError(t, server.Storage.CreateAuthRequest(ctx, authReq))
		return authReq
	}

	t.Run("connector callback", func(t *testing.T) {
		authReq := create(t, "expired-callback", false)
		rr := httptest.NewRecorder()
		server.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/callback/mock?state="+authReq.ID, nil))

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), internal.AuthRequestExpiredMessage)

		_, err := server.Storage.GetAuthRequest(ctx, authReq.ID)
		require.NoError(t, err, "the expired row remains until garbage collection")
	})

	t.Run("password login", func(t *testing.T) {
		authReq := create(t, "expired-password", false)
		rr := httptest.NewRecorder()
		server.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/auth/mock/login?state="+authReq.ID, nil))

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), internal.AuthRequestExpiredMessage)
	})

	t.Run("flow dispatcher", func(t *testing.T) {
		authReq := create(t, "expired-continue", false)
		mac := internal.SignStep(authReq, internal.StepContinue)
		rr := httptest.NewRecorder()
		server.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/auth?req="+authReq.ID+"&hmac="+mac, nil))

		require.Equal(t, http.StatusBadRequest, rr.Code)
		require.Contains(t, rr.Body.String(), internal.AuthRequestExpiredMessage)
	})
}

func TestFinalizeLoginRejectsExpiredAuthRequest(t *testing.T) {
	httpServer, server := newTestHandler(t, nil)
	defer httpServer.Close()

	ctx := t.Context()
	authReq := storage.AuthRequest{
		ID:          "expired-finalize",
		ClientID:    "example-app",
		ConnectorID: "mock",
		Expiry:      time.Now().Add(-time.Minute),
	}
	require.NoError(t, server.Storage.CreateAuthRequest(ctx, authReq))

	_, err := server.finalizeLogin(ctx, connector.Identity{UserID: "user-1"}, authReq, nil)
	require.ErrorIs(t, err, internal.ErrAuthRequestExpired)

	updated, err := server.Storage.GetAuthRequest(ctx, authReq.ID)
	require.NoError(t, err)
	require.False(t, updated.LoggedIn)
}
