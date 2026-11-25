package mfa

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/dexidp/dex/server/internal"
	"github.com/dexidp/dex/storage"
)

func TestExpiredAuthRequestRejectedAtMFAEntry(t *testing.T) {
	_, router, store := newTestHandler(t,
		map[string]Provider{"totp": NewTOTPProvider("test-issuer", nil)},
		[]string{"totp"},
	)

	ctx := t.Context()
	authReq := storage.AuthRequest{
		ID:          "expired-mfa",
		ClientID:    "app",
		ConnectorID: "mock",
		Expiry:      time.Now().Add(-time.Minute),
		HMACKey:     randomHMACKey(t),
		LoggedIn:    true,
		Claims:      storage.Claims{UserID: "user-1"},
	}
	require.NoError(t, store.CreateAuthRequest(ctx, authReq))

	mac := internal.SignStep(authReq, internal.StepMFA)
	rr := httptest.NewRecorder()
	router.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/mfa?req="+authReq.ID+"&hmac="+mac, nil))

	require.Equal(t, http.StatusBadRequest, rr.Code)
	require.Contains(t, rr.Body.String(), internal.AuthRequestExpiredMessage)

	updated, err := store.GetAuthRequest(ctx, authReq.ID)
	require.NoError(t, err)
	require.False(t, updated.MFAValidated)
}
