package internal

import (
	"errors"
	"time"

	"github.com/dexidp/dex/storage"
)

// ErrAuthRequestExpired is returned when a flow tries to use an auth request
// whose validity period has ended.
var ErrAuthRequestExpired = errors.New("auth request expired")

// AuthRequestExpiredMessage is shown when a flow reaches an expired request.
const AuthRequestExpiredMessage = "User session has expired."

// AuthRequestExpired reports whether authReq's validity period has ended. The
// garbage collector deletes expired requests eventually, but until it does the
// row is still readable; every consumer must enforce the deadline itself.
func AuthRequestExpired(authReq storage.AuthRequest, now time.Time) bool {
	return !now.Before(authReq.Expiry)
}
