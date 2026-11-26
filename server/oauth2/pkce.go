package oauth2

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"slices"
)

// PKCEConfig holds PKCE (Proof Key for Code Exchange) settings shared by every
// flow that starts a PKCE challenge. It is read by both the authorization code
// flow and the device authorization flow so a single configuration governs both.
type PKCEConfig struct {
	// If true, PKCE is required. Flows that cannot reject legacy clients yet
	// (the device authorization flow) treat this as a warning instead.
	Enforce bool
	// Supported code challenge methods. Defaults to ["S256", "plain"].
	CodeChallengeMethodsSupported []string
}

// ParseCodeChallengeMethod resolves the code_challenge_method of an authorization
// request. An absent method keeps the historical default of plain, so clients
// that send a code_challenge without a method do not break when plain is still a
// supported method.
func ParseCodeChallengeMethod(method string) string {
	if method == "" {
		return PKCEMethodPlain
	}
	return method
}

// MethodSupported reports whether the parsed challenge method is in the
// configured allow-list.
func (c PKCEConfig) MethodSupported(method string) bool {
	return slices.Contains(c.CodeChallengeMethodsSupported, method)
}

// ValidateCodeChallengeMethod resolves and validates a code_challenge_method
// against the configured allow-list. As with ParseCodeChallengeMethod, an
// absent method defaults to plain to keep legacy clients working. An explicitly
// requested method that the configuration does not support is rejected.
func (c PKCEConfig) ValidateCodeChallengeMethod(method string) (string, error) {
	explicit := method != ""
	method = ParseCodeChallengeMethod(method)
	if explicit && !c.MethodSupported(method) {
		return method, fmt.Errorf("unsupported PKCE challenge method (%q)", method)
	}
	return method, nil
}

// CalculateCodeChallenge derives the PKCE code challenge from a code verifier for
// the given method (RFC 7636). It is shared by every grant that verifies PKCE.
func CalculateCodeChallenge(codeVerifier, codeChallengeMethod string) (string, error) {
	switch codeChallengeMethod {
	case PKCEMethodPlain:
		return codeVerifier, nil
	case PKCEMethodS256:
		shaSum := sha256.Sum256([]byte(codeVerifier))
		return base64.RawURLEncoding.EncodeToString(shaSum[:]), nil
	default:
		return "", fmt.Errorf("unknown challenge method (%v)", codeChallengeMethod)
	}
}
