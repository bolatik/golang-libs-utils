package jwt

import (
	"crypto/subtle"
	"fmt"
	"time"

	"github.com/bolatik/golang-libs-utils/set"
)

// Structured version of Claims Section, as referenced at
// https://tools.ietf.org/html/rfc7519#section-4.1
// See examples for how to use this with your own claim types
type Claims struct {
	Audience      string                    `json:"aud,omitempty"`
	ExpiresAt     int64                     `json:"exp,omitempty"`
	Id            string                    `json:"jti,omitempty"`
	IssuedAt      int64                     `json:"iat,omitempty"`
	Issuer        string                    `json:"iss,omitempty"`
	NotBefore     int64                     `json:"nbf,omitempty"`
	Subject       string                    `json:"sub,omitempty"`
	AuthTime      int64                     `json:"auth_time,omitempty"` // auth timestamp
	Nonce         string                    `json:"nonce,omitempty"`     // nonce string
	Acr           string                    `json:"acr,omitempty"`       // auth context
	Amr           string                    `json:"amr,omitempty"`       // auth methods
	Azp           string                    `json:"azp,omitempty"`       // client id
	Acl           map[string]*set.StringSet `json:"acl,omitempty"`       // ACL
	Email         string                    `json:"email,omitempty"`
	PhoneNumber   string 					`json:"phone_number,omitempty"`
	MfaType       string                    `json:"mfa_type,omitempty"`
}

// Validates time based claims "exp, iat, nbf".
// There is no accounting for clock skew.
// As well, if any of the above claims are not in the token, it will still
// be considered a valid claim.
func (c Claims) Valid() error {
	vErr := new(ValidationError)
	now := time.Now().Unix()

	// The claims below are optional, by default, so if they are set to the
	// default value in Go, let's not fail the verification for them.
	if c.VerifyExpiresAt(now, false) == false {
		delta := time.Unix(now, 0).Sub(time.Unix(c.ExpiresAt, 0))
		vErr.Inner = fmt.Errorf("token is expired by %v", delta)
		vErr.Errors |= ValidationErrorExpired
	}

	if c.VerifyIssuedAt(now, false) == false {
		vErr.Inner = fmt.Errorf("Token used before issued")
		vErr.Errors |= ValidationErrorIssuedAt
	}

	if c.VerifyNotBefore(now, false) == false {
		vErr.Inner = fmt.Errorf("token is not valid yet")
		vErr.Errors |= ValidationErrorNotValidYet
	}

	if vErr.valid() {
		return nil
	}

	return vErr
}

// Compares the aud claim against cmp.
// If required is false, this method will return true if the value matches or is unset
func (c *Claims) VerifyAudience(cmp string, req bool) bool {
	return verifyAud(c.Audience, cmp, req)
}

// Compares the exp claim against cmp.
// If required is false, this method will return true if the value matches or is unset
func (c *Claims) VerifyExpiresAt(cmp int64, req bool) bool {
	return verifyExp(c.ExpiresAt, cmp, req)
}

// Compares the iat claim against cmp.
// If required is false, this method will return true if the value matches or is unset
func (c *Claims) VerifyIssuedAt(cmp int64, req bool) bool {
	return verifyIat(c.IssuedAt, cmp, req)
}

// Compares the iss claim against cmp.
// If required is false, this method will return true if the value matches or is unset
func (c *Claims) VerifyIssuer(cmp string, req bool) bool {
	return verifyIss(c.Issuer, cmp, req)
}

// Compares the nbf claim against cmp.
// If required is false, this method will return true if the value matches or is unset
func (c *Claims) VerifyNotBefore(cmp int64, req bool) bool {
	return verifyNbf(c.NotBefore, cmp, req)
}

// ----- helpers

func verifyAud(aud string, cmp string, required bool) bool {
	if aud == "" {
		return !required
	}
	if subtle.ConstantTimeCompare([]byte(aud), []byte(cmp)) != 0 {
		return true
	} else {
		return false
	}
}

func verifyExp(exp int64, now int64, required bool) bool {
	if exp == 0 {
		return !required
	}
	return now <= exp
}

func verifyIat(iat int64, now int64, required bool) bool {
	if iat == 0 {
		return !required
	}
	return now >= iat
}

func verifyIss(iss string, cmp string, required bool) bool {
	if iss == "" {
		return !required
	}
	if subtle.ConstantTimeCompare([]byte(iss), []byte(cmp)) != 0 {
		return true
	} else {
		return false
	}
}

func verifyNbf(nbf int64, now int64, required bool) bool {
	if nbf == 0 {
		return !required
	}
	return now >= nbf
}
