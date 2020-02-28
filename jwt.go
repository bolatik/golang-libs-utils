package jwt

import (
	"errors"
	jwtgo "github.com/dgrijalva/jwt-go"
	jwtverifier "github.com/okta/okta-jwt-verifier-golang"
	"encoding/base64"
	"strings"
	"encoding/json"
)

const privKey = `-----BEGIN RSA PRIVATE KEY-----

-----END RSA PRIVATE KEY-----`

const pubKey = `-----BEGIN PUBLIC KEY-----

-----END PUBLIC KEY-----`

func NewJwt(claims *Claims) (string, error) {
	t := jwtgo.NewWithClaims(jwtgo.GetSigningMethod("RS256"), claims)
	signKey, err := jwtgo.ParseRSAPrivateKeyFromPEM([]byte(privKey))
	if err != nil {
		return "", err
	}
	return t.SignedString(signKey)
}

func Parse(idToken string) (*Claims, error) {
	pub, err := jwtgo.ParseRSAPublicKeyFromPEM([]byte(pubKey))
	if err != nil {
		return nil, err
	}
	token, err := jwtgo.ParseWithClaims(idToken, &Claims{}, func(token *jwtgo.Token) (interface{}, error) {
		return pub, nil
	})
	if claims, ok := token.Claims.(*Claims); ok && token.Valid {
		return claims, nil
	}
	return nil, err
}

var (
	ErrInvalidJWTToken = errors.New("Token is invalid.")
)

type OktaJWT struct {
	Ver int64      `json:"ver"`
	Jti string   `json:"jti"`
	Iss string   `json:"iss"`
	Aud string   `json:"aud"`
	Sub string   `json:"sub"`
	Iat int64      `json:"iat"`
	Exp int64      `json:"exp"`
	Cid string   `json:"cid"`
	UID string   `json:"uid"`
	Scp []string `json:"scp"`
}

type OktaJWTValidator struct {
	verifier *jwtverifier.JwtVerifier
}

func NewOktaJWTValidator(clientId, issuer string) (*OktaJWTValidator, error) {
	toValidate := map[string]string{}
	toValidate["aud"] = clientId // "{CLIENT_ID}"

	jwtVerifierSetup := jwtverifier.JwtVerifier{
		Issuer: issuer, // "{ISSUER}",
		ClaimsToValidate: toValidate,
	}

	verifier := jwtVerifierSetup.New()
	return &OktaJWTValidator{verifier}, nil
}

func (vltd *OktaJWTValidator) Validate(tkn string) (*OktaJWT, error) {
	parts := strings.Split(tkn, ".")
	payload := parts[1]
	data, err := base64.RawStdEncoding.DecodeString(payload)
	jwtTkn := &OktaJWT{}
	err = json.Unmarshal(data, jwtTkn)
	if err != nil {
		return nil, err
	}
	return jwtTkn, nil
}

//func (vltd *OktaJWTValidator) Validate(tkn string) (*OktaJWT, error) {
//	token, err := vltd.verifier.VerifyIdToken(tkn)
//	if err != nil {
//		return nil, err
//	}
//	ver, ok := token.Claims["ver"].(int64)
//	if !ok {
//		return nil, err
//	}
//	jti, ok := token.Claims["jti"].(string)
//	if !ok {
//		return nil, err
//	}
//	iss, ok := token.Claims["iss"].(string)
//	if !ok {
//		return nil, err
//	}
//	aud, ok := token.Claims["aud"].(string)
//	if !ok {
//		return nil, err
//	}
//	sub, ok := token.Claims["sub"].(string)
//	if !ok {
//		return nil, err
//	}
//	iat, ok := token.Claims["iat"].(int64)
//	if !ok {
//		return nil, err
//	}
//	exp, ok := token.Claims["exp"].(int64)
//	if !ok {
//		return nil, err
//	}
//	cid, ok := token.Claims["cid"].(string)
//	if !ok {
//		return nil, err
//	}
//	uid, ok := token.Claims["uid"].(string)
//	if !ok {
//		return nil, err
//	}
//	scp, ok := token.Claims["scp"].([]string)
//	if !ok {
//		return nil, err
//	}
//	idTkn := &OktaJWT{
//		Ver: ver,
//		Jti: jti,
//		Iss: iss,
//		Aud: aud,
//		Sub: sub,
//		Iat: iat,
//		Exp: exp,
//		Cid: cid,
//		UID: uid,
//		Scp: scp,
//	}
//	return idTkn, nil
//}
