package jwtUtility

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

// Header represents the JWT header structure.
type Header struct {
	Alg string `json:"alg"`
	Typ string `json:"typ"`
}

// Claims represents the JWT claims structure.
type Claims struct {
	Exp    int64                  `json:"exp"` // Expiration time in Unix seconds
	Iss    string                 `json:"iss"` // Issuer
	Sub    string                 `json:"sub"` // Subject
	Aud    string                 `json:"aud"` // Audience
	Custom map[string]interface{} `json:"-"`   // Custom claims
}

// EncodeBase64URL encodes a byte slice to a base64 URL-safe string.
func EncodeBase64URL(data []byte) string {
	return strings.TrimRight(base64.URLEncoding.EncodeToString(data), "=")
}

// DecodeBase64URL decodes a base64 URL-safe string to a byte slice.
func DecodeBase64URL(data string) ([]byte, error) {
	return base64.URLEncoding.DecodeString(data + strings.Repeat("=", (4-len(data)%4)%4))
}

// GenerateToken creates a signed JWT with custom claims.
func GenerateToken(secretKey string, claims *Claims) (string, error) {
	header := Header{
		Alg: "HS256",
		Typ: "JWT",
	}

	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", err
	}

	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}

	headerEncoded := EncodeBase64URL(headerJSON)
	claimsEncoded := EncodeBase64URL(claimsJSON)

	signature := signData(headerEncoded+"."+claimsEncoded, secretKey)
	return headerEncoded + "." + claimsEncoded + "." + signature, nil
}

// ValidateToken verifies the integrity and validity of a JWT.
func ValidateToken(token string, secretKey string) (*Claims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("invalid token format")
	}

	_, err := DecodeBase64URL(parts[0])
	if err != nil {
		return nil, err
	}

	claimsJSON, err := DecodeBase64URL(parts[1])
	if err != nil {
		return nil, err
	}

	expectedSignature := signData(parts[0]+"."+parts[1], secretKey)
	if parts[2] != expectedSignature {
		return nil, errors.New("invalid token signature")
	}

	var claims Claims
	if err := json.Unmarshal(claimsJSON, &claims); err != nil {
		return nil, err
	}

	if claims.Exp < time.Now().Unix() {
		return nil, errors.New("token expired")
	}

	return &claims, nil
}

// signData creates an HMAC SHA-256 signature.
func signData(data string, secretKey string) string {
	h := hmac.New(sha256.New, []byte(secretKey))
	h.Write([]byte(data))
	signature := h.Sum(nil)
	return EncodeBase64URL(signature)
}

// Example Usage
// func main() {
// 	secretKey := "my_secret_key"

// 	claims := &Claims{
// 		Exp: time.Now().Add(time.Hour).Unix(),
// 		Iss: "example_issuer",
// 		Sub: "1234567890",
// 		Aud: "example_audience",
// 		Custom: map[string]interface{}{
// 			"name": "John Doe",
// 			"admin": true,
// 		},
// 	}

// 	token, err := GenerateToken(secretKey, claims)
// 	if err != nil {
// 		panic(err)
// 	}
// 	println("Generated Token:", token)

// 	parsedClaims, err := ValidateToken(token, secretKey)
// 	if err != nil {
// 		panic(err)
// 	}
// 	println("Parsed Claims:", parsedClaims)
// }
