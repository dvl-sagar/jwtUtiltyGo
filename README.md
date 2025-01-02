
# JWT utility Package

The **JWT Utility Package** is a lightweight, dependency-free library written in Go that simplifies the creation, signing, and validation of JSON Web Tokens (JWT). This package enables developers to integrate JWT-based authentication into their applications with ease, providing support for common claims and custom data.


## Features

- **Generate Tokens**: Create and sign JWTs with customizable claims.
- **Validate Tokens**: Verify the integrity and validity of JWTs.
- **Extract Claims**: Parse and access standard or custom claims from a token.
- **Common Claims Support**:
  - `exp` (Expiration Time)
  - `iss` (Issuer)
  - `sub` (Subject)
  - `aud` (Audience)
- **Custom Claims**: Add any additional key-value pairs to your token payload.
- **Secure**: Uses HMAC with SHA-256 for signing and validation.
- **No External Dependencies**: Designed to be lightweight and self-contained.


## Installation

To use the **JWT Utility Package** in your project, follow these steps:

**Import** the package in your **GO** project:
```go
import jwtUtility "github.com/dvl-sagar/jwtUtiltyGo"
```



## RestApi with JWT utility package

This utility is very lightweight and simple to use there are two methods that is the most important in this package. these two methods are enough to use in RestApi.

1. **GenerateToken()** generate a JWT token and returns the token as string. In occurance of error the relevant error is returned and empty string is returned

```go
func GenerateToken(secretKey string, claims *Claims) (string, error){}
```

Below is an example of a RestApi for Token generation
```go
func LoginHandler(w http.ResponseWriter, r *http.Request) {
	// Simulate user authentication (this is just an example)
	w.Header().Set("Content-Type", "application/json")
	var credentials Credentials
	err := json.NewDecoder(r.Body).Decode(&credentials)
	if err != nil {
		http.Error(w, "Invalid request", http.StatusBadRequest)
		return
	}
	expectPassword, ok := users[credentials.Username]
	if !ok || expectPassword != credentials.Password {
		http.Error(w, "Invalid credentials", http.StatusUnauthorized)
		return
	}
	expireTime := time.Now().Add(time.Minute * 1)
	claims := &jwtUtility.Claims{
		Exp: expireTime.Unix(),
		Iss: "<issuerNameHere>",
		Sub: "<yourSubjectHere>",
		Aud: "<audienceHere>",
		Custom: map[string]interface{}{
			"username": credentials.Username,
			"role":     "<roleHere>",
			"email":    "<EmailHere>",
		},
	}
	token, err := jwtUtility.GenerateToken(secretKey, claims)
	if err != nil {
		http.Error(w, "Internal error", http.StatusInternalServerError)
		return
	}
	res := Response{
		Token:     token,
		Message:   "Login successful",
		Exception: nil,
	}
	rd, _ := json.Marshal(res)
	w.WriteHeader(http.StatusOK)
	w.Write(rd)
}
```
2. **ValidateToken()** validated the provided string token, and the secretKey. It returns the paylaod and nil if the token is valid and correct. In occurance of the error (expired token, invalid token etc.) an error is returned and paylaod is returned as nil.

```go
func ValidateToken(token string, secretKey string) (*Claims, error){}
```
Below is an example of a RestApi for Token validation

```go
func verifyTokenHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	var data map[string]interface{}
	err := json.NewDecoder(r.Body).Decode(&data)
	if err != nil {
		res := Response{
			Message:   err.Error(),
			Exception: err,
		}
		rd, _ := json.Marshal(res)
		w.WriteHeader(http.StatusUnauthorized)
		w.Write(rd)
		return
	}
	token, ok := data["token"].(string)
	if !ok {
		res := Response{
			Token:     token,
			Message:   "token is not a string",
			Exception: nil,
		}
		rd, _ := json.Marshal(res)
		w.WriteHeader(http.StatusBadRequest)
		w.Write(rd)
		return
	}

	claims, err := jwtUtility.ValidateToken(token, secretKey)
	if err != nil {
		res := Response{
			Token:     token,
			Message:   err.Error(),
			Exception: err,
		}
		rd, _ := json.Marshal(res)
		w.WriteHeader(http.StatusUnauthorized)
		w.Write(rd)
		return
	}

	res := Response{
		Token:     token,
		Message:   "Token is valid",
		Exception: nil,
		data:      claims,
	}
	rd, _ := json.Marshal(res)
	w.WriteHeader(http.StatusOK)
	w.Write(rd)
}
```
## Structures used in above RestApi

```go
type Credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type Response struct {
	Token     string      `json:"token,omitempty"`
	Message   string      `json:"message,omitempty"`
	Exception error       `json:"exception,omitempty"`
	data      interface{} `json:"data,omitempty"`
}

var secretKey = "verysecretkey"

var users = map[string]string{
	"user1": "user1password",
	"user2": "user2password",
	"user3": "user3password",
	"user4": "user4password",
}
```
## Usage/Examples

[jwtUtilityImplementation](https://github.com/dvl-sagar/jwtUtilityImplementation)
is a Go project where the [jwtUtility](https://github.com/dvl-sagar/jwtUtiltyGo) Package is used and its implementation are shown. Use it as reference to create your own Go projects. 👍

## License

[MIT](https://choosealicense.com/licenses/mit/)
Copyright (c) [2025] [Sagar Sharma]

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

