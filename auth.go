package main

import (
	"math/rand"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Function randomly generates secret for jwt tokens
func genSecret() []byte {
	const secretLength = 16
	secret := make([]byte, secretLength)
	for i := range secretLength {
		secret[i] = byte(rand.Int())
	}
	return secret
}

// New secret is generated every time the server starts
var secret = genSecret()

// jwt token claims
type Claims struct {
	Username string `json:"username"`
	Password string `json:"password"`
	IsAdmin  bool   `json:"admin"`
	jwt.RegisteredClaims
}

// Function generates jwt token. Not sure if this works
func genJwt(user UserCredentials, secret []byte) (string, error) {
	expTime := time.Now().Add(10 * time.Minute)
	claims := &Claims{
		Username: user.Username,
		Password: user.Password,
		IsAdmin:  user.IsAdmin,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "net-calc-server",
			ExpiresAt: jwt.NewNumericDate(expTime),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(secret)
}
