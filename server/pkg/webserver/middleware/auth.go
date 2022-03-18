package middleware

import (
	"github.com/iris-contrib/middleware/jwt"
	"time"
)

var (
	mySecret     = []byte("login secret")
)

func GetLoginTokenHandler(user string, id int) string {
	now := time.Now()
	token := jwt.NewTokenWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"username": user,
		"id":       id,
		"iat":      now.Unix(),
		"exp":      now.Add(24 * time.Hour).Unix(),
	})

	tokenString, _ := token.SignedString(mySecret)

	return tokenString
}