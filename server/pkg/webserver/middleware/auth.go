package middleware

import (
	"github.com/iris-contrib/middleware/jwt"
	"github.com/kataras/iris/v12"
)

var (
	mySecret     = []byte("login secret")
	WhiteListMap = map[string]struct{}{
		"POST/api-nebula/db/connect": {},
	}
)

func GetLoginTokenHandler(nebulaAddress string, username string) string {
	token := jwt.NewTokenWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"nebulaAddress": nebulaAddress,
		"username":      username,
	})
	tokenString, _ := token.SignedString(mySecret)

	return tokenString
}

func AuthenticatedLoginHandler(ctx iris.Context) error {
	url := ctx.RouteName()
	//HACK: Whitelisted urls do not require JWT authentication
	if _, ok := WhiteListMap[url]; ok {
		ctx.Next()
		return nil
	}

	j := jwt.New(jwt.Config{
		ValidationKeyGetter: func(token *jwt.Token) (interface{}, error) {
			return mySecret, nil
		},
		Expiration:    false,
		Extractor:     jwt.FromAuthHeader,
		SigningMethod: jwt.SigningMethodHS256,
	})
	if err := j.CheckJWT(ctx); err != nil {
		return err
	}

	token := ctx.Values().Get("jwt").(*jwt.Token)

	userInfo := token.Claims.(jwt.MapClaims)
	for key, value := range userInfo {
		ctx.Values().Set(key, value)
	}
	ctx.Next()
	return nil
}
