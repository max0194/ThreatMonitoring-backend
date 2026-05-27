package helpers

import (
	"context"
	"net/http"
	"time"

	"github.com/go-redis/redis/v8"

	"threat-monitoring/internal/app/ds"
	"threat-monitoring/internal/app/pkg"
)

var TestJWTSecret = []byte("test-secret")

func AuthorizeRequest(req *http.Request, redisClient *redis.Client, userID int, userType string, fullName string) error {

	token, err := ds.CreateToken(
		TestJWTSecret,
		time.Hour,
		userID,
		userType,
		fullName,
	)

	if err != nil {
		return err
	}

	err = redisClient.Set(
		context.Background(),
		pkg.SessionKey(token),
		"active",
		time.Hour,
	).Err()

	if err != nil {
		return err
	}

	req.AddCookie(&http.Cookie{
		Name:  pkg.AccessTokenCookie,
		Value: token,
	})

	return nil
}
