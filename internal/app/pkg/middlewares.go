package pkg

import (
	"context"
	"net/http"
	"strings"
	"time"

	"threat-monitoring/internal/app/ds"

	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"github.com/sirupsen/logrus"
)

const (
	AccessTokenCookie = "access_token"
	sessionPrefix     = "session:"
	blacklistPrefix   = "blacklist:"
)

func TokenFromRequest(ctx *gin.Context) string {
	authHeader := ctx.GetHeader("Authorization")

	if strings.HasPrefix(authHeader, "Bearer ") {
		token := strings.TrimSpace(strings.TrimPrefix(authHeader, "Bearer "))
		return token
	}

	if authHeader != "" {
		return authHeader
	}

	if token, err := ctx.Cookie(AccessTokenCookie); err == nil {
		return token
	}

	logrus.Debug("Токен не найден ни в заголовках, ни в куках")
	return ""
}

func SessionKey(token string) string {
	return sessionPrefix + token
}

func BlacklistKey(token string) string {
	return blacklistPrefix + token
}

func IsTokenBlacklisted(ctx context.Context, redisClient *redis.Client, token string) bool {
	if token == "" {
		return false
	}
	_, err := redisClient.Get(ctx, BlacklistKey(token)).Result()
	return err == nil
}

func IsSessionActive(ctx context.Context, redisClient *redis.Client, token string) bool {
	if token == "" {
		return false
	}

	if IsTokenBlacklisted(ctx, redisClient, token) {
		return false
	}

	_, err := redisClient.Get(ctx, SessionKey(token)).Result()
	return err == nil
}

func AddToBlacklist(ctx context.Context, redisClient *redis.Client, token string, ttl time.Duration) error {
	return redisClient.Set(ctx, BlacklistKey(token), "revoked", ttl).Err()
}

func AuthMiddleware(redisClient *redis.Client, jwtSecret []byte) gin.HandlerFunc {
	return func(ctx *gin.Context) {
		tokenString := TokenFromRequest(ctx)
		if tokenString == "" {
			ctx.JSON(http.StatusUnauthorized, gin.H{"status": "error", "message": "Требуется авторизация"})
			ctx.Abort()
			return
		}

		claims, err := ds.ParseToken(tokenString, jwtSecret)
		if err != nil {
			ctx.JSON(http.StatusUnauthorized, gin.H{"status": "error", "message": "Недействительный токен"})
			ctx.Abort()
			return
		}

		if !IsSessionActive(ctx.Request.Context(), redisClient, tokenString) {
			ctx.JSON(http.StatusUnauthorized, gin.H{"status": "error", "message": "Сессия недействительна"})
			ctx.Abort()
			return
		}

		ctx.Set("user_id", claims.UserID)
		ctx.Set("user_type", claims.UserType)
		ctx.Set("user_name", claims.FullName)
		ctx.Next()
	}
}
