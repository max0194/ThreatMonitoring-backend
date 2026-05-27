package helpers

import (
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"

	"threat-monitoring/internal/app/handler"
	"threat-monitoring/internal/app/repository"
)

func SetupIntegrationRouter() (*gin.Engine, *gorm.DB, *redis.Client) {
	gin.SetMode(gin.TestMode)

	dsn := "host=postgres user=postgres password=postgres dbname=threat_monitoring_test port=5432 sslmode=disable"

	db, err := gorm.Open(
		postgres.Open(dsn),
		&gorm.Config{},
	)

	if err != nil {
		panic(err)
	}

	error1 := db.AutoMigrate(
		&repository.User{},
		&repository.Category{},
		&repository.ThreatType{},
		&repository.Request{},
		&repository.Fact{},
	)

	if error1 != nil {
		panic(error1)
	}

	miniRedis, err := miniredis.Run()
	if err != nil {
		panic(err)
	}

	redisClient := redis.NewClient(&redis.Options{
		Addr: miniRedis.Addr(),
	})

	if err != nil {
		panic(err)
	}

	repo := repository.NewRepository(
		db,
		nil,
	)

	h := handler.NewHandler(
		repo,
		redisClient,
		[]byte("test-secret"),
		time.Hour,
	)

	r := gin.Default()

	api := r.Group("/api")
	{
		api.POST("/auth/login", h.LoginAPI)
		api.POST("/auth/logout", h.LogoutAPI)

		auth := api.Group("")
		auth.Use(h.AuthMiddleware())
		{
			auth.POST("/auth/register", h.RegisterAPI)

			auth.GET("/requests", h.GetRequestsAPI)
			auth.POST("/requests", h.CreateRequestAPI)

			auth.POST("/requests/:id/facts", h.CreateFactAPI)

			auth.PUT("/requests/:id/submit", h.SubmitRequest)
			auth.PUT("/requests/:id/complete", h.CompleteRequest)
		}
	}

	return r, db, redisClient
}
