package api

import (
	"context"
	"net/http"
	"os"
	"strings"
	"threat-monitoring/docs"
	"threat-monitoring/internal/app/handler"
	"threat-monitoring/internal/app/pkg"
	"threat-monitoring/internal/app/repository"
	"time"

	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"github.com/sirupsen/logrus"
)

var swaggerJSON []byte

func StartServer() {
	logrus.SetFormatter(&logrus.TextFormatter{
		FullTimestamp:   true,
		TimestampFormat: "2006-01-02 15:04:05",
	})

	logLevel := os.Getenv("LOG_LEVEL")
	if logLevel == "" {
		logLevel = "trace"
	}
	level, err := logrus.ParseLevel(strings.ToLower(logLevel))
	if err != nil {
		logrus.Warnf("Неверный LOG_LEVEL=%q, используется INFO", logLevel)
		level = logrus.InfoLevel
	}
	logrus.SetLevel(level)
	logrus.Infof("Logrus initialized, level=%s", level.String())

	logrus.Info("Starting Threat Monitoring Server")

	dbUser := os.Getenv("DB_USER")
	if dbUser == "" {
		dbUser = "postgres"
	}
	dbPassword := os.Getenv("DB_PASSWORD")
	if dbPassword == "" {
		dbPassword = ""
	}
	dbHost := os.Getenv("DB_HOST")
	if dbHost == "" {
		dbHost = "127.0.0.1"
	}
	dbPort := os.Getenv("DB_PORT")
	if dbPort == "" {
		dbPort = "5433"
	}
	dbName := os.Getenv("DB_NAME")
	if dbName == "" {
		dbName = "threat_monitoring"
	}

	dsn := repository.GetDSN(dbUser, dbPassword, dbHost, dbPort, dbName)
	logrus.WithFields(logrus.Fields{
		"db_user": dbUser,
		"db_host": dbHost,
		"db_port": dbPort,
		"db_name": dbName,
	}).Info("Database configuration loaded")

	repo, err := repository.NewDatabase(dsn)
	if err != nil {
		logrus.Fatal("Ошибка при подключении к БД:", err)
		return
	}

	redisHost := os.Getenv("REDIS_HOST")
	if redisHost == "" {
		redisHost = "127.0.0.1"
	}
	redisPort := os.Getenv("REDIS_PORT")
	if redisPort == "" {
		redisPort = "6379"
	}
	redisPassword := os.Getenv("REDIS_PASSWORD")
	redisAddr := redisHost + ":" + redisPort
	redisClient := redis.NewClient(&redis.Options{
		Addr:     redisAddr,
		Password: redisPassword,
		DB:       0,
	})
	if err := redisClient.Ping(context.Background()).Err(); err != nil {
		logrus.Fatal("Ошибка при подключении к Redis:", err)
		return
	}

	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		jwtSecret = "threat-monitoring-secret"
	}
	jwtTTL := 24 * time.Hour

	h := handler.NewHandler(repo, redisClient, []byte(jwtSecret), jwtTTL)

	swaggerJSON = []byte(docs.SwaggerInfo.ReadDoc())

	r := gin.Default()
	r.Use(gin.Recovery())
	r.Use(gin.Logger())

	r.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"http://localhost:5173", "http://localhost:3000", "http://localhost:9090"},
		AllowMethods:     []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowHeaders:     []string{"Origin", "Content-Type", "Authorization"},
		AllowCredentials: true,
	}))

	r.Use(pkg.PrometheusMiddleware())

	r.GET("/", h.ReturnOK)
	r.GET("/metrics", pkg.MetricsHandler())

	api := r.Group("/api")
	{
		api.POST("/auth/login", h.LoginAPI)
		api.POST("/auth/logout", h.LogoutAPI)

		apiAuth := api.Group("")
		apiAuth.Use(h.AuthMiddleware())
		{
			apiAuth.POST("/auth/register", h.RegisterAPI)
			apiAuth.GET("/auth/profile", h.ProfileAPI)
			apiAuth.GET("/requests", h.GetRequestsAPI)
			apiAuth.GET("/requests/:id", h.GetRequestAPI)
			apiAuth.POST("/requests", h.CreateRequestAPI)
			apiAuth.PUT("/requests/:id", h.UpdateRequestAPI)
			apiAuth.PUT("/requests/:id/submit", h.SubmitRequest)
			apiAuth.PUT("/requests/:id/complete", h.CompleteRequest)
			apiAuth.DELETE("/requests/:id", h.DeleteRequestAPI)

			apiAuth.GET("/requests/:id/facts", h.GetRequestFactsAPI)
			apiAuth.POST("/requests/:id/facts", h.CreateFactAPI)
		}
	}

	r.GET("/swagger", func(c *gin.Context) {
		c.File("./docs/swagger.html")
	})

	r.GET("/swagger/swagger.json", func(c *gin.Context) {
		c.Data(http.StatusOK, "application/json", swaggerJSON)
	})

	if err := r.Run(":8080"); err != nil {
		logrus.Fatal("Ошибка при запуске сервера:", err)
	}
	logrus.Info("Server down")
}
