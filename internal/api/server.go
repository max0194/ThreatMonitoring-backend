package api

import (
	"log"
	"os"
	"threat-monitoring/internal/app/handler"
	"threat-monitoring/internal/app/repository"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

func StartServer() {
	log.Println("Starting Threat Monitoring Server")

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
	repo, err := repository.NewDatabase(dsn)
	if err != nil {
		logrus.Fatal("Ошибка при подключении к БД:", err)
		return
	}

	h := handler.NewHandler(repo)

	r := gin.Default()
	r.Use(gin.Recovery())
	r.Use(gin.Logger())

	r.Use(func(c *gin.Context) {
		c.Header("Content-Type", "text/html; charset=utf-8")
		c.Next()
	})

	r.LoadHTMLGlob("../frontend/templates/*")

	r.GET("/static/styles/style.css", func(c *gin.Context) {
		logrus.Info("Запрос CSS")
		c.Header("Content-Type", "text/css")
		c.File("../frontend/resources/styles/style.css")
		logrus.Info("CSS получен")
	})

	r.GET("/login", h.GetLogin)
	r.POST("/login", h.HandleLogin)
	r.GET("/logout", h.Logout)

	r.GET("/employee", h.GetEmployeeIndex)
	r.GET("/employee/requests", h.GetEmployeeRequests)
	r.POST("/create-request", h.CreateRequest)
	r.POST("/create-fact", h.CreateFact)

	r.GET("/specialist", h.GetSpecialistIndex)

	r.GET("/request/:id", h.GetRequest)
	r.GET("/threat/:id", h.GetThreat)
	r.POST("/request/:id/delete", h.DeleteRequest)
	r.POST("/request/:id/update-status", h.UpdateRequestStatus)

	if err := r.Run(":8080"); err != nil {
		logrus.Fatal("Ошибка при запуске сервера:", err)
	}
	log.Println("Server down")
}
