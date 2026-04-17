package api

import (
	"log"
	"threat-monitoring/internal/app/handler"
	"threat-monitoring/internal/app/repository"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

func StartServer() {
	log.Println("Starting Threat Monitoring Server")

	repo, err := repository.NewRepository()
	if err != nil {
		logrus.Error("ошибка инициализации репозитория")
	}

	handler := handler.NewHandler(repo)

	r := gin.Default()
	r.LoadHTMLGlob("../frontend/templates/*")
	r.GET("/static/styles/style.css", func(c *gin.Context) {
		logrus.Info("Запрос CSS")
		c.Header("Content-Type", "text/css")
		c.File("../frontend/resources/styles/style.css")
		logrus.Info("CSS получен")
	})

	r.GET("/login", handler.GetLogin)
	r.POST("/login", handler.HandleLogin)

	r.GET("/employee", handler.GetEmployeeIndex)

	r.GET("/specialist", handler.GetSpecialistIndex)

	r.GET("/request/:id", handler.GetRequest)
	r.GET("/threat/:id", handler.GetThreat)

	r.Run(":8080")
	log.Println("Server down")
}
