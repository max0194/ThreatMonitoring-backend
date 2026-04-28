package main

import (
	"log"
	"threat-monitoring/internal/api"
)

// @title Threat Monitoring
// @version 1.0
// @description API для мониторинга угроз безопасности в информационных системах. Позволяет регистрировать и отслеживать инциденты, связанные с безопасностью, а также управлять ими.

// @contact.name API Support
// @contact.url https://vk.com/club234398304
// @contact.email maksim.ago@mail.ru

// @license.name AS IS (NO WARRANTY)

// @host localhost:8080
// @schemes http
// @BasePath /
// @securityDefinitions.apikey ApiKeyAuth
// @in header
// @name Authorization

func main() {
	log.Println("Application start!")
	api.StartServer()
	log.Println("Application terminated!")
}
