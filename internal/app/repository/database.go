package repository

import (
	"fmt"
	"log"

	"github.com/sirupsen/logrus"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

type Database struct {
	DB *gorm.DB
}

func NewDatabase(dsn string) (*Repository, error) {
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		logrus.Fatal("Ошибка подключения к БД:", err)
		return nil, err
	}

	log.Println("Подключение к PostgreSQL успешно")

	err = db.AutoMigrate(
		&User{},
		&Category{},
		&ThreatType{},
		&Request{},
		&Fact{},
	)

	if err != nil {
		logrus.Fatal("Ошибка при выполнении миграций:", err)
		return nil, err
	}

	log.Println("Миграции успешно выполнены")

	minioClient, err := NewMinIOClient("localhost:9000", "minioadmin", "minioadmin", "screenshots", false)
	if err != nil {
		logrus.Fatal("Ошибка инициализации MinIO:", err)
		return nil, err
	}

	log.Println("MinIO клиент инициализирован")

	repo := NewRepository(db, minioClient)

	return repo, nil
}

func GetDSN(user, password, host, port, dbname string) string {
	if password == "" {
		return fmt.Sprintf("host=%s port=%s user=%s dbname=%s sslmode=disable client_encoding=utf8",
			host, port, user, dbname)
	}
	return fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=disable client_encoding=utf8",
		host, port, user, password, dbname)
}
