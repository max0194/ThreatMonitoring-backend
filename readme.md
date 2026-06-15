# ThreatMonitoring Backend

## О проекте
Это backend-сервис для системы мониторинга ИТ-угроз. Приложение принимает запросы, сохраняет данные об угрозах и работает с базой данных PostgreSQL и объектным хранилищем MinIO.

## Требования
* Docker Compose
* Go 1.20 или новее

## Быстрый запуск с контейнерами
1. Перейдите в папку клонированного репозитория (например, backend):
```bash
cd backend
```
2. Запустите контейнеры через Docker Compose:
```bash
cd compose
docker compose up -d
```

Если контейнеры успешно запустились (статус started в `docker compose ps`), то сам сервис будет доступен по адресу:
* `http://localhost:8085`

Веб-интерфейс доступен по адресу:
* `http://localhost:3005`

Админка для базы данных доступна по адресу:
* `http://localhost:8084`

## Проверка окружения
Перед запуском убедитесь, что:
* установлен Docker и Docker Compose
* установлен Go версии 1.20 или выше
* порт `8080` свободен
* порт `8084` свободен

## Структура проекта
* `cmd/threat-monitoring/main.go` — точка входа в приложение
* `internal/api/server.go` — настройка HTTP-сервера и маршрутов
* `internal/app/handler/handler.go` — обработка HTTP-запросов
* `internal/app/repository/database.go` — подключение к PostgreSQL
* `internal/app/repository/minio.go` — работа с MinIO
* `internal/app/repository/models.go` — описание моделей данных
* `internal/app/repository/repository.go` — методы доступа к данным
* `internal/app/pkg/middlewares.go` — middleware для приложения
* `internal/app/pkg/metrics.go` — сбор метрик Prometheus

## Docker Compose
В каталоге `backend/compose` находятся настройки Docker Compose для:
* PostgreSQL
* MinIO
* Adminer

Запускайте контейнеры из этой папки.

## Технологии и документации
* [Go](https://goru.dev/doc)
* [Gin](https://gin-gonic.com/ru/docs/)
* [PostgreSQL]()
* [MinIO](https://docs.min.io/aistor/)
* [Docker Compose](https://docs.docker.com/)
* [Redis](https://redis-docs.ru/) (JWT токены)
* [Prometheus](https://prometheus.io/docs/introduction/overview/)
* [Grafana](https://grafana.com/docs/)

## Параметры для Adminer
Используйте следующие данные для подключения к базе данных:
* Сервер: `threat-monitoring-db`
* Пользователь: `postgres`
* Пароль: `postgres`
* База: `threat-monitoring`
