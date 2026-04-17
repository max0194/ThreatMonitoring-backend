package repository

type Worker struct {
	ID         int
	FullName   string
	Phone      string
	Post       string
	Department string
	Email      string
	Password   string
}

type Specialist struct {
	ID       int
	Phone    string
	Email    string
	Password string
}

type Category struct {
	ID       int
	Name     string
	Priority int
}

type ThreatType struct {
	ID         int
	CategoryID int
	Name       string
}

type Request struct {
	ID          int
	TypeID      int
	WorkerID    int
	Title       string
	Description string
	Category    string
	ThreatType  string
	Status      string
	CreatedAt   string
}

type Fact struct {
	ID            int
	RequestID     int
	Title         string
	Description   string
	CreatedAt     string
	ScreenshotURL string
}

type Repository struct {
	Workers     []Worker
	Categories  []Category
	ThreatTypes []ThreatType
	Requests    []Request
	Facts       []Fact
	Specialists []Specialist
}

func NewRepository() (*Repository, error) {

	repo := &Repository{
		Categories: []Category{
			{ID: 1, Name: "Вредоносное ПО", Priority: 1},
			{ID: 2, Name: "Фишинг", Priority: 2},
			{ID: 3, Name: "DDoS атаки", Priority: 1},
		},
		ThreatTypes: []ThreatType{
			{ID: 1, CategoryID: 1, Name: "Троян"},
			{ID: 2, CategoryID: 1, Name: "Вирус-вымогатель"},
			{ID: 3, CategoryID: 2, Name: "Email фишинг"},
			{ID: 4, CategoryID: 2, Name: "SMS фишинг"},
			{ID: 5, CategoryID: 3, Name: "HTTP Flood"},
		},
		Requests: []Request{
			{ID: 1, Title: "Проблема в ПО", Description: "Описание угрозы", Category: "Артефакты", ThreatType: "Полосы в ПО", Status: "В работе", CreatedAt: "2026-02-20 12:00", TypeID: 1, WorkerID: 1},
		},
		Facts: []Fact{
			{ID: 1, RequestID: 1, Title: "Первое появление", Description: "Заметил при открытии браузера", CreatedAt: "2024-05-20 12:00", ScreenshotURL: "http://localhost:9001/api/v1/download-shared-object/aHR0cDovLzEyNy4wLjAuMTo5MDAwL3RocmVhdC1yZXBvcnRzLzIwMjYtMDItMjRfMDgtNDUtMjAucG5nP1gtQW16LUFsZ29yaXRobT1BV1M0LUhNQUMtU0hBMjU2JlgtQW16LUNyZWRlbnRpYWw9WDBZWEFTM0Y2WDJPTDBQSlkxNU0lMkYyMDI2MDIyNiUyRnVzLWVhc3QtMSUyRnMzJTJGYXdzNF9yZXF1ZXN0JlgtQW16LURhdGU9MjAyNjAyMjZUMDUyNTExWiZYLUFtei1FeHBpcmVzPTQzMjAwJlgtQW16LVNlY3VyaXR5LVRva2VuPWV5SmhiR2NpT2lKSVV6VXhNaUlzSW5SNWNDSTZJa3BYVkNKOS5leUpoWTJObGMzTkxaWGtpT2lKWU1GbFlRVk16UmpaWU1rOU1NRkJLV1RFMVRTSXNJbVY0Y0NJNk1UYzNNakV5Tmpjd05Dd2ljR0Z5Wlc1MElqb2liV2x1YVc5aFpHMXBiaUo5LmhCWnZVLWxuaWZ5c09pWkV6VGlTUnRFLXU4aUVhY1R6WWlYMmcxaXVzX1ZCdmJfUUN6MXRocGxxb241MDA1eTd4RVdfWi1YSzVCNnNaMFFWNDc4eXlRJlgtQW16LVNpZ25lZEhlYWRlcnM9aG9zdCZ2ZXJzaW9uSWQ9bnVsbCZYLUFtei1TaWduYXR1cmU9NTFlMTg5MGFmYTZlNTM4Nzg5MWE1YjQ4ZjNiMzdjZjIzZmY0ZGIzN2NlYWJjOThmOGVlNGNkZjdlYzQ3YzU1ZQ"},
			{ID: 2, RequestID: 1, Title: "Повторный инцидент", Description: "Появилось снова через час", CreatedAt: "2024-05-20 13:00", ScreenshotURL: "http://localhost:9001/api/v1/download-shared-object/aHR0cDovLzEyNy4wLjAuMTo5MDAwL3RocmVhdC1yZXBvcnRzLzIwMjYtMDItMjRfMDgtNDUtMjAucG5nP1gtQW16LUFsZ29yaXRobT1BV1M0LUhNQUMtU0hBMjU2JlgtQW16LUNyZWRlbnRpYWw9WDBZWEFTM0Y2WDJPTDBQSlkxNU0lMkYyMDI2MDIyNiUyRnVzLWVhc3QtMSUyRnMzJTJGYXdzNF9yZXF1ZXN0JlgtQW16LURhdGU9MjAyNjAyMjZUMDUyNTExWiZYLUFtei1FeHBpcmVzPTQzMjAwJlgtQW16LVNlY3VyaXR5LVRva2VuPWV5SmhiR2NpT2lKSVV6VXhNaUlzSW5SNWNDSTZJa3BYVkNKOS5leUpoWTJObGMzTkxaWGtpT2lKWU1GbFlRVk16UmpaWU1rOU1NRkJLV1RFMVRTSXNJbVY0Y0NJNk1UYzNNakV5Tmpjd05Dd2ljR0Z5Wlc1MElqb2liV2x1YVc5aFpHMXBiaUo5LmhCWnZVLWxuaWZ5c09pWkV6VGlTUnRFLXU4aUVhY1R6WWlYMmcxaXVzX1ZCdmJfUUN6MXRocGxxb241MDA1eTd4RVdfWi1YSzVCNnNaMFFWNDc4eXlRJlgtQW16LVNpZ25lZEhlYWRlcnM9aG9zdCZ2ZXJzaW9uSWQ9bnVsbCZYLUFtei1TaWduYXR1cmU9NTFlMTg5MGFmYTZlNTM4Nzg5MWE1YjQ4ZjNiMzdjZjIzZmY0ZGIzN2NlYWJjOThmOGVlNGNkZjdlYzQ3YzU1ZQ"},
		},
		Workers: []Worker{
			{ID: 1, FullName: "Иванов Иван", Phone: "+79001234567", Post: "Разработчик", Department: "IT", Email: "ivanov@company.com", Password: "pass123"},
			{ID: 2, FullName: "Петров Петр", Phone: "+79007654321", Post: "Аналитик", Department: "Безопасность", Email: "petrov@company.com", Password: "pass456"},
		},
		Specialists: []Specialist{
			{ID: 1, Phone: "+79001112233", Email: "spec1@company.com", Password: "specpass1"},
			{ID: 2, Phone: "+79004445566", Email: "spec2@company.com", Password: "specpass2"},
		},
	}
	return repo, nil
}
