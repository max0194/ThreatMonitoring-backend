package unit

import (
	"bytes"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"testing"
	"threat-monitoring/internal/app/repository"
	"threat-monitoring/tests/helpers"

	"github.com/stretchr/testify/assert"
)

func TestCreateFactSuccess(t *testing.T) {
	router, db, redis := helpers.SetupTestRouter()

	helpers.CleanupDB(db)

	user := repository.User{
		Email:    "employee@company.com",
		Password: "12345678",
		FullName: "Сотрудник",
		Phone:    "+79999999999",
		UserType: "employee",
	}

	db.Create(&user)

	category := repository.Category{
		Name: "Вирусы",
	}

	db.Create(&category)

	threatType := repository.ThreatType{
		CategoryID: category.ID,
		Name:       "Троян",
	}

	db.Create(&threatType)

	request := repository.Request{
		Title:        "Заявка 1",
		Description:  "Описание 1",
		ThreatTypeID: threatType.ID,
		CreatorID:    user.ID,
		Status:       "draft",
	}

	db.Create(&request)

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	_ = writer.WriteField("title", "Факт")
	_ = writer.WriteField("description", "Описание")

	part, _ := writer.CreateFormFile(
		"screenshot",
		"screen.png",
	)

	data := []byte("fake image")

	_, err := part.Write(data)
	if err != nil {
		panic(err)
	}

	errorWriter := writer.Close()

	if errorWriter != nil {
		panic(errorWriter)
	}

	req, _ := http.NewRequest(
		http.MethodPost,
		fmt.Sprintf("/api/requests/%d/facts", request.ID),
		body,
	)

	req.Header.Set(
		"Content-Type",
		writer.FormDataContentType(),
	)

	authErr := helpers.AuthorizeRequest(
		req,
		redis,
		user.ID,
		user.UserType,
		user.FullName,
	)

	assert.NoError(t, authErr)

	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusCreated, rr.Code)

	var fact repository.Fact

	db.First(&fact)

	assert.Equal(t, "Факт", fact.Title)
	assert.Equal(t, request.ID, fact.RequestID)
}
