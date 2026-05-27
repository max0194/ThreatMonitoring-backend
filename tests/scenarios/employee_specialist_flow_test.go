package scenarios

import (
	"bytes"
	"encoding/json"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"testing"

	"threat-monitoring/internal/app/repository"
	"threat-monitoring/tests/helpers"

	"github.com/stretchr/testify/assert"
)

func TestEmployeeSpecialistFlow(t *testing.T) {
	router, db, redis := helpers.SetupIntegrationRouter()

	helpers.CleanupDB(db)

	employee := repository.User{
		Email:    "employee@company.com",
		Password: "12345678",
		FullName: "Employee",
		Phone:    "+79999999999",
		UserType: "employee",
	}

	specialist := repository.User{
		Email:    "specialist@company.com",
		Password: "12345678",
		FullName: "Specialist",
		Phone:    "+79999999998",
		UserType: "specialist",
	}

	db.Create(&employee)
	db.Create(&specialist)

	category := repository.Category{
		Name: "Вирусы",
	}

	db.Create(&category)

	threatType := repository.ThreatType{
		CategoryID: category.ID,
		Name:       "Троян",
	}

	db.Create(&threatType)

	requestBody := map[string]interface{}{
		"title":          "Поймал троян",
		"description":    "Что делать",
		"threat_type_id": threatType.ID,
	}

	requestJson, _ := json.Marshal(requestBody)

	createReq, _ := http.NewRequest(
		http.MethodPost,
		"/api/requests",
		bytes.NewBuffer(requestJson),
	)

	createReq.Header.Set("Content-Type", "application/json")

	autherror1 := helpers.AuthorizeRequest(
		createReq,
		redis,
		employee.ID,
		employee.UserType,
		employee.FullName,
	)

	assert.NoError(t, autherror1)

	createRR := httptest.NewRecorder()

	router.ServeHTTP(createRR, createReq)

	assert.Equal(t, http.StatusCreated, createRR.Code)

	var createdRequest repository.Request

	db.Last(&createdRequest)

	factBody := &bytes.Buffer{}
	writer := multipart.NewWriter(factBody)

	_ = writer.WriteField("title", "Обнаружен файл")
	_ = writer.WriteField("description", "Подозрительный exe")

	part, _ := writer.CreateFormFile(
		"screenshot",
		"virus.png",
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

	factReq, _ := http.NewRequest(
		http.MethodPost,
		fmt.Sprintf(
			"/api/requests/%d/facts",
			createdRequest.ID,
		),
		factBody,
	)

	factReq.Header.Set(
		"Content-Type",
		writer.FormDataContentType(),
	)

	autherrorFact := helpers.AuthorizeRequest(
		factReq,
		redis,
		employee.ID,
		employee.UserType,
		employee.FullName,
	)

	assert.NoError(t, autherrorFact)

	factRR := httptest.NewRecorder()

	router.ServeHTTP(factRR, factReq)

	assert.Equal(t, http.StatusCreated, factRR.Code)

	var fact repository.Fact

	db.First(&fact)

	assert.Equal(t, createdRequest.ID, fact.RequestID)
	assert.Equal(t, "Обнаружен файл", fact.Title)

	submitReq, _ := http.NewRequest(
		http.MethodPut,
		"/api/requests/1/submit",
		nil,
	)

	autherror2 := helpers.AuthorizeRequest(
		submitReq,
		redis,
		specialist.ID,
		specialist.UserType,
		specialist.FullName,
	)

	assert.NoError(t, autherror2)

	submitRR := httptest.NewRecorder()

	router.ServeHTTP(submitRR, submitReq)

	assert.Equal(t, http.StatusOK, submitRR.Code)

	completeReq, _ := http.NewRequest(
		http.MethodPut,
		"/api/requests/1/complete",
		nil,
	)

	autherror3 := helpers.AuthorizeRequest(
		completeReq,
		redis,
		specialist.ID,
		specialist.UserType,
		specialist.FullName,
	)

	assert.NoError(t, autherror3)

	completeRR := httptest.NewRecorder()

	router.ServeHTTP(completeRR, completeReq)

	assert.Equal(t, http.StatusOK, completeRR.Code)
}
