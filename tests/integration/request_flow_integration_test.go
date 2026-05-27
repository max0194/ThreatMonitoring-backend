package integration

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"threat-monitoring/internal/app/repository"
	"threat-monitoring/tests/helpers"

	"github.com/stretchr/testify/assert"
)

func TestCreateAndGetRequests(t *testing.T) {
	router, db, redis := helpers.SetupIntegrationRouter()

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

	body := map[string]interface{}{
		"title":          "Поймал троян",
		"description":    "Теперь что-то не так с компьютером",
		"threat_type_id": threatType.ID,
	}

	jsonBody, _ := json.Marshal(body)

	req, _ := http.NewRequest(
		http.MethodPost,
		"/api/requests",
		bytes.NewBuffer(jsonBody),
	)

	req.Header.Set("Content-Type", "application/json")

	autherror1 := helpers.AuthorizeRequest(
		req,
		redis,
		user.ID,
		user.UserType,
		user.FullName,
	)

	assert.NoError(t, autherror1)

	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusCreated, rr.Code)

	getReq, _ := http.NewRequest(
		http.MethodGet,
		"/api/requests",
		nil,
	)

	autherror2 := helpers.AuthorizeRequest(
		getReq,
		redis,
		user.ID,
		user.UserType,
		user.FullName,
	)

	assert.NoError(t, autherror2)

	getRR := httptest.NewRecorder()

	router.ServeHTTP(getRR, getReq)

	assert.Equal(t, http.StatusOK, getRR.Code)
}
