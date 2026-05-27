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

func TestRegisterAndLogin(t *testing.T) {
	router, db, redis := helpers.SetupIntegrationRouter()

	helpers.CleanupDB(db)

	specialist := repository.User{
		Email:    "specialist@company.com",
		Password: "12345678",
		FullName: "Специалист",
		Phone:    "+79999999998",
		UserType: "specialist",
	}

	err := db.Create(&specialist).Error
	assert.NoError(t, err)

	registerBody := map[string]interface{}{
		"email":     "newuser@company.com",
		"password":  "12345678",
		"full_name": "Сотрудник",
		"phone":     "+79999999999",
		"user_type": "employee",
	}

	jsonBody, _ := json.Marshal(registerBody)

	req, _ := http.NewRequest(
		http.MethodPost,
		"/api/auth/register",
		bytes.NewBuffer(jsonBody),
	)

	req.Header.Set("Content-Type", "application/json")

	autherror := helpers.AuthorizeRequest(
		req,
		redis,
		specialist.ID,
		specialist.UserType,
		specialist.FullName,
	)

	assert.NoError(t, autherror)

	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusCreated, rr.Code)

	loginBody := map[string]interface{}{
		"email":    "newuser@company.com",
		"password": "12345678",
	}

	loginJson, _ := json.Marshal(loginBody)

	loginReq, _ := http.NewRequest(
		http.MethodPost,
		"/api/auth/login",
		bytes.NewBuffer(loginJson),
	)

	loginReq.Header.Set("Content-Type", "application/json")

	loginRR := httptest.NewRecorder()

	router.ServeHTTP(loginRR, loginReq)

	assert.Equal(t, http.StatusOK, loginRR.Code)
}
