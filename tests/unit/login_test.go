package unit

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

func TestLoginSuccess(t *testing.T) {
	router, db, _ := helpers.SetupTestRouter()

	helpers.CleanupDB(db)

	user := repository.User{
		Email:    "employeelogin1@company.com",
		Password: "12345678",
		FullName: "Сотрудник",
		Phone:    "+79999999999",
		UserType: "employee",
	}

	err := db.Create(&user).Error
	assert.NoError(t, err)

	body := map[string]interface{}{
		"email":    "employeelogin1@company.com",
		"password": "12345678",
	}

	jsonBody, _ := json.Marshal(body)

	req, _ := http.NewRequest(
		http.MethodPost,
		"/api/auth/login",
		bytes.NewBuffer(jsonBody),
	)

	assert.NoError(t, err)

	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
}

func TestLoginInvalidEmail(t *testing.T) {
	router, db, _ := helpers.SetupTestRouter()

	helpers.CleanupDB(db)

	user := repository.User{
		Email:    "employeelogin2@company.com",
		Password: "12345678",
		FullName: "Сотрудник",
		Phone:    "+79999999999",
		UserType: "employee",
	}

	err := db.Create(&user).Error
	assert.NoError(t, err)

	body := map[string]interface{}{
		"email":    "employeewrong@company.com",
		"password": "12345678",
	}

	jsonBody, _ := json.Marshal(body)

	req, _ := http.NewRequest(
		http.MethodPost,
		"/api/auth/login",
		bytes.NewBuffer(jsonBody),
	)

	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestLoginWrongPassword(t *testing.T) {
	router, db, _ := helpers.SetupTestRouter()

	helpers.CleanupDB(db)

	user := repository.User{
		Email:    "employeelogin3@company.com",
		Password: "12345678",
		FullName: "Сотрудник",
		Phone:    "+79999999999",
		UserType: "employee",
	}

	err := db.Create(&user).Error
	assert.NoError(t, err)

	body := map[string]interface{}{
		"email":    "employee@company.com",
		"password": "",
	}

	jsonBody, _ := json.Marshal(body)

	req, _ := http.NewRequest(
		http.MethodPost,
		"/api/auth/login",
		bytes.NewBuffer(jsonBody),
	)

	req.Header.Set("Content-Type", "application/json")

	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}
