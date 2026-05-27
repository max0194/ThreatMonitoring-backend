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

func TestRegisterSuccess(t *testing.T) {
	router, db, redis := helpers.SetupTestRouter()

	helpers.CleanupDB(db)

	specialist := repository.User{
		Email:    "specialist@company.com",
		Password: "12345678",
		FullName: "Specialist",
		Phone:    "+79999999998",
		UserType: "specialist",
	}

	err := db.Create(&specialist).Error
	assert.NoError(t, err)

	body := map[string]interface{}{
		"email":     "employee1@company.com",
		"password":  "12345678",
		"full_name": "Сотрудник1",
		"phone":     "+79999999999",
		"user_type": "employee",
	}

	jsonBody, _ := json.Marshal(body)

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
}

func TestRegisterWrongDomain(t *testing.T) {
	router, db, redis := helpers.SetupTestRouter()

	helpers.CleanupDB(db)

	specialist := repository.User{
		Email:    "specialist@company.com",
		Password: "12345678",
		FullName: "Specialist",
		Phone:    "+79999999998",
		UserType: "specialist",
	}

	err := db.Create(&specialist).Error
	assert.NoError(t, err)

	body := map[string]interface{}{
		"email":     "employee2@mail.ru",
		"password":  "12345678",
		"full_name": "Сотрудник2",
		"phone":     "+79999999999",
		"user_type": "employee",
	}

	jsonBody, _ := json.Marshal(body)

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

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

func TestRegisterWrongPhone(t *testing.T) {
	router, db, redis := helpers.SetupTestRouter()

	helpers.CleanupDB(db)

	specialist := repository.User{
		Email:    "specialist@company.com",
		Password: "12345678",
		FullName: "Specialist",
		Phone:    "+79999999998",
		UserType: "specialist",
	}

	err := db.Create(&specialist).Error
	assert.NoError(t, err)

	body := map[string]interface{}{
		"email":     "employee3@company.com",
		"password":  "12345678",
		"full_name": "Сотрудник3",
		"phone":     "12345",
		"user_type": "employee",
	}

	jsonBody, _ := json.Marshal(body)

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

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}
