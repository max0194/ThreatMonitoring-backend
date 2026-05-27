package unit

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"

	"threat-monitoring/internal/app/repository"
	"threat-monitoring/tests/helpers"
)

func TestCreateRequestSuccess(t *testing.T) {
	router, db, redis := helpers.SetupTestRouter()

	helpers.CleanupDB(db)

	user := repository.User{
		Email:    "employee@company.com",
		Password: "12345678",
		FullName: "Сотрудник",
		Phone:    "+79999999999",
		UserType: "employee",
	}

	err := db.Create(&user).Error
	assert.NoError(t, err)

	category := repository.Category{
		Name: "Вирусы",
	}

	db.Create(&category)

	threatType := repository.ThreatType{
		CategoryID: category.ID,
		Name:       "Троян",
	}

	err = db.Create(&threatType).Error
	assert.NoError(t, err)

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

	autherror := helpers.AuthorizeRequest(
		req,
		redis,
		user.ID,
		user.UserType,
		user.FullName,
	)

	assert.NoError(t, autherror)

	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusCreated, rr.Code)

	var request repository.Request

	err = db.First(&request).Error

	assert.NoError(t, err)

	assert.Equal(t, "Поймал троян", request.Title)
	assert.Equal(t, "draft", request.Status)
	assert.Equal(t, user.ID, request.CreatorID)
}

func TestCreateRequestWithoutTitle(t *testing.T) {
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

	body := map[string]interface{}{
		"description":    "Обнаружена угроза",
		"threat_type_id": threatType.ID,
	}

	jsonBody, _ := json.Marshal(body)

	req, _ := http.NewRequest(
		http.MethodPost,
		"/api/requests",
		bytes.NewBuffer(jsonBody),
	)

	req.Header.Set("Content-Type", "application/json")

	autherror := helpers.AuthorizeRequest(
		req,
		redis,
		user.ID,
		user.UserType,
		user.FullName,
	)

	assert.NoError(t, autherror)

	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)

	var count int64

	db.Model(&repository.Request{}).Count(&count)

	assert.Equal(t, int64(0), count)
}

func TestGetRequestsForEmployee(t *testing.T) {
	router, db, redis := helpers.SetupTestRouter()

	helpers.CleanupDB(db)

	user := repository.User{
		Email:    "employee@company.com",
		Password: "12345678",
		FullName: "Employee User",
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

	request1 := repository.Request{
		Title:        "Заявка 1",
		Description:  "Описание 1",
		ThreatTypeID: threatType.ID,
		CreatorID:    user.ID,
		Status:       "draft",
	}

	fact1 := repository.Fact{
		Title:       "Факт 1",
		Description: "Описание 1",
		RequestID:   request1.ID,
	}

	request2 := repository.Request{
		Title:        "Заявка 2",
		Description:  "Описание 2",
		ThreatTypeID: threatType.ID,
		CreatorID:    user.ID,
		Status:       "awaiting",
	}

	fact2 := repository.Fact{
		Title:       "Факт 2",
		Description: "Описание 2",
		RequestID:   request2.ID,
	}

	db.Create(&request1)
	db.Create(&fact1)
	db.Create(&request2)
	db.Create(&fact2)

	req, _ := http.NewRequest(
		http.MethodGet,
		"/api/requests",
		nil,
	)

	autherror := helpers.AuthorizeRequest(
		req,
		redis,
		user.ID,
		user.UserType,
		user.FullName,
	)

	assert.NoError(t, autherror)

	rr := httptest.NewRecorder()

	router.ServeHTTP(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
}

func TestSubmitRequestBySpecialist(t *testing.T) {
	router, db, redis := helpers.SetupTestRouter()

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

	request := repository.Request{
		Title:        "Ошибка 1",
		Description:  "Описание 1",
		ThreatTypeID: threatType.ID,
		CreatorID:    employee.ID,
		Status:       "awaiting",
	}

	fact := repository.Fact{
		Title:       "Факт 1",
		Description: "Описание 1",
		RequestID:   request.ID,
	}

	db.Create(&fact)
	db.Create(&request)

	req, _ := http.NewRequest(
		http.MethodPut,
		fmt.Sprintf("/api/requests/%d/submit", request.ID),
		nil,
	)

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

	assert.Equal(t, http.StatusOK, rr.Code)

	var updated repository.Request

	db.First(&updated, request.ID)

	assert.Equal(t, "taken", updated.Status)
}
