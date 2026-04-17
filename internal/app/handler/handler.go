package handler

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"threat-monitoring/internal/app/repository"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

const (
	apiUserID    = 1
	apiUserEmail = "api_user@example.com"
	apiUserName  = "API Пользователь"
	apiUserPhone = "+79000000000"
	apiUserType  = "employee"
)

var (
	apiUser     *repository.User
	apiUserOnce sync.Once
)

type Handler struct {
	Repository *repository.Repository
}

func NewHandler(r *repository.Repository) *Handler {
	return &Handler{
		Repository: r,
	}
}

func (h *Handler) getCurrentUserID(ctx *gin.Context) (int, error) {
	userIDStr, err := ctx.Cookie("user_id")
	if err != nil {
		return 0, err
	}
	userID, err := strconv.Atoi(userIDStr)
	if err != nil {
		return 0, err
	}
	return userID, nil
}

func (h *Handler) getCurrentUserType(ctx *gin.Context) (string, error) {
	userType, err := ctx.Cookie("user_type")
	if err != nil {
		return "", err
	}
	return userType, nil
}

func getAPIUser() *repository.User {
	apiUserOnce.Do(func() {
		apiUser = &repository.User{
			ID:       apiUserID,
			Email:    apiUserEmail,
			FullName: apiUserName,
			Phone:    apiUserPhone,
			UserType: apiUserType,
		}
	})
	return apiUser
}

func (h *Handler) writeJSONError(ctx *gin.Context, status int, message string) {
	ctx.JSON(status, gin.H{"status": "error", "message": message})
}

func (h *Handler) parseDateParam(value string) (*time.Time, error) {
	if value == "" {
		return nil, nil
	}
	t, err := time.Parse("2006-01-02", value)
	if err != nil {
		return nil, err
	}
	return &t, nil
}

func (h *Handler) GetEmployeeIndex(ctx *gin.Context) {
	userIDStr, err := ctx.Cookie("user_id")
	if err != nil {
		ctx.Redirect(http.StatusFound, "/login")
		return
	}

	userID, _ := strconv.Atoi(userIDStr)

	categories, _ := h.Repository.GetAllCategories()
	threatTypes, _ := h.Repository.GetAllThreatTypes()

	userName, _ := ctx.Cookie("user_name")

	ctx.HTML(http.StatusOK, "employee_index.html", gin.H{
		"categories":  categories,
		"threatTypes": threatTypes,
		"userID":      userID,
		"userName":    userName,
		"userType":    "employee",
	})
}

func (h *Handler) GetEmployeeRequests(ctx *gin.Context) {
	userIDStr, err := ctx.Cookie("user_id")
	if err != nil {
		ctx.Redirect(http.StatusFound, "/login")
		return
	}

	userID, _ := strconv.Atoi(userIDStr)

	allRequests, _ := h.Repository.GetAllRequests()
	var userRequests []repository.Request
	for _, req := range allRequests {
		if req.CreatorID == userID {
			userRequests = append(userRequests, req)
		}
	}

	q := strings.TrimSpace(ctx.Query("q"))

	if q != "" {
		var filtered []repository.Request
		words := strings.Fields(q)
		for _, req := range userRequests {
			desc := strings.ToLower(req.Description)
			matched := false
			for _, w := range words {
				w = strings.ToLower(w)
				if w == "" {
					continue
				}
				if strings.Contains(desc, w) {
					matched = true
					break
				}
			}
			if matched {
				filtered = append(filtered, req)
			}
		}
		userRequests = filtered
	}

	userName, _ := ctx.Cookie("user_name")

	ctx.HTML(http.StatusOK, "employee_requests.html", gin.H{
		"requests": userRequests,
		"userName": userName,
		"userType": "employee",
		"query":    q,
	})
}

func (h *Handler) GetSpecialistIndex(ctx *gin.Context) {
	_, err := ctx.Cookie("user_id")
	if err != nil {
		ctx.Redirect(http.StatusFound, "/login")
		return
	}

	requests, _ := h.Repository.GetAllRequests()

	q := strings.TrimSpace(ctx.Query("q"))
	if q != "" {
		var filtered []repository.Request
		words := strings.Fields(q)
		for _, req := range requests {
			desc := strings.ToLower(req.Description)
			matched := false
			for _, w := range words {
				w = strings.ToLower(w)
				if w == "" {
					continue
				}
				if strings.Contains(desc, w) {
					matched = true
					break
				}
			}
			if matched {
				filtered = append(filtered, req)
			}
		}
		requests = filtered
	}

	workerMap := make(map[int]repository.User)
	for _, request := range requests {
		if request.Creator != nil {
			workerMap[request.Creator.ID] = *request.Creator
		}
	}

	userName, _ := ctx.Cookie("user_name")

	ctx.HTML(http.StatusOK, "specialist_index.html", gin.H{
		"requests":  requests,
		"workerMap": workerMap,
		"userName":  userName,
		"userType":  "specialist",
		"query":     q,
	})
}

func (h *Handler) GetRequest(ctx *gin.Context) {
	_, err := ctx.Cookie("user_id")
	if err != nil {
		ctx.Redirect(http.StatusFound, "/login")
		return
	}

	idStr := ctx.Param("id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		logrus.Error(err)
		ctx.HTML(http.StatusBadRequest, "error.html", gin.H{"error": "Неверный ID заявки"})
		return
	}
	request, err := h.Repository.GetRequestByID(id)
	if err != nil || request == nil {
		ctx.HTML(http.StatusNotFound, "error.html", gin.H{"error": "Заявка не найдена"})
		return
	}

	facts, _ := h.Repository.GetFactsByRequestID(id)
	logrus.Info("Загружена заявка ID=", id, " с ", len(facts), " фактами")
	if request.RequestFacts != nil {
		logrus.Info("RequestFacts в request: ", len(request.RequestFacts), " фактов")
	}

	category := (*repository.Category)(nil)
	if request.ThreatType != nil && request.ThreatType.Category != nil {
		category = request.ThreatType.Category
	}

	userName, _ := ctx.Cookie("user_name")
	userType, _ := ctx.Cookie("user_type")

	ctx.HTML(http.StatusOK, "request.html", gin.H{
		"request":    request,
		"worker":     request.Creator,
		"threatType": request.ThreatType,
		"facts":      facts,
		"category":   category,
		"userName":   userName,
		"userType":   userType,
	})
}

func (h *Handler) GetThreat(ctx *gin.Context) {
	idStr := ctx.Param("id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		logrus.Error(err)
		ctx.HTML(http.StatusBadRequest, "error.html", gin.H{"error": "Неверный ID угрозы"})
		return
	}

	threatType, err := h.Repository.GetThreatTypeByID(id)
	if err != nil || threatType == nil {
		ctx.HTML(http.StatusNotFound, "error.html", gin.H{"error": "Угроза не найдена"})
		return
	}

	category := (*repository.Category)(nil)
	if threatType.Category != nil {
		category = threatType.Category
	}

	ctx.HTML(http.StatusOK, "threat.html", gin.H{
		"threatType": threatType,
		"category":   category,
	})
}

func (h *Handler) GetLogin(ctx *gin.Context) {
	ctx.HTML(http.StatusOK, "login.html", gin.H{})
}

func (h *Handler) Logout(ctx *gin.Context) {
	ctx.SetCookie("user_id", "", -1, "/", "", false, true)
	ctx.SetCookie("user_type", "", -1, "/", "", false, true)
	ctx.SetCookie("user_name", "", -1, "/", "", false, true)

	ctx.Redirect(http.StatusFound, "/login")
}

func (h *Handler) HandleLogin(ctx *gin.Context) {
	userType := ctx.PostForm("user_type")
	email := ctx.PostForm("email")
	password := ctx.PostForm("password")

	if userType != "employee" && userType != "specialist" {
		ctx.HTML(http.StatusOK, "login.html", gin.H{"error": "Неверный тип пользователя"})
		return
	}

	user, err := h.Repository.GetUserByEmail(email)
	if err != nil || user == nil || user.Password != password {
		ctx.HTML(http.StatusOK, "login.html", gin.H{"error": "Неверный email или пароль"})
		return
	}

	if user.UserType != userType {
		ctx.HTML(http.StatusOK, "login.html", gin.H{"error": "Неверный тип пользователя"})
		return
	}

	ctx.SetCookie("user_id", strconv.Itoa(user.ID), 86400, "/", "", false, true)
	ctx.SetCookie("user_type", user.UserType, 86400, "/", "", false, true)
	ctx.SetCookie("user_name", user.FullName, 86400, "/", "", false, true)

	if userType == "employee" {
		ctx.Redirect(http.StatusFound, "/employee")
	} else {
		ctx.Redirect(http.StatusFound, "/specialist")
	}
}

func (h *Handler) LoginAPI(ctx *gin.Context) {
	var body struct {
		Email    string `json:"email" binding:"required,email"`
		Password string `json:"password" binding:"required"`
		UserType string `json:"user_type" binding:"required,oneof=employee specialist"`
	}
	if err := ctx.ShouldBindJSON(&body); err != nil {
		h.writeJSONError(ctx, http.StatusBadRequest, "Неверные данные для входа")
		return
	}

	user, err := h.Repository.GetUserByEmail(body.Email)
	if err != nil || user == nil || user.Password != body.Password {
		h.writeJSONError(ctx, http.StatusUnauthorized, "Неверный email или пароль")
		return
	}
	if user.UserType != body.UserType {
		h.writeJSONError(ctx, http.StatusForbidden, "Неверный тип пользователя")
		return
	}

	ctx.SetCookie("user_id", strconv.Itoa(user.ID), 86400, "/", "", false, true)
	ctx.SetCookie("user_type", user.UserType, 86400, "/", "", false, true)
	ctx.SetCookie("user_name", user.FullName, 86400, "/", "", false, true)
	ctx.JSON(http.StatusOK, gin.H{"status": "ok", "user": user})
}

func (h *Handler) RegisterAPI(ctx *gin.Context) {
	var body struct {
		Email    string `json:"email" binding:"required,email"`
		Password string `json:"password" binding:"required"`
		FullName string `json:"full_name" binding:"required"`
		Phone    string `json:"phone" binding:"required"`
		UserType string `json:"user_type" binding:"required,oneof=employee specialist"`
	}
	if err := ctx.ShouldBindJSON(&body); err != nil {
		h.writeJSONError(ctx, http.StatusBadRequest, "Неверные данные для регистрации")
		return
	}

	existingUser, err := h.Repository.GetUserByEmail(body.Email)
	if err != nil {
		h.writeJSONError(ctx, http.StatusInternalServerError, "Ошибка при проверке пользователя")
		return
	}
	if existingUser != nil {
		h.writeJSONError(ctx, http.StatusConflict, "Пользователь с таким email уже существует")
		return
	}

	user := &repository.User{
		Email:    strings.TrimSpace(body.Email),
		Password: strings.TrimSpace(body.Password),
		FullName: strings.TrimSpace(body.FullName),
		Phone:    strings.TrimSpace(body.Phone),
		UserType: body.UserType,
	}

	if err := h.Repository.CreateUser(user); err != nil {
		h.writeJSONError(ctx, http.StatusInternalServerError, "Ошибка при создании пользователя")
		return
	}

	ctx.JSON(http.StatusCreated, gin.H{"status": "ok", "user": user})
}

func (h *Handler) LogoutAPI(ctx *gin.Context) {
	ctx.SetCookie("user_id", "", -1, "/", "", false, true)
	ctx.SetCookie("user_type", "", -1, "/", "", false, true)
	ctx.SetCookie("user_name", "", -1, "/", "", false, true)
	ctx.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func (h *Handler) CreateRequestAPI(ctx *gin.Context) {
	user := getAPIUser()

	var body struct {
		Title        string `json:"title" binding:"required"`
		Description  string `json:"description" binding:"required"`
		ThreatTypeID int    `json:"threat_type_id" binding:"required"`
	}
	if err := ctx.ShouldBindJSON(&body); err != nil {
		h.writeJSONError(ctx, http.StatusBadRequest, "Неверные данные для создания заявки")
		return
	}

	request := &repository.Request{
		Title:        strings.TrimSpace(body.Title),
		Description:  strings.TrimSpace(body.Description),
		ThreatTypeID: body.ThreatTypeID,
		CreatorID:    user.ID,
		Status:       "draft",
		CreatedAt:    time.Now(),
	}

	if err := h.Repository.CreateRequest(request); err != nil {
		h.writeJSONError(ctx, http.StatusInternalServerError, "Ошибка при создании заявки")
		return
	}

	ctx.JSON(http.StatusCreated, gin.H{"status": "ok", "request": request})
}

func (h *Handler) CreateRequest(ctx *gin.Context) {
	userIDStr, err := ctx.Cookie("user_id")
	if err != nil {
		ctx.HTML(http.StatusUnauthorized, "login.html", gin.H{"error": "Требуется вход"})
		return
	}
	creatorID, _ := strconv.Atoi(userIDStr)

	type RequestForm struct {
		Description  string `form:"description" binding:"required"`
		ThreatTypeID string `form:"threat_type" binding:"required"`
	}

	var form RequestForm
	if err := ctx.ShouldBind(&form); err != nil {
		logrus.Error("Ошибка при биндинге формы:", err)
		ctx.Redirect(http.StatusFound, "/employee?error=Error of form process")
		return
	}

	description := strings.TrimSpace(form.Description)
	threatTypeIDStr := strings.TrimSpace(form.ThreatTypeID)

	logrus.Info("Полученные данные формы - description: ", description, ", threat_type: ", threatTypeIDStr)

	if !isValidUTF8(description) {
		logrus.Info("Обнаружена неправильная кодировка, исправляем UTF-8")
		description = fixUTF8(description)
		logrus.Info("Успешно исправлено: ", description)
	}

	if description == "" {
		ctx.Redirect(http.StatusFound, "/employee?error=Description of request cannot be empty")
		return
	}

	if threatTypeIDStr == "" {
		ctx.Redirect(http.StatusFound, "/employee?error=Type of threat has not been choosen")
		return
	}

	threatTypeID, _ := strconv.Atoi(threatTypeIDStr)

	title := description
	if len(title) > 50 {
		title = title[:50] + "..."
	}

	if !isValidUTF8(title) {
		logrus.Info("Обнаружена неправильная кодировка в title, исправляем UTF-8")
		title = fixUTF8(title)
		logrus.Info("Title исправлено: ", title)
	}

	request := &repository.Request{
		Title:        title,
		Description:  description,
		ThreatTypeID: threatTypeID,
		CreatorID:    creatorID,
		Status:       "draft",
		CreatedAt:    time.Now(),
	}

	if err := h.Repository.CreateRequest(request); err != nil {
		logrus.Error("Ошибка при создании заявки:", err)
		ctx.Redirect(http.StatusFound, "/employee?error=Error while create request")
		return
	}

	ctx.Redirect(http.StatusFound, fmt.Sprintf("/request/%d", request.ID))
}

func (h *Handler) CreateFact(ctx *gin.Context) {
	_, err := ctx.Cookie("user_id")
	if err != nil {
		ctx.HTML(http.StatusUnauthorized, "login.html", gin.H{"error": "Нужен вход"})
		return
	}

	userType, err := ctx.Cookie("user_type")
	if err != nil || userType != "employee" {
		ctx.HTML(http.StatusForbidden, "error.html", gin.H{"error": "Недостаточно прав"})
		return
	}

	requestIDStr := strings.TrimSpace(ctx.PostForm("request_id"))
	title := strings.TrimSpace(ctx.PostForm("fact_title"))
	description := strings.TrimSpace(ctx.PostForm("fact_description"))

	if requestIDStr == "" {
		ctx.Redirect(http.StatusFound, "/employee?error=ID request not stated")
		return
	}

	requestID, _ := strconv.Atoi(requestIDStr)

	if title == "" {
		ctx.Redirect(http.StatusFound, "/employee?error=Title of fact cannot be empty")
		return
	}

	if description == "" {
		ctx.Redirect(http.StatusFound, "/employee?error=Desc of fact cannot be empty")
		return
	}

	file, header, err := ctx.Request.FormFile("screenshot")
	if err != nil {
		logrus.Error("Ошибка при загрузке файла:", err)
		ctx.Redirect(http.StatusFound, "/employee?error=Error while uploading")
		return
	}
	defer func() {
		if err := file.Close(); err != nil {
			logrus.Error("Ошибка при закрытии файла:", err)
		}
	}()

	objectName := repository.GenerateObjectName(header.Filename)

	screenshotURL, err := h.Repository.MinIOClient.UploadFile(ctx.Request.Context(), file, header, objectName)
	if err != nil {
		logrus.Error("Ошибка при загрузке файла в MinIO:", err)
		ctx.Redirect(http.StatusFound, "/employee?error=Error while uploading")
		return
	}

	fact := &repository.Fact{
		RequestID:     requestID,
		Title:         title,
		Description:   description,
		ScreenshotURL: screenshotURL,
	}

	logrus.Info("Создание факта: RequestID=", requestID, ", Title=", title)

	if err := h.Repository.CreateFact(fact); err != nil {
		logrus.Error("Ошибка при создании факта:", err)
		ctx.Redirect(http.StatusFound, "/employee?error=Error while creating a fact")
		return
	}

	referer := ctx.Request.Referer()
	if strings.Contains(referer, "/request/") {
		ctx.Redirect(http.StatusFound, "/request/"+strconv.Itoa(requestID))
	} else {
		ctx.Redirect(http.StatusFound, "/employee")
	}
}

func (h *Handler) DeleteRequest(ctx *gin.Context) {
	idStr := ctx.Param("id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		logrus.Error(err)
		ctx.HTML(http.StatusBadRequest, "error.html", gin.H{"error": "Неверный ID заявки"})
		return
	}

	if err := h.Repository.DeleteRequest(id); err != nil {
		ctx.HTML(http.StatusInternalServerError, "error.html", gin.H{"error": "Ошибка при удалении заявки"})
		return
	}

	ctx.Redirect(http.StatusFound, "/employee/requests")
}

func (h *Handler) UpdateRequestStatus(ctx *gin.Context) {
	userIDStr, err := ctx.Cookie("user_id")
	if err != nil {
		ctx.Redirect(http.StatusFound, "/login")
		return
	}

	userType, err := ctx.Cookie("user_type")
	if err != nil {
		ctx.Redirect(http.StatusFound, "/login")
		return
	}

	requestIDStr := ctx.Param("id")
	requestID, err := strconv.Atoi(requestIDStr)
	if err != nil {
		ctx.HTML(http.StatusBadRequest, "error.html", gin.H{"error": "Неверный ID заявки"})
		return
	}

	newStatus := ctx.PostForm("status")
	if newStatus == "" {
		ctx.HTML(http.StatusBadRequest, "error.html", gin.H{"error": "Не указан новый статус"})
		return
	}

	request, err := h.Repository.GetRequestByID(requestID)
	if err != nil {
		ctx.HTML(http.StatusInternalServerError, "error.html", gin.H{"error": "Ошибка при получении заявки"})
		return
	}

	switch userType {
	case "specialist":
		if (newStatus == "taken" && request.Status != "awaiting") ||
			(newStatus == "closed" && request.Status != "taken") {
			ctx.HTML(http.StatusForbidden, "error.html", gin.H{"error": "Недостаточно прав для изменения статуса"})
			return
		}
	case "employee":
		userID, _ := strconv.Atoi(userIDStr)
		if newStatus != "closed" || request.CreatorID != userID {
			ctx.HTML(http.StatusForbidden, "error.html", gin.H{"error": "Недостаточно прав для изменения статуса"})
			return
		}
	default:
		ctx.HTML(http.StatusForbidden, "error.html", gin.H{"error": "Недостаточно прав"})
		return
	}

	if err := h.Repository.UpdateRequestStatus(requestID, newStatus); err != nil {
		ctx.HTML(http.StatusInternalServerError, "error.html", gin.H{"error": "Ошибка при обновлении статуса"})
		return
	}

	logrus.Info("Статус заявки ", requestID, " изменен на ", newStatus, " пользователем типа ", userType)

	ctx.Redirect(http.StatusFound, "/request/"+requestIDStr)
}

func (h *Handler) GetRequestsAPI(ctx *gin.Context) {
	status := strings.TrimSpace(ctx.Query("status"))
	from, err := h.parseDateParam(strings.TrimSpace(ctx.Query("date_from")))
	if err != nil {
		h.writeJSONError(ctx, http.StatusBadRequest, "Неверный формат даты date_from")
		return
	}
	to, err := h.parseDateParam(strings.TrimSpace(ctx.Query("date_to")))
	if err != nil {
		h.writeJSONError(ctx, http.StatusBadRequest, "Неверный формат даты date_to")
		return
	}

	requests, err := h.Repository.GetRequests(status, from, to)
	if err != nil {
		h.writeJSONError(ctx, http.StatusInternalServerError, "Ошибка при получении заявок")
		return
	}

	for idx := range requests {
		requests[idx].ResultCount = len(requests[idx].RequestFacts)
	}

	ctx.JSON(http.StatusOK, gin.H{"status": "ok", "requests": requests})
}

func (h *Handler) GetRequestAPI(ctx *gin.Context) {
	idStr := ctx.Param("id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		h.writeJSONError(ctx, http.StatusBadRequest, "Неверный ID заявки")
		return
	}
	request, err := h.Repository.GetRequestByID(id)
	if err != nil {
		h.writeJSONError(ctx, http.StatusInternalServerError, "Ошибка при получении заявки")
		return
	}
	if request == nil {
		h.writeJSONError(ctx, http.StatusNotFound, "Заявка не найдена")
		return
	}
	request.ResultCount = len(request.RequestFacts)
	ctx.JSON(http.StatusOK, gin.H{"status": "ok", "request": request})
}

func (h *Handler) UpdateRequestAPI(ctx *gin.Context) {
	userID, err := h.getCurrentUserID(ctx)
	if err != nil {
		h.writeJSONError(ctx, http.StatusUnauthorized, "Требуется вход")
		return
	}

	idStr := ctx.Param("id")
	requestID, err := strconv.Atoi(idStr)
	if err != nil {
		h.writeJSONError(ctx, http.StatusBadRequest, "Неверный ID заявки")
		return
	}

	request, err := h.Repository.GetRequestByID(requestID)
	if err != nil || request == nil {
		h.writeJSONError(ctx, http.StatusNotFound, "Заявка не найдена")
		return
	}
	if request.CreatorID != userID {
		h.writeJSONError(ctx, http.StatusForbidden, "Только создатель может изменять заявку")
		return
	}
	if request.Status != "draft" {
		h.writeJSONError(ctx, http.StatusBadRequest, "Изменение заявки возможно только в статусе draft")
		return
	}

	var body struct {
		Title        string `json:"title"`
		Description  string `json:"description"`
		ThreatTypeID int    `json:"threat_type_id"`
	}
	if err := ctx.ShouldBindJSON(&body); err != nil {
		h.writeJSONError(ctx, http.StatusBadRequest, "Неверные данные заявки")
		return
	}

	updates := map[string]interface{}{}
	if strings.TrimSpace(body.Title) != "" {
		updates["title"] = strings.TrimSpace(body.Title)
	}
	if strings.TrimSpace(body.Description) != "" {
		updates["description"] = strings.TrimSpace(body.Description)
	}
	if body.ThreatTypeID > 0 {
		updates["threat_type_id"] = body.ThreatTypeID
	}
	if len(updates) == 0 {
		h.writeJSONError(ctx, http.StatusBadRequest, "Нет данных для обновления")
		return
	}

	if err := h.Repository.UpdateRequest(requestID, updates); err != nil {
		h.writeJSONError(ctx, http.StatusInternalServerError, "Ошибка при обновлении заявки")
		return
	}
	ctx.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func (h *Handler) SubmitRequest(ctx *gin.Context) {
	userID, err := h.getCurrentUserID(ctx)
	if err != nil {
		h.writeJSONError(ctx, http.StatusUnauthorized, "Требуется вход")
		return
	}
	userType, err := h.getCurrentUserType(ctx)
	if err != nil || userType != "specialist" {
		h.writeJSONError(ctx, http.StatusForbidden, "Только специалист может брать заявку")
		return
	}

	idStr := ctx.Param("id")
	requestID, err := strconv.Atoi(idStr)
	if err != nil {
		h.writeJSONError(ctx, http.StatusBadRequest, "Неверный ID заявки")
		return
	}

	request, err := h.Repository.GetRequestByID(requestID)
	if err != nil || request == nil {
		h.writeJSONError(ctx, http.StatusNotFound, "Заявка не найдена")
		return
	}
	if request.Status != "awaiting" {
		h.writeJSONError(ctx, http.StatusBadRequest, "Заявку можно принять только в статусе awaiting")
		return
	}

	updates := map[string]interface{}{
		"status":       "taken",
		"moderator_id": userID,
	}
	if err := h.Repository.UpdateRequest(requestID, updates); err != nil {
		h.writeJSONError(ctx, http.StatusInternalServerError, "Ошибка при принятии заявки")
		return
	}
	ctx.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func (h *Handler) CompleteRequest(ctx *gin.Context) {
	userID, err := h.getCurrentUserID(ctx)
	if err != nil {
		h.writeJSONError(ctx, http.StatusUnauthorized, "Требуется вход")
		return
	}
	userType, err := h.getCurrentUserType(ctx)
	if err != nil || userType != "specialist" {
		h.writeJSONError(ctx, http.StatusForbidden, "Только специалист может завершать заявку")
		return
	}

	idStr := ctx.Param("id")
	requestID, err := strconv.Atoi(idStr)
	if err != nil {
		h.writeJSONError(ctx, http.StatusBadRequest, "Неверный ID заявки")
		return
	}

	var body struct {
		Status string `json:"status" binding:"required,oneof=closed rejected"`
	}
	if err := ctx.ShouldBindJSON(&body); err != nil {
		h.writeJSONError(ctx, http.StatusBadRequest, "Неверный статус")
		return
	}

	request, err := h.Repository.GetRequestByID(requestID)
	if err != nil || request == nil {
		h.writeJSONError(ctx, http.StatusNotFound, "Заявка не найдена")
		return
	}
	if request.Status != "taken" {
		h.writeJSONError(ctx, http.StatusBadRequest, "Завершить можно только сформированную заявку")
		return
	}

	if err := h.Repository.CompleteRequest(requestID, userID, body.Status); err != nil {
		h.writeJSONError(ctx, http.StatusInternalServerError, "Ошибка при завершении заявки")
		return
	}
	ctx.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func (h *Handler) DeleteRequestAPI(ctx *gin.Context) {
	userID, err := h.getCurrentUserID(ctx)
	if err != nil {
		h.writeJSONError(ctx, http.StatusUnauthorized, "Требуется вход")
		return
	}
	userType, _ := h.getCurrentUserType(ctx)

	idStr := ctx.Param("id")
	requestID, err := strconv.Atoi(idStr)
	if err != nil {
		h.writeJSONError(ctx, http.StatusBadRequest, "Неверный ID заявки")
		return
	}

	request, err := h.Repository.GetRequestByID(requestID)
	if err != nil || request == nil {
		h.writeJSONError(ctx, http.StatusNotFound, "Заявка не найдена")
		return
	}
	if userType != "specialist" && request.CreatorID != userID {
		h.writeJSONError(ctx, http.StatusForbidden, "Нет прав на удаление этой заявки")
		return
	}

	if err := h.Repository.DeleteRequest(requestID); err != nil {
		h.writeJSONError(ctx, http.StatusInternalServerError, "Ошибка при удалении заявки")
		return
	}
	ctx.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func (h *Handler) GetRequestFactsAPI(ctx *gin.Context) {
	idStr := ctx.Param("id")
	requestID, err := strconv.Atoi(idStr)
	if err != nil {
		h.writeJSONError(ctx, http.StatusBadRequest, "Неверный ID заявки")
		return
	}

	facts, err := h.Repository.GetFactsByRequestID(requestID)
	if err != nil {
		h.writeJSONError(ctx, http.StatusInternalServerError, "Ошибка при получении фактов заявки")
		return
	}

	ctx.JSON(http.StatusOK, gin.H{"status": "ok", "facts": facts})
}

func (h *Handler) CreateFactAPI(ctx *gin.Context) {
	user := getAPIUser()
	if user.UserType != "employee" {
		h.writeJSONError(ctx, http.StatusForbidden, "Только сотрудник может добавлять факты")
		return
	}

	idStr := ctx.Param("id")
	requestID, err := strconv.Atoi(idStr)
	if err != nil {
		h.writeJSONError(ctx, http.StatusBadRequest, "Неверный ID заявки")
		return
	}

	var body struct {
		Title         string `json:"title" binding:"required"`
		Description   string `json:"description" binding:"required"`
		ScreenshotURL string `json:"screenshot_url"`
	}
	if err := ctx.ShouldBindJSON(&body); err != nil {
		h.writeJSONError(ctx, http.StatusBadRequest, "Неверные данные для создания факта")
		return
	}

	fact := &repository.Fact{
		RequestID:     requestID,
		Title:         strings.TrimSpace(body.Title),
		Description:   strings.TrimSpace(body.Description),
		ScreenshotURL: strings.TrimSpace(body.ScreenshotURL),
	}
	if fact.Title == "" || fact.Description == "" {
		h.writeJSONError(ctx, http.StatusBadRequest, "Название и описание факта обязательны")
		return
	}

	if err := h.Repository.CreateFact(fact); err != nil {
		h.writeJSONError(ctx, http.StatusInternalServerError, "Ошибка при создании факта")
		return
	}

	ctx.JSON(http.StatusCreated, gin.H{"status": "ok", "fact": fact})
}

func isValidUTF8(s string) bool {
	return strings.IndexFunc(s, func(r rune) bool {
		return r == '\uFFFD'
	}) == -1
}

func fixUTF8(s string) string {
	return strings.ToValidUTF8(s, "")
}
