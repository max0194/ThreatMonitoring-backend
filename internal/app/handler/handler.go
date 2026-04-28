package handler

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"threat-monitoring/internal/app/ds"
	"threat-monitoring/internal/app/pkg"
	"threat-monitoring/internal/app/repository"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"github.com/sirupsen/logrus"
)

const (
	accessTokenCookie = pkg.AccessTokenCookie
)

type Handler struct {
	Repository  *repository.Repository
	RedisClient *redis.Client
	jwtSecret   []byte
	jwtTTL      time.Duration
}

func NewHandler(r *repository.Repository, redisClient *redis.Client, jwtSecret []byte, jwtTTL time.Duration) *Handler {
	return &Handler{
		Repository:  r,
		RedisClient: redisClient,
		jwtSecret:   jwtSecret,
		jwtTTL:      jwtTTL,
	}
}

func (h *Handler) getCurrentUserType(ctx *gin.Context) (string, error) {
	if userType, exists := ctx.Get("user_type"); exists {
		if t, ok := userType.(string); ok {
			return t, nil
		}
	}
	userType, err := ctx.Cookie("user_type")
	if err != nil {
		return "", err
	}
	return userType, nil
}

func (h *Handler) getCurrentUserID(ctx *gin.Context) (int, error) {
	if userID, exists := ctx.Get("user_id"); exists {
		if id, ok := userID.(int); ok {
			return id, nil
		}
	}
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

func (h *Handler) storeSession(ctx context.Context, token string, value string) error {
	return h.RedisClient.Set(ctx, pkg.SessionKey(token), value, h.jwtTTL).Err()
}

func (h *Handler) deleteSession(ctx context.Context, token string) error {
	return h.RedisClient.Del(ctx, pkg.SessionKey(token)).Err()
}

func (h *Handler) AuthMiddleware() gin.HandlerFunc {
	return pkg.AuthMiddleware(h.RedisClient, h.jwtSecret)
}

func (h *Handler) writeSessionCookies(ctx *gin.Context, token string) {
	ctx.SetCookie(accessTokenCookie, token, int(h.jwtTTL.Seconds()), "/", "", false, true)
}

func (h *Handler) clearSessionCookies(ctx *gin.Context) {
	ctx.SetCookie(accessTokenCookie, "", -1, "/", "", false, true)
	ctx.SetCookie("user_id", "", -1, "/", "", false, true)
	ctx.SetCookie("user_type", "", -1, "/", "", false, true)
	ctx.SetCookie("user_name", "", -1, "/", "", false, true)
}

func (h *Handler) writeJSONError(ctx *gin.Context, status int, message string) {
	ctx.JSON(status, gin.H{"status": "error", "message": message})
}

func (h *Handler) parseDateParam(value string) (*time.Time, error) {
	logrus.Tracef("parseDateParam: value=%q", value)
	if value == "" {
		return nil, nil
	}
	t, err := time.Parse("2006-01-02", value)
	if err != nil {
		logrus.Warnf("Invalid date value=%q: %v", value, err)
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
	tokenString, _ := ctx.Cookie(pkg.AccessTokenCookie)
	if tokenString != "" {
		if err := pkg.AddToBlacklist(
			ctx.Request.Context(),
			h.RedisClient,
			tokenString,
			h.jwtTTL,
		); err != nil {
			logrus.WithError(err).Warn("Failed to add token to blacklist")
		}
	}

	ctx.SetCookie("user_id", "", -1, "/", "", false, true)
	ctx.SetCookie("user_type", "", -1, "/", "", false, true)
	ctx.SetCookie("user_name", "", -1, "/", "", false, true)
	ctx.SetCookie(pkg.AccessTokenCookie, "", -1, "/", "", false, true)

	ctx.Redirect(http.StatusFound, "/login")
}

func (h *Handler) HandleLogin(ctx *gin.Context) {
	userType := ctx.PostForm("user_type")
	email := ctx.PostForm("email")
	password := ctx.PostForm("password")

	logrus.Debugf("HandleLogin: попытка email=%s user_type=%s", email, userType)

	if userType != "employee" && userType != "specialist" {
		logrus.Warnf("HandleLogin: неправильный user_type=%q", userType)
		ctx.HTML(http.StatusOK, "login.html", gin.H{"error": "Неверный тип пользователя"})
		return
	}

	user, err := h.Repository.GetUserByEmail(email)
	if err != nil || user == nil || user.Password != password {
		logrus.Warnf("HandleLogin: ошибка аутентификации email=%s user_type=%s", email, userType)
		ctx.HTML(http.StatusOK, "login.html", gin.H{"error": "Неверный email или пароль"})
		return
	}

	if user.UserType != userType {
		logrus.Warnf("HandleLogin: неправильная роль пользователя email=%s expected=%s actual=%s", email, userType, user.UserType)
		ctx.HTML(http.StatusOK, "login.html", gin.H{"error": "Неверный тип пользователя"})
		return
	}

	token, err := ds.CreateToken(h.jwtSecret, h.jwtTTL, user.ID, user.UserType, user.FullName)
	if err != nil {
		logrus.Error("HandleLogin: ошибка генерация JWT-токена:", err)
		ctx.HTML(http.StatusOK, "login.html", gin.H{"error": "Ошибка генерации токена"})
		return
	}

	if err := h.storeSession(ctx.Request.Context(), token, strconv.Itoa(user.ID)+"|"+user.UserType); err != nil {
		logrus.Error("HandleLogin: ошибка сохранения сессии", err)
		ctx.HTML(http.StatusOK, "login.html", gin.H{"error": "Ошибка сохранения сессии"})
		return
	}

	h.writeSessionCookies(ctx, token)

	cookieTTL := int(h.jwtTTL.Seconds())
	ctx.SetCookie("user_id", strconv.Itoa(user.ID), cookieTTL, "/", "", false, true)
	ctx.SetCookie("user_type", user.UserType, cookieTTL, "/", "", false, true)
	ctx.SetCookie("user_name", user.FullName, cookieTTL, "/", "", false, true)

	logrus.WithFields(logrus.Fields{
		"user_id":   user.ID,
		"email":     user.Email,
		"user_type": user.UserType,
	}).Info("Пользователь вошел со своим токеном")

	if userType == "employee" {
		ctx.Redirect(http.StatusFound, "/employee")
	} else {
		ctx.Redirect(http.StatusFound, "/specialist")
	}
	pkg.IncrementLoginSuccess()
}

func (h *Handler) RegisterWeb(ctx *gin.Context) {
	userType, err := h.getCurrentUserType(ctx)
	if err != nil || userType != "specialist" {
		ctx.Redirect(http.StatusFound, "/login")
		return
	}

	if ctx.Request.Method == "POST" {
		var form struct {
			Email    string `form:"email" binding:"required,email"`
			Password string `form:"password" binding:"required"`
			FullName string `form:"full_name" binding:"required"`
			Phone    string `form:"phone" binding:"required"`
			UserType string `form:"user_type" binding:"required,oneof=employee specialist"`
		}

		if err := ctx.ShouldBind(&form); err != nil {
			logrus.Debugf("RegisterWeb: ошибка - неверные данные %v", err)
			ctx.HTML(http.StatusBadRequest, "signup.html", gin.H{
				"Error": "Неверные данные для регистрации",
			})
			return
		}

		logrus.Debugf("RegisterWeb: попытка email=%s user_type=%s", form.Email, form.UserType)
		if !strings.HasSuffix(form.Email, "@company.com") {
			ctx.HTML(http.StatusBadRequest, "signup.html", gin.H{
				"Error": "Разрешены только корпоративные email с доменом @company.com",
			})
			return
		}
		existingUser, err := h.Repository.GetUserByEmail(form.Email)
		if err != nil {
			logrus.Error("Ошибка при проверке пользователя:", err)
			ctx.HTML(http.StatusInternalServerError, "signup.html", gin.H{
				"Error": "Ошибка при проверке пользователя",
			})
			return
		}
		if existingUser != nil {
			logrus.Warnf("RegisterWeb: конфликт существующих email=%s", form.Email)
			ctx.HTML(http.StatusConflict, "signup.html", gin.H{
				"Error": "Пользователь с таким email уже существует",
			})
			return
		}

		user := &repository.User{
			Email:    strings.TrimSpace(form.Email),
			Password: strings.TrimSpace(form.Password),
			FullName: strings.TrimSpace(form.FullName),
			Phone:    strings.TrimSpace(form.Phone),
			UserType: form.UserType,
		}

		if err := h.Repository.CreateUser(user); err != nil {
			logrus.Error("Ошибка при создании пользователя:", err)
			ctx.HTML(http.StatusInternalServerError, "signup.html", gin.H{
				"Error": "Ошибка при создании пользователя",
			})
			return
		}

		logrus.WithFields(logrus.Fields{
			"user_email": user.Email,
			"user_type":  user.UserType,
		}).Info("Новая регистрация через форму")

		ctx.Redirect(http.StatusSeeOther, "/specialist")
		return
	}

	userName, _ := ctx.Cookie("user_name")

	ctx.HTML(http.StatusOK, "signup.html", gin.H{
		"userName": userName,
	})
}

type LoginAPIInput struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required"`
	UserType string `json:"user_type" binding:"required,oneof=employee specialist"`
}

func (h *Handler) CreateRequest(ctx *gin.Context) {
	userIDStr, err := ctx.Cookie("user_id")
	if err != nil {
		logrus.Warn("CreateRequest: необходима авторизация")
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

	logrus.Debugf("CreateRequest form data: user_id=%s description_len=%d threat_type=%s", userIDStr, len(description), threatTypeIDStr)

	if !isValidUTF8(description) {
		logrus.Info("Обнаружена неправильная кодировка, исправляем UTF-8")
		description = fixUTF8(description)
		logrus.Info("Успешно исправлено: ", description)
	}

	if description == "" {
		logrus.Warn("CreateRequest: пустое описание")
		ctx.Redirect(http.StatusFound, "/employee?error=Description of request cannot be empty")
		return
	}

	if threatTypeIDStr == "" {
		logrus.Warn("CreateRequest: типо ошибки не был выбран")
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
		logrus.Info("Title исправлен: ", title)
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
	logrus.WithFields(logrus.Fields{"request_id": request.ID, "creator_id": creatorID, "threat_type_id": threatTypeID}).Info("New request created")
	ctx.Redirect(http.StatusFound, fmt.Sprintf("/request/%d", request.ID))
}

func (h *Handler) CreateFact(ctx *gin.Context) {
	_, err := ctx.Cookie("user_id")
	if err != nil {
		logrus.Warn("CreateFact: необходимо авторизоваться")
		ctx.HTML(http.StatusUnauthorized, "login.html", gin.H{"error": "Нужен вход"})
		return
	}

	userType, err := ctx.Cookie("user_type")
	if err != nil || userType != "employee" {
		logrus.Warnf("CreateFact: недостаточно прав user_type=%s", userType)
		ctx.HTML(http.StatusForbidden, "error.html", gin.H{"error": "Недостаточно прав"})
		return
	}

	requestIDStr := strings.TrimSpace(ctx.PostForm("request_id"))
	title := strings.TrimSpace(ctx.PostForm("fact_title"))
	description := strings.TrimSpace(ctx.PostForm("fact_description"))

	logrus.Debugf("CreateFact entry: request_id=%s title_len=%d description_len=%d", requestIDStr, len(title), len(description))

	if requestIDStr == "" {
		logrus.Warn("CreateFact: не указан ID заявки")
		ctx.Redirect(http.StatusFound, "/employee?error=ID request not stated")
		return
	}

	requestID, _ := strconv.Atoi(requestIDStr)

	if title == "" {
		logrus.Warn("CreateFact: имя факта не может быть пустым")
		ctx.Redirect(http.StatusFound, "/employee?error=Title of fact cannot be empty")
		return
	}

	if description == "" {
		logrus.Warn("CreateFact: описание факта не может быть пустым")
		ctx.Redirect(http.StatusFound, "/employee?error=Desc of fact cannot be empty")
		return
	}

	file, header, err := ctx.Request.FormFile("screenshot")
	if err != nil {
		logrus.Error("CreateFact: ошибка при загрузке файла:", err)
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
	logrus.WithFields(logrus.Fields{"request_id": requestID, "fact_title": title}).Info("Факт успешно создан")

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
		logrus.Warn("UpdateRequestStatus: неавторизованный пользователь")
		ctx.Redirect(http.StatusFound, "/login")
		return
	}

	userType, err := ctx.Cookie("user_type")
	if err != nil {
		logrus.Warn("UpdateRequestStatus: нету user_type токена")
		ctx.Redirect(http.StatusFound, "/login")
		return
	}

	requestIDStr := ctx.Param("id")
	requestID, err := strconv.Atoi(requestIDStr)
	if err != nil {
		logrus.Warnf("UpdateRequestStatus invalid request id=%s", requestIDStr)
		ctx.HTML(http.StatusBadRequest, "error.html", gin.H{"error": "Неверный ID заявки"})
		return
	}

	newStatus := ctx.PostForm("status")
	if newStatus == "" {
		logrus.Warn("UpdateRequestStatus: пустой статус")
		ctx.HTML(http.StatusBadRequest, "error.html", gin.H{"error": "Не указан новый статус"})
		return
	}
	logrus.Debugf("UpdateRequestStatus: попытка request_id=%d user_type=%s new_status=%s", requestID, userType, newStatus)

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

// LoginAPI godoc
// @Summary Зайти за пользователя
// @Description Позволяет зайти за пользователя, используя его данные.
// @Tags auth
// @Accept json
// @Produce json
// @Param request body LoginAPIInput true "Данные для входа"
// @Success 200 {object} map[string]interface{} "Успешный вход"
// @Failure 400 {object} map[string]interface{} "Неверные данные"
// @Failure 401 {object} map[string]interface{} "Неверный email или пароль"
// @Failure 403 {object} map[string]interface{} "Неверный тип пользователя"
// @Failure 500 {object} map[string]interface{} "Ошибка сервера"
// @Router /api/auth/login [post]
func (h *Handler) LoginAPI(ctx *gin.Context) {
	var body struct {
		Email    string `json:"email" binding:"required,email"`
		Password string `json:"password" binding:"required"`
		UserType string `json:"user_type" binding:"required,oneof=employee specialist"`
	}
	if err := ctx.ShouldBindJSON(&body); err != nil {
		logrus.Debugf("LoginAPI: ошибка - неверные данные %v", err)
		h.writeJSONError(ctx, http.StatusBadRequest, "Неверные данные для входа")
		return
	}

	logrus.Debugf("LoginAPI attempt: email=%s user_type=%s", body.Email, body.UserType)
	user, err := h.Repository.GetUserByEmail(body.Email)
	if err != nil || user == nil || user.Password != body.Password {
		logrus.Warnf("LoginAPI: ошибка аутентификации email=%s user_type=%s", body.Email, body.UserType)
		h.writeJSONError(ctx, http.StatusUnauthorized, "Неверный email или пароль")
		return
	}
	if user.UserType != body.UserType {
		logrus.Warnf("LoginAPI: неверный тип пользователя email=%s expected=%s actual=%s", body.Email, body.UserType, user.UserType)
		h.writeJSONError(ctx, http.StatusForbidden, "Неверный тип пользователя")
		return
	}

	token, err := ds.CreateToken(h.jwtSecret, h.jwtTTL, user.ID, user.UserType, user.FullName)
	if err != nil {
		logrus.Error("LoginAPI: ошибка генерации токена", err)
		h.writeJSONError(ctx, http.StatusInternalServerError, "Ошибка генерации токена")
		return
	}

	if err := h.storeSession(ctx.Request.Context(), token, strconv.Itoa(user.ID)+"|"+user.UserType); err != nil {
		logrus.Error("LoginAPI: ошибка сохранения сессии", err)
		h.writeJSONError(ctx, http.StatusInternalServerError, "Ошибка сохранения сессии")
		return
	}

	ctx.SetCookie("user_id", strconv.Itoa(user.ID), int(h.jwtTTL.Seconds()), "/", "", false, true)
	ctx.SetCookie("user_type", user.UserType, int(h.jwtTTL.Seconds()), "/", "", false, true)
	ctx.SetCookie("user_name", user.FullName, int(h.jwtTTL.Seconds()), "/", "", false, true)
	h.writeSessionCookies(ctx, token)
	logrus.WithFields(logrus.Fields{"user_id": user.ID, "email": user.Email, "user_type": user.UserType}).Info("API user authenticated")
	ctx.JSON(http.StatusOK, gin.H{"status": "ok", "token": token, "user": user})

	pkg.IncrementLoginSuccess()
}

type RegisterAPIInput struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required"`
	FullName string `json:"full_name" binding:"required"`
	Phone    string `json:"phone" binding:"required"`
	UserType string `json:"user_type" binding:"required"`
}

// RegisterAPI godoc
// @Summary Зарегистрировать пользователя
// @Description Позволяет зарегистрировать пользователя. Необходим вход за специалиста.
// @Tags auth
// @Accept json
// @Produce json
// @Security ApiKeyAuth
// @Param request body RegisterAPIInput true "Данные для регистрации"
// @Success 200 {object} map[string]interface{} "Успешная регистрация"
// @Failure 400 {object} map[string]interface{} "Неверные данные"
// @Failure 403 {object} map[string]interface{} "Неверный тип пользователя"
// @Failure 500 {object} map[string]interface{} "Ошибка сервера"
// @Router /api/auth/register [post]
func (h *Handler) RegisterAPI(ctx *gin.Context) {
	userType, err := h.getCurrentUserType(ctx)
	if err != nil || userType != "specialist" {
		logrus.Warnf("Ошибка типа пользователя или авторизации %v", err)
		h.writeJSONError(ctx, http.StatusBadRequest, "Ошибка типа пользователя или авторизации")
		return
	}
	var body struct {
		Email    string `json:"email" binding:"required,email"`
		Password string `json:"password" binding:"required"`
		FullName string `json:"full_name" binding:"required"`
		Phone    string `json:"phone" binding:"required"`
		UserType string `json:"user_type" binding:"required,oneof=employee specialist"`
	}
	if err := ctx.ShouldBindJSON(&body); err != nil {
		logrus.Debugf("RegisterAPI: неверные данные %v", err)
		h.writeJSONError(ctx, http.StatusBadRequest, "Неверные данные для регистрации")
		return
	}

	logrus.Debugf("RegisterAPI: попытка email=%s user_type=%s", body.Email, body.UserType)
	if !strings.HasSuffix(body.Email, "@company.com") {
		logrus.Warnf("RegisterAPI: ошибка домена (не @company.com) %v", err)
		h.writeJSONError(ctx, http.StatusBadRequest, "Разрешены только корпоративные email с доменом @company.com")
		return
	}

	existingUser, err := h.Repository.GetUserByEmail(body.Email)
	if err != nil {
		logrus.Warnf("RegisterAPI: ошибка проверки Email %v", err)
		h.writeJSONError(ctx, http.StatusInternalServerError, "Ошибка при проверке пользователя")
		return
	}
	if existingUser != nil {
		logrus.Warnf("RegisterAPI: уже существует пользователь с таким email=%s", body.Email)
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
	logrus.WithFields(logrus.Fields{"user_email": user.Email, "user_type": user.UserType}).Info("Новый пользователь зарегистрирован")
	ctx.JSON(http.StatusCreated, gin.H{"status": "ok", "user": user})
}

// LogoutAPI godoc
// @Summary Выход из системы
// @Description Завершает текущую авторизованную сессию.
// @Tags auth
// @Accept json
// @Produce json
// @Security ApiKeyAuth
// @Success 200 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Router /api/auth/logout [post]
func (h *Handler) LogoutAPI(ctx *gin.Context) {
	tokenString := pkg.TokenFromRequest(ctx)
	if tokenString == "" {
		logrus.Warn("LogoutAPI: требуется вход")
		h.writeJSONError(ctx, http.StatusUnauthorized, "Требуется вход")
		return
	}

	if err := h.deleteSession(ctx.Request.Context(), tokenString); err != nil {
		logrus.Warn("LogoutAPI: ошибка выхода")
		h.writeJSONError(ctx, http.StatusInternalServerError, "Ошибка выхода")
		return
	}

	if err := pkg.AddToBlacklist(
		ctx.Request.Context(),
		h.RedisClient,
		tokenString,
		h.jwtTTL,
	); err != nil {
		logrus.Warn("LogoutAPI: ошибка добавления токена в Blacklist")
		h.writeJSONError(ctx, http.StatusInternalServerError, "Ошибка добавления токена в Blacklist")
		return
	}

	h.clearSessionCookies(ctx)
	ctx.JSON(http.StatusOK, gin.H{"status": "ok"})
}

type CreateRequestInput struct {
	Title        string `json:"title" binding:"required"`
	Description  string `json:"description" binding:"required"`
	ThreatTypeID int    `json:"threat_type_id" binding:"required"`
}

// CreateRequestAPI godoc
// @Summary Создать заявку
// @Description Создает новую заявку для авторизованного пользователя.
// @Tags requests
// @Accept json
// @Produce json
// @Security ApiKeyAuth
// @Param request body CreateRequestInput true "Данные заявки"
// @Success 201 {object} map[string]interface{}
// @Failure 400 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Failure 500 {object} map[string]interface{} "Ошибка при создании заявки"
// @Router /api/requests [post]
func (h *Handler) CreateRequestAPI(ctx *gin.Context) {
	userID, err := h.getCurrentUserID(ctx)
	if err != nil {
		logrus.Warn("CreateRequestAPI: требуется вход")
		h.writeJSONError(ctx, http.StatusUnauthorized, "Требуется вход")
		return
	}

	var body struct {
		Title        string `json:"title" binding:"required"`
		Description  string `json:"description" binding:"required"`
		ThreatTypeID int    `json:"threat_type_id" binding:"required"`
	}
	if err := ctx.ShouldBindJSON(&body); err != nil {
		logrus.Warn("CreateRequestAPI: неверные данные для создания заявки")
		h.writeJSONError(ctx, http.StatusBadRequest, "Неверные данные для создания заявки")
		return
	}

	request := &repository.Request{
		Title:        strings.TrimSpace(body.Title),
		Description:  strings.TrimSpace(body.Description),
		ThreatTypeID: body.ThreatTypeID,
		CreatorID:    userID,
		Status:       "draft",
		CreatedAt:    time.Now(),
	}

	if err := h.Repository.CreateRequest(request); err != nil {
		logrus.Error("CreateRequestAPI: ошибка создания заявки")
		h.writeJSONError(ctx, http.StatusInternalServerError, "Ошибка при создании заявки")
		return
	}

	ctx.JSON(http.StatusCreated, gin.H{"status": "ok", "request": request})
}

// GetRequestsAPI godoc
// @Summary Получить список заявок
// @Description Возвращает список заявок. Доступно только после авторизации.
// @Tags requests
// @Accept json
// @Produce json
// @Security ApiKeyAuth
// @Param status query string false "Статус заявки"
// @Param date_from query string false "Дата от (YYYY-MM-DD)"
// @Param date_to query string false "Дата до (YYYY-MM-DD)"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]interface{} "Ошибка с параметрами запроса"
// @Failure 401 {object} map[string]interface{} "Требуется авторизация"
// @Failure 403 {object} map[string]interface{} "Доступ запрещён"
// @Failure 500 {object} map[string]interface{} "Внутренняя ошибка сервера"
// @Router /api/requests [get]
func (h *Handler) GetRequestsAPI(ctx *gin.Context) {
	userID, err := h.getCurrentUserID(ctx)
	if err != nil {
		logrus.Warn("GetRequestsAPI: требуется вход")
		h.writeJSONError(ctx, http.StatusUnauthorized, "Требуется вход")
		return
	}

	userType, err := h.getCurrentUserType(ctx)
	if err != nil {
		logrus.Error("GetRequestsAPI: ошибка при определении роли пользователя")
		h.writeJSONError(ctx, http.StatusInternalServerError, "Ошибка при определении роли пользователя")
		return
	}

	status := strings.TrimSpace(ctx.Query("status"))
	from, err := h.parseDateParam(strings.TrimSpace(ctx.Query("date_from")))
	if err != nil {
		logrus.Warn("GetRequestsAPI: неверный формат даты date_from")
		h.writeJSONError(ctx, http.StatusBadRequest, "Неверный формат даты date_from")
		return
	}
	to, err := h.parseDateParam(strings.TrimSpace(ctx.Query("date_to")))
	if err != nil {
		logrus.Warn("GetRequestsAPI: неверный формат даты date_to")
		h.writeJSONError(ctx, http.StatusBadRequest, "Неверный формат даты date_to")
		return
	}
	logrus.Tracef("GetRequestsAPI: фильтрация status=%q from=%v to=%v", status, from, to)

	requests, err := h.Repository.GetRequests(status, from, to)
	if err != nil {
		logrus.Error("GetRequestsAPI: ошибка при получении заявок", err)
		h.writeJSONError(ctx, http.StatusInternalServerError, "Ошибка при получении заявок")
		return
	}

	if userType == "employee" {
		var filtered []repository.Request
		for _, req := range requests {
			if req.CreatorID == userID {
				filtered = append(filtered, req)
			}
		}
		requests = filtered
		logrus.Debugf("GetRequestsAPI: заявки отфильтрованы для %d: %d requests", userID, len(filtered))
	} else {
		logrus.Debugf("GetRequestsAPI: специалист %d видит заявок: %d", userID, len(requests))
	}

	for idx := range requests {
		requests[idx].ResultCount = len(requests[idx].RequestFacts)
	}

	ctx.JSON(http.StatusOK, gin.H{
		"status":   "ok",
		"count":    len(requests),
		"requests": requests,
	})
}

// GetRequestAPI godoc
// @Summary Получить заявку
// @Description Возвращает заявку по ID. Доступно только после авторизации.
// @Tags requests
// @Accept json
// @Produce json
// @Security ApiKeyAuth
// @Param id path int true "ID заявки"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]interface{} "Неверный ID заявки"
// @Failure 401 {object} map[string]interface{} "Требуется авторизация"
// @Failure 403 {object} map[string]interface{} "Доступ запрещён"
// @Failure 404 {object} map[string]interface{} "Заявка не найдена"
// @Router /api/requests/{id} [get]
func (h *Handler) GetRequestAPI(ctx *gin.Context) {
	userID, err := h.getCurrentUserID(ctx)
	if err != nil {
		logrus.Warnf("GetRequestAPI: требуется вход: %d", userID)
		h.writeJSONError(ctx, http.StatusUnauthorized, "Требуется вход")
		return
	}

	userType, err := h.getCurrentUserType(ctx)
	if err != nil {
		logrus.Errorf("GetRequestAPI: ошибка при определении роли пользователя: %d", userID)
		h.writeJSONError(ctx, http.StatusInternalServerError, "Ошибка при определении роли пользователя")
		return
	}

	idStr := ctx.Param("id")
	id, err := strconv.Atoi(idStr)
	if err != nil {
		logrus.Errorf("GetRequestAPI: неверный ID заявки: %d", id)
		h.writeJSONError(ctx, http.StatusBadRequest, "Неверный ID заявки")
		return
	}

	request, err := h.Repository.GetRequestByID(id)
	if err != nil {
		logrus.Error("GetRequestAPI: ошибка получения заявки ", err)
		h.writeJSONError(ctx, http.StatusInternalServerError, "Ошибка при получении заявки")
		return
	}
	if request == nil {
		logrus.Error("GetRequestAPI: заявка не найдена: ", request)
		h.writeJSONError(ctx, http.StatusNotFound, "Заявка не найдена")
		return
	}

	if userType == "employee" && request.CreatorID != userID {
		logrus.Errorf("GetRequestAPI: доступ к заявке %d запрещён для %d", request.ID, userID)
		h.writeJSONError(ctx, http.StatusForbidden, "Доступ к этой заявке запрещён")
		return
	}

	request.ResultCount = len(request.RequestFacts)
	ctx.JSON(http.StatusOK, gin.H{"status": "ok", "request": request})
}

// UpdateRequestAPI godoc
// @Summary Обновить заявку
// @Description Обновляет существующую заявку, если пользователь является её создателем.
// @Tags requests
// @Accept json
// @Produce json
// @Security ApiKeyAuth
// @Param id path int true "ID заявки"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Failure 403 {object} map[string]interface{}
// @Failure 404 {object} map[string]interface{}
// @Router /api/requests/{id} [put]
func (h *Handler) UpdateRequestAPI(ctx *gin.Context) {
	userID, err := h.getCurrentUserID(ctx)
	if err != nil {
		logrus.Warn("UpdateRequestAPI: требуется вход")
		h.writeJSONError(ctx, http.StatusUnauthorized, "Требуется вход")
		return
	}

	idStr := ctx.Param("id")
	requestID, err := strconv.Atoi(idStr)
	if err != nil {
		logrus.Warn("UpdateRequestAPI: неверный ID заявки: ", requestID)
		h.writeJSONError(ctx, http.StatusBadRequest, "Неверный ID заявки")
		return
	}

	request, err := h.Repository.GetRequestByID(requestID)
	if err != nil || request == nil {
		logrus.Warn("UpdateRequestAPI: заявка не найдена: ", request)
		h.writeJSONError(ctx, http.StatusNotFound, "Заявка не найдена")
		return
	}
	if request.CreatorID != userID {
		logrus.Warn("UpdateRequestAPI: только создатель может изменять заявку: ", request)
		h.writeJSONError(ctx, http.StatusForbidden, "Только создатель может изменять заявку")
		return
	}
	if request.Status != "draft" {
		logrus.Warn("UpdateRequestAPI: изменение заявки возможно только в статусе draft: ", request.Status)
		h.writeJSONError(ctx, http.StatusBadRequest, "Изменение заявки возможно только в статусе draft")
		return
	}

	var body struct {
		Title        string `json:"title"`
		Description  string `json:"description"`
		ThreatTypeID int    `json:"threat_type_id"`
	}
	if err := ctx.ShouldBindJSON(&body); err != nil {
		logrus.Warn("UpdateRequestAPI: неверные данные заявки ")
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
		logrus.Warn("UpdateRequestAPI: нет данных для обновления")
		h.writeJSONError(ctx, http.StatusBadRequest, "Нет данных для обновления")
		return
	}

	if err := h.Repository.UpdateRequest(requestID, updates); err != nil {
		logrus.Error("UpdateRequestAPI: ошибка при обновлении заявки")
		h.writeJSONError(ctx, http.StatusInternalServerError, "Ошибка при обновлении заявки")
		return
	}
	ctx.JSON(http.StatusOK, gin.H{"status": "ok"})
}

// SubmitRequest godoc
// @Summary Взять заявку в работу
// @Description Специалист принимает заявку для обработки.
// @Tags requests
// @Accept json
// @Produce json
// @Security ApiKeyAuth
// @Param id path int true "ID заявки"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Failure 403 {object} map[string]interface{}
// @Failure 404 {object} map[string]interface{}
// @Router /api/requests/{id}/submit [put]
func (h *Handler) SubmitRequest(ctx *gin.Context) {
	userID, err := h.getCurrentUserID(ctx)
	if err != nil {
		logrus.Warn("SubmitRequestAPI: требуется вход")
		h.writeJSONError(ctx, http.StatusUnauthorized, "Требуется вход")
		return
	}
	userType, err := h.getCurrentUserType(ctx)
	if err != nil || userType != "specialist" {
		logrus.Warn("SubmitRequestAPI: только специалист может брать заявку: ", userType)
		h.writeJSONError(ctx, http.StatusForbidden, "Только специалист может брать заявку")
		return
	}

	idStr := ctx.Param("id")
	requestID, err := strconv.Atoi(idStr)
	if err != nil {
		logrus.Warn("SubmitRequestAPI: неверный ID заявки: ", requestID)
		h.writeJSONError(ctx, http.StatusBadRequest, "Неверный ID заявки")
		return
	}

	request, err := h.Repository.GetRequestByID(requestID)
	if err != nil || request == nil {
		logrus.Warn("SubmitRequestAPI: заявка не найдена: ", request)
		h.writeJSONError(ctx, http.StatusNotFound, "Заявка не найдена")
		return
	}
	if request.Status != "awaiting" {
		logrus.Warn("SubmitRequestAPI: изменение заявки возможно только в статусе draft: ", request.Status)
		h.writeJSONError(ctx, http.StatusBadRequest, "Заявку можно принять только в статусе awaiting")
		return
	}

	updates := map[string]interface{}{
		"status":       "taken",
		"moderator_id": userID,
	}
	if err := h.Repository.UpdateRequest(requestID, updates); err != nil {
		logrus.Warn("SubmitRequestAPI: неверные данные заявки ")
		h.writeJSONError(ctx, http.StatusInternalServerError, "Ошибка при принятии заявки")
		return
	}
	ctx.JSON(http.StatusOK, gin.H{"status": "ok"})
}

// CompleteRequest godoc
// @Summary Завершить заявку
// @Description Специалист завершает заявку со статусом closed или rejected.
// @Tags requests
// @Accept json
// @Produce json
// @Security ApiKeyAuth
// @Param id path int true "ID заявки"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Failure 403 {object} map[string]interface{}
// @Failure 404 {object} map[string]interface{}
// @Router /api/requests/{id}/complete [put]
func (h *Handler) CompleteRequest(ctx *gin.Context) {
	userID, err := h.getCurrentUserID(ctx)
	if err != nil {
		logrus.Warn("CompleteRequest: требуется вход")
		h.writeJSONError(ctx, http.StatusUnauthorized, "Требуется вход")
		return
	}
	userType, err := h.getCurrentUserType(ctx)
	if err != nil || userType != "specialist" {
		logrus.Warn("CompleteRequest: только специалист может брать заявку: ", userType)
		h.writeJSONError(ctx, http.StatusForbidden, "Только специалист может завершать заявку")
		return
	}

	idStr := ctx.Param("id")
	requestID, err := strconv.Atoi(idStr)
	if err != nil {
		logrus.Warn("CompleteRequest: неверный ID заявки: ", requestID)
		h.writeJSONError(ctx, http.StatusBadRequest, "Неверный ID заявки")
		return
	}

	var body struct {
		Status string `json:"status" binding:"required,oneof=closed rejected"`
	}
	if err := ctx.ShouldBindJSON(&body); err != nil {
		logrus.Warn("CompleteRequest: неверный статус заявки")
		h.writeJSONError(ctx, http.StatusBadRequest, "Неверный статус")
		return
	}

	request, err := h.Repository.GetRequestByID(requestID)
	if err != nil || request == nil {
		logrus.Warn("CompleteRequest: заявка не найдена: ", request)
		h.writeJSONError(ctx, http.StatusNotFound, "Заявка не найдена")
		return
	}
	if request.Status != "taken" {
		logrus.Warn("CompleteRequest: завершение заявки возможно только в статусе taken: ", request.Status)
		h.writeJSONError(ctx, http.StatusBadRequest, "Завершить можно только принятую заявку")
		return
	}

	if err := h.Repository.CompleteRequest(requestID, userID, body.Status); err != nil {
		logrus.Error("CompleteRequest: ошибка при завершении заявки")
		h.writeJSONError(ctx, http.StatusInternalServerError, "Ошибка при завершении заявки")
		return
	}
	ctx.JSON(http.StatusOK, gin.H{"status": "ok"})
}

// DeleteRequestAPI godoc
// @Summary Удалить заявку
// @Description Удаляет заявку, если у пользователя есть право на это.
// @Tags requests
// @Accept json
// @Produce json
// @Security ApiKeyAuth
// @Param id path int true "ID заявки"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Failure 403 {object} map[string]interface{}
// @Failure 404 {object} map[string]interface{}
// @Router /api/requests/{id} [delete]
func (h *Handler) DeleteRequestAPI(ctx *gin.Context) {
	userID, err := h.getCurrentUserID(ctx)
	if err != nil {
		logrus.Warn("DeleteRequestAPI: требуется вход")
		h.writeJSONError(ctx, http.StatusUnauthorized, "Требуется вход")
		return
	}
	userType, _ := h.getCurrentUserType(ctx)

	idStr := ctx.Param("id")
	requestID, err := strconv.Atoi(idStr)
	if err != nil {
		logrus.Warn("DeleteRequestAPI: неверный ID заявки: ", requestID)
		h.writeJSONError(ctx, http.StatusBadRequest, "Неверный ID заявки")
		return
	}

	request, err := h.Repository.GetRequestByID(requestID)
	if err != nil || request == nil {
		logrus.Warn("DeleteRequestAPI: заявка не найдена: ", request)
		h.writeJSONError(ctx, http.StatusNotFound, "Заявка не найдена")
		return
	}
	if userType != "specialist" && request.CreatorID != userID {
		logrus.Warn("DeleteRequestAPI: нет прав на удаление этой заявки: ", userType)
		h.writeJSONError(ctx, http.StatusForbidden, "Нет прав на удаление этой заявки")
		return
	}

	if err := h.Repository.DeleteRequest(requestID); err != nil {
		logrus.Warn("DeleteRequestAPI: ошибка удаления заявки ")
		h.writeJSONError(ctx, http.StatusInternalServerError, "Ошибка при удалении заявки")
		return
	}
	ctx.JSON(http.StatusOK, gin.H{"status": "ok"})
}

// GetRequestFactsAPI godoc
// @Summary Получить факты заявки
// @Description Возвращает список фактов для заявки. Требуется авторизация.
// @Tags requests
// @Accept json
// @Produce json
// @Security ApiKeyAuth
// @Param id path int true "ID заявки"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Failure 404 {object} map[string]interface{}
// @Router /api/requests/{id}/facts [get]
func (h *Handler) GetRequestFactsAPI(ctx *gin.Context) {
	userID, err := h.getCurrentUserID(ctx)
	if err != nil {
		logrus.Warnf("GetRequestFactsAPI: требуется вход: %d", userID)
		h.writeJSONError(ctx, http.StatusUnauthorized, "Требуется вход")
		return
	}

	userType, err := h.getCurrentUserType(ctx)
	if err != nil {
		logrus.Errorf("GetRequestFactsAPI: ошибка при определении роли пользователя: %d", userID)
		h.writeJSONError(ctx, http.StatusInternalServerError, "Ошибка при определении роли пользователя")
		return
	}

	idStr := ctx.Param("id")
	requestID, err := strconv.Atoi(idStr)
	if err != nil {
		logrus.Errorf("GetRequestFactsAPI: неверный ID заявки: %d", requestID)
		h.writeJSONError(ctx, http.StatusBadRequest, "Неверный ID заявки")
		return
	}

	request, err := h.Repository.GetRequestByID(requestID)
	if err != nil {
		logrus.Error("GetRequestFactsAPI: ошибка получения заявки ", err)
		h.writeJSONError(ctx, http.StatusInternalServerError, "Ошибка при получении заявки")
		return
	}
	if request == nil {
		logrus.Error("GetRequestFactsAPI: заявка не найдена: ", request)
		h.writeJSONError(ctx, http.StatusNotFound, "Заявка не найдена")
		return
	}
	if userType == "employee" && request.CreatorID != userID {
		logrus.Errorf("GetRequestFactsAPI: доступ к заявке %d запрещён для %d", requestID, userID)
		h.writeJSONError(ctx, http.StatusForbidden, "Доступ к этой заявке запрещён")
		return
	}

	facts, err := h.Repository.GetFactsByRequestID(requestID)
	if err != nil {
		logrus.Error("GetRequestFactsAPI: ошибка при получении фактов заявки")
		h.writeJSONError(ctx, http.StatusInternalServerError, "Ошибка при получении фактов заявки")
		return
	}

	ctx.JSON(http.StatusOK, gin.H{"status": "ok", "facts": facts})
}

// CreateFactAPI godoc
// @Summary Добавить факт к заявке
// @Description Создает новый факт для заявки. Требуется авторизация сотрудника.
// @Tags requests
// @Accept json
// @Produce json
// @Security ApiKeyAuth
// @Param id path int true "ID заявки"
// @Success 201 {object} map[string]interface{}
// @Failure 400 {object} map[string]interface{}
// @Failure 401 {object} map[string]interface{}
// @Failure 403 {object} map[string]interface{}
// @Router /api/requests/{id}/facts [post]
func (h *Handler) CreateFactAPI(ctx *gin.Context) {
	userType, err := h.getCurrentUserType(ctx)
	if err != nil || userType != "employee" {
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
